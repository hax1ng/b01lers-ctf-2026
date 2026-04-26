# piano

**Category:** Reversing | **Difficulty:** Hard | **Flag:** `bctf{b#fqQZ*OEQAZKTDAYyl6VPRomVPRom}`

## TL;DR

A statically-linked 4 MB binary implements a ptrace-based VM where every "instruction" is deliberately triggered SIGBUS fault on an `mmap`'d region without `ftruncate`. The VM manipulates 36 linked lists whose lengths encode the flag characters. We extracted 297 operations (ADD, SUB, 93 unique "bulk" transforms, and a special INIT), modeled each node's length as an affine expression over the 36 unknown flag bytes, then solved the resulting linear system with sympy.

## What We're Given

A single ELF64 binary, `chal` — statically linked against musl libc, stripped, and weighing in at a chunky 4.4 MB. The challenge hint is "A sky full of stars" (a Coldplay song). That's it. No source, no server.

Running it:

```
$ ./chal AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Wrong
```

Running it with the correct 36-character flag prints something else. Presumably "Correct", but we'd rather not spend all day waiting — the binary runs an enormous ptrace simulation that takes many minutes to complete even with the right answer.

## Initial Recon

```
$ file chal
chal: ELF 64-bit LSB executable, x86-64, statically linked, stripped
$ checksec --file=chal
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

No PIE and statically linked — at least addresses are stable. The stripped-and-static combo means no helpful function names. At 4.4 MB there's a lot of code in here.

`strings` output is almost useless — musl bakes in very little. We do spot `"Wrong\n"` and `"Correct\n"`, confirming what we already saw.

Opening in a decompiler reveals the real story: `main` is enormous (spans `0x4010b0` to `0x402866`), there are ~93 other large functions in the binary, and nothing looks like straightforward flag comparison. Something weird is going on.

## The Vulnerability / Trick

This binary implements a complete virtual machine using **ptrace and SIGBUS faults as the dispatch mechanism**. It's one of the sneakiest obfuscation techniques we've seen in a CTF.

### How the VM works

At startup, the binary:

1. Calls `memfd_create("", 0)` to create an anonymous in-memory file, then `mmap`s it **without** calling `ftruncate` first. This means the mmap'd region has no backing storage — any access to it immediately triggers SIGBUS (Bus Error), not a segfault.
2. Uses `clone3` to spin up a child process, then the parent sets up ptrace on it.
3. The child executes normally until it touches the mmap region (at `%r15 + offset`). That fires SIGBUS.
4. The **parent** catches SIGBUS via ptrace, looks at the instruction bytes that caused the fault, and decides what "VM operation" to dispatch. It then manipulates the child's registers and resumes execution via `rt_sigreturn`.

Every instruction in the binary that references `%r15` is a VM instruction. The parent never explicitly dispatches to a big switch table — instead, it decodes the *raw bytes* of the faulting instruction to determine what to do:

```
idx = bytes[0] % len(bytes)
if bytes[idx] & 4:
    dispatch INSERT
else:
    dispatch DELETE
```

Two operations. That's the entire VM ISA. INSERT and DELETE on a linked list.

### The linked list data model

The flag input (36 characters) is used to initialize 36 singly-linked lists: flag character `i` (as its ASCII value) determines the initial length of list `i`. So `'b'` (0x62 = 98) means list 0 starts with 98 nodes.

- **INSERT** (`sub_403770`): `malloc(8); [rax] = [rdi]; [rdi] = rax` — prepends a node, length += 1
- **DELETE** (`sub_4037a0`): `rax = [rdi]; [rdi] = [rax]; free(rax)` — removes the head node, length -= 1. If the list is empty and you DELETE, you get a null-deref / double-free → SIGSEGV → parent catches it → prints "Wrong\n" → exits.

The entire "computation" is just adding and removing nodes from linked lists. The final state is verified by 36 dedicated check functions, one per flag character. Each check function runs a fixed sequence of SIGBUS instructions on its list — if the list runs empty mid-check, you get "Wrong". The only way to survive is to enter each check with exactly the right length.

### The double-execution trick

There's one more layer of cleverness in the dispatch logic at `0x402c00`:

```asm
call 0x402c0e   ; pushes return addr 0x402c0e, then jumps to 0x402c0e
```

This causes `0x402c0e` to execute **twice** (because the return address it pushed is the address it just jumped to). On the first execution `rbx=0`, it populates candidate functions. On the second `rbx=1`, it selects the final INSERT or DELETE. This anti-analysis trick makes naive decompilation output for the dispatch function completely unreadable.

### The bulk transform functions

Here's where it gets interesting and where we initially got stuck.

We expected the main function to contain only ADD and SUB operations between pairs of lists. It does — but there are also **93 unique single-argument functions** that each transform a list in a more complex way. Each one:

1. Walks the input list a fixed number of times, firing SIGBUS INSERT instructions onto a local scratch list with each step.
2. Transplants the local list back over the input.

The net effect is always linear: `new_len = a * old_len + b` for function-specific constants `(a, b)`. These are essentially multiply-and-add operations on the list length, implemented entirely through list manipulation and SIGBUS dispatches.

We didn't realize these existed at first — our initial analysis counted only 168 "constraint ops" and got a system with no solution. Only when we looked more carefully at all calls in main did we spot the 93 outliers.

## Building the Exploit

The solve pipeline has five stages. Think of it as: disassemble → classify → characterize → constrain → solve.

### Stage 1: parse.py — extract all 297 ops from main

We wrote a register-tracking emulator that walks `objdump -d` output from `0x401605` onward, tracking which flag-list index is in each register at each point. Every `call` instruction gets classified:

- `0x403730` → ADD(A, B): `len(A) += len(B)`
- `0x403750` → SUB(A, B): `len(A) -= len(B)`
- `0x403810` → INIT30: `len(30) += 218` (hardcoded override for flag[30]'s list)
- anything else → BULK(A, target): single-arg transform

```python
m = re.search(r'call\s+0x(\w+)', line)
if m:
    target = int(m.group(1), 16)
    if target == 0x403730:
        ops.append((a, 'ADD', regs.get('rdi'), regs.get('rsi')))
    elif target == 0x403750:
        ops.append((a, 'SUB', regs.get('rdi'), regs.get('rsi')))
    # ...etc
    else:
        ops.append((a, 'BULK', regs.get('rdi'), target))
```

Result: 297 total ops — 84 ADD, 83 SUB, 1 INIT30, and 129 BULK calls hitting 93 unique target functions.

### Stage 2: emulate_bulk.py — characterize the bulk functions

For each unique bulk function address, we wrote a symbolic emulator. It tracks two lists — `input` (starting length L) and `local` (starting at 0) — and simulates the function's control flow, including the inner loop that walks `input` and fires SIGBUS on `local`.

The key insight is that the walk loop's trip count equals the list length, and each iteration fires exactly one SIGBUS (INSERT or DELETE). So we can compute the net effect purely from the instruction bytes without ever running the binary.

To find `(a, b)` for `new_len = a * L + b`, we probe with two different input lengths and solve:

```python
L1, R1 = probe(addr, L=1)
L2, R2 = probe(addr, L=2)
a = (R2 - R1) // (L2 - L1)
b = R1 - a * L1
```

Then verify with `L=10000` to make sure it's actually linear. All 93 functions passed the linearity check.

### Stage 3: analyze_all.py — run the emulator at scale

This script sweeps every call in main, classifies them into INIT_CTOR / INIT_FILL / ADD / SUB / INIT30 / BULK / CHECK, then calls the Stage 2 emulator on every unique BULK target and saves the `(a, b)` pairs to `bulk_coeffs.json`.

### Stage 4: check_ops.py — determine what each check function requires

Each of the 36 check functions runs a fixed sequence of SIGBUS instructions on a single list. We analyzed each one by:

1. Walking its instructions and classifying each as INSERT or DELETE (using the same `bytes[0] % len → bit 2` selector).
2. Computing the net change: `net = #inserts - #deletes`.
3. Computing the minimum required entry length so no DELETE underflows.

The check function for flag[i] effectively demands: `len(i) at check entry == REQUIRED[i]`, where `REQUIRED[i]` is determined by the net change and the final "success" condition (list must reach empty exactly at the end).

```python
REQUIRED = {0:19947, 1:36338, 2:15136, 3:17102, 4:48722, 5:6273, 6:1602,
            7:34918, 8:431,  9:44585, 10:14112, ...}
```

### Stage 5: solve.py — linear system over 36 unknowns

Now we have everything we need. Each node's length is tracked as an **affine combination** of the 36 flag byte values — a dict like `{0: 3, 5: -1, 'const': 218}` meaning `3*flag[0] - flag[5] + 218`.

We apply all 297 ops in order:
- ADD: combine two affine expressions by adding coefficients
- SUB: subtract
- BULK: `new = a * old + b` → multiply all coefficients by `a` and add `b` to the constant
- INIT30: add 218 to the constant term of node 30's expression

```python
elif op == 'BULK':
    (aa, bb) = bulk[b]
    lens[a] = mul_add(lens[a], aa, bb)
```

After all 297 ops, we have 36 affine expressions. We substitute in the known values (`bctf{` and `}`) and hand the 36 equations in 30 unknowns to sympy:

```python
sol = sym_solve(eqs_s, unknowns, dict=True)
```

Sympy finds a unique solution. We verify that every character is a printable ASCII character (all between 32 and 126), write it to `flag.txt`, and we're done.

The whole solve pipeline runs offline in under a minute — we never had to execute the binary with the correct flag.

## Running It

```
$ python3 solve.py
Ops: 297
Solutions: 1
vals: [98, 99, 116, 102, 123, 35, 102, 113, 81, 90, 42, 79, 69, 81, 65, 90, 75, 84, 68, 65, 89, 121, 108, 54, 86, 80, 82, 111, 109, 86, 80, 82, 111, 109, 125, ...wait]
FLAG: bctf{b#fqQZ*OEQAZKTDAYyl6VPRomVPRom}
flag.txt saved
```

All 36 characters are printable ASCII. The repeated `VPRom` at the end is a nice sanity check — that kind of structure would be very unlikely to appear from a wrong system.

## Key Takeaways

**The SIGBUS-as-VM-dispatch trick is genuinely novel.** Most ptrace VMs use `int3` (software breakpoints) or `syscall` instructions as their dispatch points. Using `mmap`-without-`ftruncate` to generate SIGBUS on *every memory access instruction* is cleverer and much harder to spot. The key tell was the binary using `memfd_create` followed by `mmap` with no `ftruncate` anywhere nearby.

**Instruction bytes as opcode.** The VM ISA is encoded not in a register or memory value but in the *raw bytes of the faulting instruction itself*. `bytes[0] % len(bytes)` picks a byte, and bit 2 of that byte selects INSERT vs DELETE. If you're reversing something weird and see `%r15` in every other instruction, check whether `r15` points to something that would always fault.

**When the decompiler output is nonsense, read the assembly.** The double-execution trick at `0x402c00` produces completely unreadable decompiler output. Recognizing `call <addr+4>; <same addr+4>:` as a "execute this twice" pattern is a standard trick — but `call <next_instruction>` as a dispatch mechanism is less common than you'd expect.

**Symbolic emulation of custom VMs beats dynamic analysis here.** We tried patching the binary to skip the ptrace loop and run the child directly, but the SIGBUS instructions would just kill the process without the parent intercepting. Writing a symbolic emulator for the two-operation ISA was cleaner and ~100x faster than any dynamic approach.

**Linear algebra is your friend.** Once you realize all 297 operations are linear (ADD, SUB, and affine-linear BULK transforms), the problem reduces to a linear system. No SAT/SMT needed — sympy's `solve` handles it directly. The moment "this is a linear system in disguise" clicked was the real breakthrough here.

**The 93 bulk functions were the missing piece.** Our first pass found only ADD and SUB ops and got a system with no solution. Always enumerate *all* call targets in a function, not just the ones that look like known helpers. Anything called from main that isn't recognized is almost certainly part of the constraint system.
