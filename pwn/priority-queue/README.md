# Priority Queue

**Category:** pwn | **Difficulty:** medium-hard | **Flag:** `bctf{u53_4ft3r_fr33_f4n_v5_0v3rl4pp1n6_4110c4t10n5_3nj0y3r_8c6fd0b452}`

## TL;DR

A binary min-heap that stores strings as individual malloc'd chunks. The `edit()` function always writes 32 bytes regardless of chunk size — we use this to corrupt adjacent tcache chunk headers, force a mis-sized free into the wrong bin, then overflow a strcpy into a tcache fd pointer to redirect the next allocation to the flag chunk already sitting on the heap.

## What We're Given

We get a binary (`chall`), the source code (`chall.c`), and a matching libc/linker. The challenge description reads: *"spacemonkeyy — Anything but paying attention during DSA lecture..."* which is a fun nod to the fact that this is literally a heap data structure challenge where the heap data structure IS the exploit surface.

The binary implements a text-mode priority queue with five operations: `insert`, `delete`, `peek`, `edit`, `count`. Strings you insert get malloc'd individually and sorted via min-heap ordering (lexicographic, so the lexicographically smallest string always sits at `array[0]`).

Protections (from checksec): Partial RELRO, no stack canary, NX enabled, PIE enabled. glibc 2.31.

```
$ checksec chall
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

No canary is nice, but we're not doing a stack smash here. The real action is on the heap.

## Initial Recon

Looking at the source, a few things jump out immediately.

First, `main()` opens `flag.txt` and reads it into a malloc'd buffer — and then just... leaves it there:

```c
FILE *file = fopen("flag.txt", "r");
if (file) {
    char *flag = malloc(100);   // 0x70 chunk — flag lives here forever
    fgets(flag, 100, file);
    fclose(file);
}
// flag pointer goes out of scope here, but the *memory* is never freed
```

The local variable `flag` is gone, but the heap chunk containing the flag bytes is still sitting on the heap for the entire lifetime of the process. This is our target — we don't need to hijack control flow or call `system()`. We just need to get `array[0]` to point near the flag chunk, then call `peek()` to `puts()` it out.

Second, `edit()` is suspicious:

```c
void edit(void) {
    if (size == 0) { puts("Queue is empty!"); return; }
    puts("Message: ");
    read(fileno(stdin), array[0], 32);   // always writes 32 bytes!
    move_down(0);
}
```

It writes **exactly 32 bytes** via `read()` into `array[0]`, no matter how big the chunk actually is. For a freshly inserted single-character string, the chunk is `0x20` bytes (16 bytes of data + 8 bytes header). So we can write 16 bytes past the end of the chunk — right into the next chunk's header. This is our heap overflow primitive, and `read()` is used instead of `strcpy`, so null bytes are fine.

Third, `insert()` allocates `malloc(strlen(buffer) + 1)` and uses `strcpy`. The +1 accounts for the null terminator but glibc rounds up to the nearest 16 bytes anyway, so a 1-byte string gets a 0x20 chunk (16 byte data area), a 38-byte string gets a 0x30 chunk, and so on.

## The Vulnerability / Trick

There are actually two separate bugs at play that we chain together:

**Bug 1: edit() fixed-size overflow.** `edit()` always writes 32 bytes. A 0x20-sized chunk has 16 bytes of data, so the last 16 bytes spill into the next chunk on the heap — specifically into that chunk's `prev_size` and `size` fields. This gives us a header corruption primitive.

**Bug 2: edit() doesn't null-terminate.** `read()` doesn't append a null byte. If we fill all 32 bytes with non-null data, then `peek()` → `puts(array[0])` will keep reading past our data until it hits a null. Beyond the 32 bytes we wrote, the next chunk's header and fd pointer sit in memory. Heap pointers have null bytes in their upper 2 bytes (addresses look like `0x0000555555xxxxxx`), but the *lower 6 bytes* are non-null — so `puts` will leak those before stopping.

Together these let us leak a heap address and corrupt tcache metadata to redirect an allocation to the flag chunk.

The glibc tcache (thread-local cache) is how glibc fast-tracks small allocations — think of it as a per-size singly-linked list of recently freed chunks. When you free a chunk, it goes to the front of its tcache bin. When you malloc the same size later, it pops straight off the front without any complex searching. The "next chunk to allocate" pointer is stored in the `fd` field of the freed chunk's data area. If we corrupt that pointer, the next allocation from that bin returns wherever we point it — this is the classic **tcache poisoning** attack.

The twist in this challenge is how we get to corrupt that `fd`. We can't do it directly with `edit()` because a 0x20 chunk overflow only reaches the *next* chunk's header — the `fd` field of the chunk after that is 8 bytes further than our overflow can reach. We're off by exactly one chunk-header-worth of bytes. So we do something sneaky: we corrupt the *size* field of the next chunk to make glibc think it's a 0x30 chunk instead of 0x20. When that chunk gets freed, it lands in the wrong tcache bin (`tcache[0x30]`). Then we allocate back from `tcache[0x30]` with a 38-byte string — `malloc(39)` rounds up to 0x30 — and `strcpy` of 38 non-null bytes + a null terminator overflows 7 bytes past the end of the chunk, landing squarely on the `fd` field of a *real* 0x20 chunk that's sitting in `tcache[0x20]`.

One more subtlety: we can't write a full 8-byte heap address with `strcpy` because heap addresses have two null bytes at the top (`0x0000...`), and `strcpy` stops at the first null. But we don't need to! Those top 2 bytes are already zero in the original fd value. We only need to overwrite the low 6 bytes, and we write exactly 6 non-null bytes of address followed by the null terminator at position 6 (which was already zero). Perfect alignment — no null byte problem.

The flag name itself spoils the technique: `u53_4ft3r_fr33_f4n_v5_0v3rl4pp1n6_4110c4t10n5_3nj0y3r` = "use after free fan vs overlapping allocations enjoyer." We went the overlapping allocations route.

## Building the Exploit

### Phase 1: Heap Leak

We insert four single-character strings (`d`, `c`, `b`, `a`) to get four adjacent 0x20 chunks on the heap. Then we delete three of them — they go onto `tcache[0x20]` in order: `c → b → a`. Now only `d` remains in the array.

```python
insert(io, b'd'); insert(io, b'c'); insert(io, b'b'); insert(io, b'a')
delete(io); delete(io); delete(io)   # frees a, b, c into tcache[0x20]
```

Now we edit `d` (which is `array[0]`) with 32 `Z` bytes — filling `d`'s 16-byte data area AND 16 bytes into the next chunk's header:

```python
edit_exact(io, b'Z' * 32)
leaked = peek(io)
```

`peek()` calls `puts(array[0])`. Since `d`'s data is all `Z`s (no null), `puts` keeps going: past `d`'s data, past the corrupted header of the next chunk (also `Z`s), and into the `fd` field of that chunk — which points to the second entry in the tcache chain (`b`'s user area). That's a real heap pointer. Its lower 6 bytes are non-null, so we get a 6-byte leak before `puts` hits the null upper bytes.

```python
b_user = u64(leaked[32:].ljust(8, b'\x00'))
d_chunk = b_user - 0x50      # d's chunk header is 0x50 bytes before b's user area
flag_user = d_chunk - 0xb0   # flag chunk was allocated before d, 0xb0 bytes earlier
```

We recover `b`'s user area, then compute the flag chunk address via known heap offsets. (These offsets are constant because heap layout is deterministic — same sequence of allocations = same relative positions every run.)

### Phase 2: Fix the Corruption and Drain Tcache

The leak left `c`'s header with garbage bytes. Before we can safely use `c`, we fix it with another edit:

```python
fix_payload = b'A' * 16 + p64(0) + p64(0x21)   # restore prev_size=0, size=0x21
edit_exact(io, fix_payload)
```

Then we drain `tcache[0x20]` with three inserts using short strings. Each insert pops a tcache entry and reuses the memory:

```python
insert(io, b'<9'); insert(io, b'<8'); insert(io, b'<7')
```

These pop `c`, `b`, `a` from tcache. The tcache is now empty for 0x20. Good, clean slate.

### Phase 3: Set Up Attack Chunks

We insert three more strings that are lexicographically smallest (so they'll compete for `array[0]`) and short enough to land in 0x20 chunks. We use `!`, `#`, `%` (ASCII 0x21, 0x23, 0x25):

```python
insert(io, b'!')   # chunk A — lands at heap+0x80
insert(io, b'#')   # chunk B — at heap+0xa0
insert(io, b'%')   # chunk C — at heap+0xc0
```

Because `!` is lex-smallest, chunk A is `array[0]`.

### Phase 4: Corrupt B's Size Field

We edit `array[0]` (chunk A) with 16 bytes of `\x01` (filler, and lex-smallest so A stays at `array[0]` after `move_down`) followed by `p64(0) + p64(0x31)`:

```python
a_edit = b'\x01' * 16 + p64(0) + p64(0x31)
edit_exact(io, a_edit)
```

The last 16 bytes land in chunk B's header: `prev_size = 0`, `size = 0x31` (that's `0x30 | PREV_INUSE`). Chunk B now looks like a 0x30 chunk to glibc.

### Phase 5: Free Everything Into the Wrong Bins

```python
delete(io)   # free A → tcache[0x20] (correct)
delete(io)   # free B (size=0x31!) → tcache[0x30] (wrong bin!)
delete(io)   # free C → tcache[0x20]: C → A
```

After this: `tcache[0x20]` has `C → A`, and `tcache[0x30]` has `B` (mis-filed).

### Phase 6: The Poisoning Insert

Here's the main event. We insert a 38-character string:

```python
target = flag_user - 0x20
target_bytes = p64(target)
poison_payload = b'X' * 32 + target_bytes[:6]   # 38 bytes total
insert(io, poison_payload)
```

`malloc(39)` rounds up to 0x30, pops B from `tcache[0x30]`. Then `strcpy(chunk, poison_payload)` writes 38 non-null bytes + a null terminator = 39 bytes total. Chunk B's data area is only 32 bytes (it's really a 0x20 chunk!), so the last 7 bytes overflow into the next chunk's data area. That next chunk is C, currently sitting in `tcache[0x20]`. The first 8 bytes of a freed tcache chunk's data area IS its `fd` pointer.

So bytes 32-37 of our strcpy overwrite the low 6 bytes of `C.fd` with `target_bytes[:6]`, and the null terminator at position 38 lands at byte 6 of `C.fd` (which was already `0x00`). The upper 2 bytes are untouched (also already `0x00`). Result: `C.fd = flag_user - 0x20`.

Why `flag_user - 0x20` instead of `flag_user` directly? If we pointed straight at the flag chunk, the next `insert()` would `strcpy` into it and overwrite the first bytes of the flag. By landing 32 bytes *before* the flag, we get a chunk whose 32-byte data area ends exactly where the flag begins. Then we can use `edit()` on it to fill those 32 bytes with `\x01` values, and `puts()` prints 32 junk bytes followed by the flag.

### Phase 7: Pop the Poisoned Chain

```python
insert(io, b'Y')     # pops C from tcache[0x20]. tcache[0x20] head = C.fd = flag_user-0x20
insert(io, b'\x01')  # pops flag_user-0x20. This is now a chunk in our array!
```

The second insert returns the fake chunk at `flag_user - 0x20`. We store `"\x01\0"` there (2 bytes, safely before the flag). `\x01` is lex-smallest so this chunk becomes `array[0]`.

### Phase 8: Edit and Peek

```python
edit_exact(io, b'\x01' * 32)   # fill the 32 bytes before the flag with non-null
leaked_flag = peek(io)          # puts reads 32 x \x01, then continues into flag
```

`puts(array[0])` prints 32 `\x01` bytes, then hits the flag chunk and prints right through `bctf{...}` until the null at the end of the flag string. Flag extracted.

## Running It

```
$ python3 solve.py REMOTE
[*] d_chunk=0x55555555a180 flag_user=0x55555555a0d0
[*] poison payload: b'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\x....' (len 38)
[*] count after poison: 7
[*] leaked output: b'\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01bctf{u53_4ft3r_fr33_f4n_v5_0v3rl4pp1n6_4110c4t10n5_3nj0y3r_8c6fd0b452}'
[+] FLAG: bctf{u53_4ft3r_fr33_f4n_v5_0v3rl4pp1n6_4110c4t10n5_3nj0y3r_8c6fd0b452}
```

32 bytes of `\x01` garbage followed immediately by the flag. Clean.

## Key Takeaways

**Technique: tcache size confusion leading to overlapping allocations.** If you can corrupt a chunk's size field before freeing it, glibc will put it in the wrong tcache bin. When you then allocate from that bin, glibc gives you a chunk that's larger than the original allocation — and anything you write past the original size overlaps with neighboring allocations. This is the "overlapping allocations" in the flag.

**The off-by-one-position problem was the interesting design.** The direct approach (use edit overflow to corrupt C's fd while C is still in tcache) doesn't work because the overflow from a 0x20 chunk reaches the *next* chunk's header but not its fd — you're 8 bytes short. The size-confusion trick adds an extra 0x10 bytes of "legitimate" write range, bridging that gap.

**Null byte handling with strcpy and heap pointers.** Heap addresses on x86-64 typically have two zero bytes at the top. strcpy stops at null, so you can't write a full 8-byte pointer. But if you're overwriting an fd that was itself a heap pointer (and therefore also has two zero bytes at the top), you only need to write the low 6 bytes — the high 2 were already right. Aligning your strcpy payload so the null terminator lands exactly where those zeros are is the key trick.

**The flag was already on the heap — no RCE needed.** This is a common CTF pattern worth recognizing: sometimes the challenge puts the secret into memory and leaves it there. If you can redirect a read primitive (here, `puts(array[0])`) to point at the secret's location, you win without ever hijacking execution. Much simpler than a full ROP chain.

**The flag itself is a hint.** `u53_4ft3r_fr33` = "use after free" and `0v3rl4pp1n6_4110c4t10n5` = "overlapping allocations." The challenge name is whispering the solution at you the whole time.

For more background on tcache poisoning, the [how2heap](https://github.com/shellphish/how2heap) repository has standalone examples of tcache_poisoning and tcache_house_of_spirit that walk through the same primitives in a cleaner context. Highly recommended if this exploit felt like magic — spend 30 minutes with those demos and it'll click.
