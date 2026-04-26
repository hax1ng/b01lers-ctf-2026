# Favorite Potato

**Category:** Reversing | **Difficulty:** Medium-Hard | **Flag:** `bctf{Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w..:D}`

## TL;DR

A 5.8MB 6502 binary that runs as a stream (not in RAM) is actually just 250,000 repetitions of 10 unique macro shapes. Every macro is invertible, so we reverse the program and apply inverse operations to recover input from output instantly.

## What We're Given

The challenge drops us with:

- `favorite_potato.py` — the server script
- `code.bin.gz` — compresses down to 257KB but expands to a whopping **5,820,001 bytes**
- `test.bin` — a 9-byte toy example
- `screenshot.png` — a Commodore 64 BASIC screen showing `INPUT A,X,Y; POKE 780/781/782; SYS ...`

The challenge description reads:
> Yay, at last - I managed to upgrade my old potato. Now I can run suuuuper loooong binaries that nobody can reverse (RAM is still 64k but I only need a minimal amount).

The server is a C64 emulator. You connect, it runs `code.bin` 20 times with 20 different random `(A, X, Y)` register values, shows you the output registers, then asks you to give back all 20 inputs. Get all 20 right and you get the flag.

The Commodore 64 is a classic 8-bit home computer with a 6502 CPU. Registers are 8-bit: A (accumulator), X, and Y (index registers). The address space is 16-bit — 64KB maximum. So how is a 5.8MB binary even a thing? That's the puzzle.

## Initial Recon

First things first — look at `test.bin` to understand what format we're dealing with:

```
$ xxd test.bin
00000000: 0818 692a cac8 c828 60              .i*....(`
```

Disassembling those 9 bytes:
```
PHP         ; push processor flags
CLC         ; clear carry
ADC #$2A    ; A += 42
PLP         ; pop flags (restore)
DEX         ; X -= 1
INY         ; Y += 1
INY         ; Y += 1
RTS         ; return
```

So `test.bin` takes `(A, X, Y)` and returns `(A+42, X-1, Y+2)`. Clean.

Now `code.bin`:

```
$ xxd -l 8 code.bin
00000000: 08 18 69 a3 28 08 18 69  ..i.(..i
```

Same `PHP CLC ADC #imm PLP` opener. And when we count opcode frequencies across the whole 5.8MB:

```
0x68 (PLA): 770,345
0x48 (PHA): 740,321
0x98 (TYA): 360,319
0xa8 (TAY): 360,303
0x28 (PLP): 340,305
0x9a (TXS): 300,310   <-- interesting
0x08 (PHP): 280,312
```

Huge amounts of stack push/pop, and suspiciously many `TXS` (transfer X to stack pointer) and `TSX` (transfer stack pointer to X) instructions. That hint about "RAM is still 64k" is tickling the back of our brain. Let's keep reading.

## The Vulnerability / Trick

There are actually **two** tricks here stacked on top of each other.

### Trick 1: Stream Execution

The 6502 has a 16-bit program counter — it can only address 64KB. So how does a 5.8MB binary run? The server doesn't actually load the binary into RAM as code. Instead, it treats the file as a **stream**, with the program counter being a 24-bit file offset that just walks forward through the bytes. Real branches and short jumps still work (they're relative), but the CPU never needs a full 64KB map of the code. The only genuine `RTS` in the entire 5.8MB file is the very last byte — everything else that looks like `0x60` is just an immediate operand of something else.

This is what the challenge description was hinting at with "RAM is still 64k but I only need a minimal amount" — only a tiny working area of RAM is needed (zero page + stack), while the code itself is executed linearly from the file.

### Trick 2: It's All Macros

Once we know that, the key insight: scan for the pattern `28 08` (PLP immediately followed by PHP). That's a macro boundary — one operation finishes restoring flags, the next starts saving them. Splitting on these boundaries gives us exactly **250,000 macros**.

After normalizing away the immediate values (replacing them with a placeholder `0xFF`), there are only **10 unique macro shapes** in the entire 5.8MB binary:

| Count   | Operation      |
|---------|----------------|
| 60,000  | swap A, Y      |
| 30,000  | swap A, X      |
| 30,000  | swap X, Y      |
| 30,000  | A = ROR(A, N)  |
| 30,000  | A ^= Y         |
| 29,999  | A ^= imm       |
| 20,000  | A += imm       |
| 10,000  | X += A         |
| 10,000  | Y += A         |
| 1       | A ^= imm + RTS (final) |

The whole 5.8MB file is just these 10 operations, scrambled and repeated 250,000 times.

### Trick 3: TSX/TXS as Stack Pointer Arithmetic

The flag itself spoils the third trick: `Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w`. The macros use `TSX` (copy SP into X) and `TXS` (copy X into SP) to **directly manipulate the stack pointer** without pushing or popping. This lets the macro code "peek" at values buried in the stack — for example, to implement `A ^= Y`, the code pushes A and Y onto the stack, then uses `TSX/INX/TXS` to skip past the top entry and `PLA` to pull the one below it. It's clever assembly golf for register manipulation.

### The Inversion

Here's the beautiful part: **every single one of those 10 operations is invertible**:

- `swap A,Y` → swap A,Y again (it's its own inverse)
- `swap A,X` → same
- `swap X,Y` → same
- `A = ROR(A, N)` → `A = ROL(A, N)` (= `ROR(A, 8-N)`)
- `A ^= Y` → `A ^= Y` (XOR is its own inverse)
- `A ^= imm` → `A ^= imm`
- `A += imm` → `A -= imm`
- `X += A` → `X -= A` (A is unchanged by this op)
- `Y += A` → `Y -= A`

So to go from output `(A_out, X_out, Y_out)` back to input `(A_in, X_in, Y_in)`, we just walk the program backwards and apply the inverse of each operation. No brute force. No emulation. Pure math.

## Building the Exploit

The solve has four parts:

**1. Parse the binary into a macro list**

`macro_emu.py` scans through `code.bin`, splits on `28 08` boundaries, normalizes each macro's shape, and matches it against the 10 known patterns. The result is a list of `(op_name, immediate)` tuples:

```python
def parse_program(data):
    pc = 0
    boundaries = [0]
    prev_was_plp = False
    while pc < len(data):
        op = data[pc]
        if op == 0x08 and prev_was_plp and pc != 0:
            boundaries.append(pc)
        prev_was_plp = (op == 0x28)
        pc += INSTR_LEN[op]
    boundaries.append(len(data))
    # ... match each segment against SHAPES dict
```

**2. Invert the program**

`solve.py` is the heart of the solution. We walk the program list backwards and apply the inverse of each operation:

```python
def invert(program, A, X, Y):
    for op, imm in reversed(program):
        if op == 'SWAP_AY': A, Y = Y, A
        elif op == 'SWAP_AX': A, X = X, A
        elif op == 'SWAP_XY': X, Y = Y, X
        elif op == 'ROR_A':
            n = imm % 8
            if n:
                # Forward was ROR by n; inverse is ROL by n = ROR by (8-n)
                A = ((A << n) | (A >> (8 - n))) & 0xFF
        elif op == 'XOR_AY':
            A ^= Y          # involution: same operation
        elif op in ('XOR_A_IMM', 'XOR_A_IMM_FINAL'):
            A ^= imm        # involution
        elif op == 'ADD_A_IMM':
            A = (A - imm) & 0xFF
        elif op == 'ADD_X_A':
            X = (X - A) & 0xFF   # A unchanged, so we can subtract it
        elif op == 'ADD_Y_A':
            Y = (Y - A) & 0xFF
    return A, X, Y
```

We self-test this with 20 random inputs: run forward with `execute()`, then `invert()` on the result, and check we get back to where we started. All 20 pass.

**3. Connect to the server**

`exploit.py` uses pwntools (a CTF toolkit that handles network connections) to talk to the server. The server shows us 20 output triples, one per line. We parse them with a regex, call `invert()` on each, and submit the recovered inputs:

```python
data = open('code.bin', 'rb').read()
program = parse_program(data)         # do this ONCE — takes a couple seconds
# ...
matches = re.findall(r'Final output #(\d+): A=(\d+) X=(\d+) Y=(\d+)', bulk)
for idx_str, A_out, X_out, Y_out in matches:
    A_in, X_in, Y_in = invert(program, int(A_out), int(X_out), int(Y_out))
    # submit A_in, X_in, Y_in
```

The inversion of each round is instantaneous — it's 250,000 simple arithmetic operations in Python, which runs in under a second.

## Running It

```
$ python3 exploit.py
[*] Loading and parsing code.bin...
[*] Parsed 250000 macros
[*] Round 1:  out=(183,71,44)  -> in=(12,200,88)
[*] Round 2:  out=(99,14,201)  -> in=(67,88,135)
[*] Round 3:  out=(41,255,17)  -> in=(201,44,9)
...
[*] Round 20: out=(128,0,255)  -> in=(94,17,201)
[*] Server response:
Correct!
Here is your flag: bctf{Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w..:D}

[+] FLAG: bctf{Nev3r_underst00d_why_we_n33d_TSX_and_TXS_unt1l_n0w..:D}
```

## Dead Ends Worth Knowing

Before we landed on inversion, we tried the obvious approaches:

**Brute force:** The input space is 256^3 = 16.7 million possible `(A, X, Y)` triples. Our Python emulator could evaluate one in about 10 seconds (32 million 6502 cycles). That's 1.9 years of compute. Hard pass.

**C emulator:** We wrote `emu6502.c` and got that down to 0.06s per evaluation — still 280 hours for a full table. Also no.

**Meeting in the middle / precomputed lookup table:** Same total work, 100MB of RAM, and still 280 hours to build. Same problem.

The breakthrough was realizing that brute force is only necessary if the function is one-way. Once we spotted the macro structure, inversion was the obvious path.

**The PC truncation bug:** Our initial Python emulator treated the 16-bit program counter normally and pushed a fake return address onto the stack as a sentinel. This caused the binary's only real `RTS` to pop a truncated 16-bit address and jump into the middle of the code. The fix was to detect end-of-file by position and halt cleanly — never actually execute the sentinel RTS.

## Key Takeaways

- **Large binaries with repetitive structure beg for macro analysis.** When you see a huge binary that gzips down to 4% of its size, there's massive repetition. Find the boundaries, normalize, count unique shapes.

- **Check for invertibility before brute-forcing.** If every operation in your program is individually reversible, you can go backwards for free. The 10 operations here are all either involutions (their own inverse) or have obvious arithmetic inverses.

- **TSX/TXS as stack pointer arithmetic is a real assembly technique.** On the 6502, these are the only way to read or write the stack pointer directly. Clever code can use them to "address" specific slots in the stack without sequential push/pop — essentially treating the hardware stack as a small random-access array.

- **"RAM is still 64k" was a hint.** The challenge description was telling us the binary runs as a stream from disk, not from memory. When a binary is 90x larger than the address space, something unusual is happening. Always read the flavor text.

- **pwntools makes remote I/O painless.** `remote(host, port, ssl=True)` + `recvuntil()` + `sendline()` handles all the socket plumbing so you can focus on the math.
