# tiles+ai

**Category:** Reversing | **Difficulty:** Hard | **Flag:** `bctf{in_the_matrix_straight_up_multiplying_it_ec3428a06}`

## TL;DR

A stripped binary that uses Intel AMX (Advanced Matrix Extensions) — hardware-accelerated matrix multiplication — to transform a 48×16 state through a series of matrix ops driven by your hex input. The key insight is that each byte you provide only affects a single column of that state, turning the problem into a BFS over a manageable grid abstraction.

## What We're Given

A single binary called `chall` and a remote service at `ncat --ssl tiles--ai.opus4-7.b01le.rs 8443`. The challenge description is blunt: *"I love matrix multiplication 😍 Note: this challenge was tested with Intel SDE version 10.8.0 with the Sapphire Rapids preset."*

That note about Intel SDE is your first hint that something unusual is going on at the CPU instruction level. Sapphire Rapids is Intel's Xeon gen that introduced AMX — a class of instructions for in-silicon matrix math. If the challenge author is specifically telling you they tested with a CPU emulator, they're warning you: you might not be able to run this natively.

## Initial Recon

The usual suspects first:

```
$ file chall
chall: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

Statically linked and stripped — no shared libs to lean on, no symbol names to help. `checksec` shows NX and Partial RELRO, nothing exotic on the protection side.

```
$ strings chall | grep -iE "(flag|bctf|tile|amx|cannot)"
flag.txt
Cannot run on this CPU
```

Two useful strings: the binary reads `flag.txt` (meaning it reads the flag itself — we just need to get it to print it), and it has an error path for unsupported CPUs.

```
$ objdump -d chall | grep -iE "(ldt|tdpb|tileload|tilestore|tilerel)"
  ldtilecfg
  tileloadd
  tdpbssd
  tilestored
  tilerelease
```

There it is. `tdpbssd` is an AMX instruction — "Tile Dot Product of Bytes, Signed × Signed, accumulate to Dwords". This is the hardware doing 8-bit integer matrix multiplication in a single instruction. `ldtilecfg`, `tileloadd`, `tilestored`, and `tilerelease` are the infrastructure around it: configure tile registers, load data in, store data out, and clean up.

## Obstacle 1: The Binary Won't Run

The first attempt to run the binary produces:

```
Cannot run on this CPU
```

`strace` tells us exactly what's happening:

```
arch_prctl(ARCH_REQ_XCOMP_PERM, 0x12 /* XFEATURE_XTILE_DATA */) = 0
arch_prctl(ARCH_REQ_XCOMP_PERM, 0x11 /* XFEATURE_XTILE_CFG  */) = -1 EOPNOTSUPP
```

The binary is asking the kernel for permission to use two AMX-related CPU features. `0x12` (XTILE_DATA — the actual tile registers) succeeds. `0x11` (XTILE_CFG — the tile configuration register) fails with `EOPNOTSUPP`. On newer kernels, XTILE_CFG permission is considered implicit when you already have XTILE_DATA — the kernel doesn't expose the old interface for it. The binary was written for an older kernel model.

The fix is straightforward: patch the second `arch_prctl` call so it always succeeds. The call sequence at `0x4011ce` is a `call` into the syscall wrapper. We replace it with `xor rax, rax; nop; nop` — five bytes that zero out `rax` (making the return value 0 = success) and do nothing else. The result is `chall_patched2`, which runs correctly since we do have AMX support on a Sapphire Rapids machine.

## What AMX Is and Why It Makes This Interesting

Quick detour, because this is the whole point of the challenge:

AMX (Advanced Matrix Extensions) is a set of Intel CPU instructions for hardware-accelerated matrix operations, introduced on Sapphire Rapids (Xeon 4th gen). Instead of loops, you load up to 8 "tile registers" (tmm0–tmm7) each holding a small matrix, and fire off a single instruction like `tdpbssd tmm6, tmm0, tmm3` which computes `tmm6 += tmm0 × tmm3` where the multiplication is done in signed 8-bit integers accumulated into 32-bit results.

The clever/evil part for this challenge: tile registers have two layouts.
- **A-format**: straightforward row-major M×K matrix of int8
- **B-format**: a K×N matrix where the bytes are *physically reordered* in memory. Specifically, the K dimension is stored in groups of 4 (packed as dwords), so if you load a regular row-major matrix into a B-tile with stride 64, the logical `B[k][n]` doesn't map to `M[k][n]`. It maps to `M[(k/4)*4 + n/4][4*(n%4) + k%4]`.

That reordering caused our first dead end, and we'll come back to it.

## Binary Structure

Once the patched binary runs, the program flow becomes clear through GDB and static analysis:

1. **Init**: configure AMX tiles, run the CPU permission dance
2. **3 rounds** (round 0, 1, 2), each:
   - Copy 768 bytes (3 × 16×16 int8 matrices = the "state") from a fixed initial value
   - Print `N> ` prompt
   - Read a line of hex from stdin
   - Parse it as pairs of hex nibbles — each pair `(p, q)` where `p ∈ [0,15]` and `q ∈ [0,3]`
   - For each pair: run the AMX pipeline to transform the state, then validate
3. After all 3 rounds pass validation: read and print `flag.txt`

The state is three 16×16 int8 matrices (let's call them M0, M1, M2), concatenated as a 48×16 array. The validation check after every hex pair: all 36 of the first rows must have non-negative entries that sum to less than 2. Think of it as: each "active" row must contain at most a single 1 (and no negative values). The final check for each round: `M1[1][0]` must equal 1.

The data baked into the binary includes:
- 16 "A tiles" at `0x409000` — selected by the first nibble `p`
- 16 "A2 tiles" at `0x40a000` — also keyed on `p`
- A bank of 72 "B matrices" at `0x40b000` — indexed by `(p >> 3, q)` and which of 9 slots
- 3 sets of initial matrices at `0x40f800` — one per round

## The AMX Pipeline (What Each Hex Pair Does)

For each hex pair `(p, q)`, the binary runs three `tdpbssd` operations per output matrix (and there are 3 output matrices), structured like this in pseudocode:

```python
for bp in range(3):          # which output matrix
    tmm7 = zeros(16×16, int32)
    for j in range(3):       # which input matrix  
        tmm6 = input[j] @ A[p]          # A[p] loaded as B-format
        tmm7 += B_bank[p>>3, q][bp*3+j] @ tmm6   # B_bank loaded as A-format
    tmm7 += input[bp] @ A2[p]          # A2[p] loaded as B-format
    output[bp] = truncate_to_int8(tmm7)
```

This looks like a mess of matrix multiplications. The key to making sense of it is understanding what `A[p]` and `A2[p]` actually contain.

## The Key Insight: Only One Column Changes

When you look at the data in `A[p]` (at `0x409000 + p*256`), each one is a 16×16 matrix with a **single** 1 at position `(5*(p>>2), 5*(p&3))` — that's position `(0,0), (0,5), (0,10), (0,15), (5,0), (5,5), ...` for p = 0..15. Everything else is 0.

`A2[p]` is the complement: it has 1s at all 16 positions in the 4×4 grid `{0,5,10,15}²` *except* the one that `A[p]` has.

Now remember the B-format reordering: when `A[p]` (a 16×16 matrix with a single 1 at position `(r, c)`) is loaded as a B-tile with stride 64, the logical B matrix has `B[k][n] = A[(k/4)*4 + n/4][4*(n%4) + k%4]`. After working through the math, `A[p]` in B-format becomes a **diagonal matrix** with a single 1 at `(p, p)` — and `A2[p]` in B-format becomes the identity minus that diagonal entry.

This is the elegant part. Because `A[p]` as a B-tile is `diag(p)` (only the p-th diagonal entry is 1), the expression `input[j] @ diag(p)` extracts only column `p` of `input[j]`, zeroing everything else. And `input[bp] @ (I - diag(p))` preserves everything *except* column `p`.

The punchline: **each hex pair `(p, q)` only modifies column `p` of the 3-matrix state**. All other columns are passed through unchanged. This is a massive simplification — instead of tracking a 48×16 state, we can treat each column independently, and a single hex pair only "touches" column `p`.

## The Grid Interpretation

Looking at which initial matrices have nonzero values, the 48 rows of the state (16 rows × 3 matrices) break into a 6×6 active grid (rows 0–35) plus 12 inert rows (36–47). If you define `grid(r, c) = 6*r + c` for `r, c ∈ [0,5]`, the active state is exactly a 6×6 binary grid where each cell is 0 or 1.

The 16 possible `p` values split into two groups by behavior:
- **p ∈ [0,7]** (T_A / T_B operations): shift values along the **column** dimension of the grid (left/right shifts with different wrap behavior depending on `q`)
- **p ∈ [8,15]** (T_C / T_D operations): shift values along the **row** dimension of the grid (up/down shifts)

Each shift operation is "merge at one end, delete at the other" — there's no wrapping, things fall off the edge. The validation constraint (every active row sums to ≤ 1) means at no point can a shift cause two 1s to land in the same position.

The per-round goal: get a 1 into grid position `(2, 5)`, which corresponds to `M1[1][0]` in the matrix representation.

## Dead Ends Worth Mentioning

**Dead end 1: treating A-tiles as identity in B-format.** The first emulator (`emulate.py`) assumed that loading a row-major matrix as a B-tile was a no-op — that the bytes came out the same. Wrong. The B-format reordering is non-trivial and the emulator was producing incorrect results. The fix in `emulate2.py` implements the actual `B[k][n] = M[(k/4)*4 + n/4][4*(n%4) + k%4]` mapping.

**Dead end 2: brute-force shifting column 0.** An early attempt to solve round 0 column 0 by just applying T_B four times failed — at an intermediate step, `M0[15][15]=1` and `M0[15][0]=1` would both be in row 15, making the row sum 2 and failing validation. The constraint isn't just on the final state — it applies after *every* hex pair. You have to move things carefully.

**Dead end 3: the final tdpbssd is accumulating, not resetting.** An early read of the disassembly misread the fourth `tdpbssd` as initializing rather than accumulating into `tmm7`. Getting this wrong produces a completely wrong emulator.

## Building the Emulator and BFS Solver

With the correct model in hand (`emulate2.py`), we built a BFS over the state space. The state is the 6×6 binary grid (just 36 bits — tiny). The moves are the 16 valid hex pairs (p, q), but only 4 combinations produce "sparse" operations that can pass validation without immediately creating row sums of 2:
- `(p, 0)` and `(p, 1)` for `p ∈ [0,7]`
- `(p, 2)` and `(p, 3)` for `p ∈ [8,15]`

BFS explores sequences of moves, pruning any state where the validation constraint is violated. Since the state space is 2^36 in the worst case but heavily pruned in practice, this converges quickly for each round.

The found solutions:
- **Round 0**: `01e2e210f3f3f3010101` — 10 operations
- **Round 1**: `01f320e201` — 5 operations
- **Round 2**: `0120a2a2c231f2f2f2109393019311e320b211e3e300e31010923092921111c311d230e23030d310f3209201e2e210b3b3b30101` — 52 operations

Round 2 is significantly longer because the initial state is more complex and the target requires more careful maneuvering.

## The Solve Script

`solve.py` connects over TLS to the challenge server and sends the three precomputed answers:

```python
ROUND_INPUTS = [
    "01e2e210f3f3f3010101",
    "01f320e201",
    "0120a2a2c231f2f2f2109393019311e320b211e3e300e31010923092921111c311d230e23030d310f3209201e2e210b3b3b30101",
]
```

The connection loop reads until it sees `"> "` (the round prompt), sends the answer, then reads for the next prompt. After three rounds, the remaining output contains the flag.

## Running It

```
$ python3 solve.py
[Recv] b'0> '
[Send] b'01e2e210f3f3f3010101\n'
[Recv] b'1> '
[Send] b'01f320e201\n'
[Recv] b'2> '
[Send] b'0120a2a2c231f2f2f2109393019311e320b211e3e300e31010923092921111c311d230e23030d310f3209201e2e210b3b3b30101\n'
[Recv] b'bctf{in_the_matrix_straight_up_multiplying_it_ec3428a06}\n'

[Final output]:
bctf{in_the_matrix_straight_up_multiplying_it_ec3428a06}
```

## Key Takeaways

**AMX is real and it's in production silicon.** If you see `tdpbssd` in a CTF binary, you're dealing with tile-based matrix operations. The Intel ISA reference and intrinsics guide are your friends. The SDE (Software Development Emulator) lets you run AMX code without owning Sapphire Rapids hardware.

**B-tile format is a trap.** The biggest footgun in AMX reversal is assuming a matrix loaded into a B-tile has the same logical layout as in memory. It doesn't. `B[k][n] = mem[(k/4)*4 + n/4][4*(n%4) + k%4]`. Always verify your emulator against actual memory dumps from GDB.

**The "column independence" insight was the unlock.** Without figuring out that each hex pair only affects one column, this challenge is an opaque 48×16 state machine. With it, you have a clean 6×6 binary grid with simple shift operations — something you can BFS in seconds. Always look for structure in the data constants before diving into brute force.

**Patch first, debug second.** The `arch_prctl` failure was a one-byte context — once you identify it with `strace`, the patch is trivial. Don't let environment setup blockers waste hours.

**Validation constraints bite.** The "row sum ≤ 1 after every operation" rule is easy to miss if you only check the final state. Check intermediate validity at every step, or your BFS will find paths that work in theory but fail in practice.
