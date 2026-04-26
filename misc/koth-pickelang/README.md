# pickelang

**Category:** Misc (KOTH) | **Difficulty:** Hard | **Final payload:** 1779 bytes (3558 hex chars)

## TL;DR

Build a 1779-byte pickle that parses a string `[A, B, C]`, then computes `A^B mod C` using only `operator.add`, `operator.getitem`, `struct.pack/unpack`, and recursive pickle subroutines via `BINPERSID`. The shortest payload wins. Pack mutable state into tuples stored in shared memo so subroutines can be called with just 6 bytes per invocation.

## What We're Given

The challenge is "pickelang" - an esolang built on Python's pickle VM. The runner (`pickelang.py`) is brutally minimal:

```python
class Pickelang(Unpickler):
    def find_class(self, module, name):
        if name in ['add', 'getitem']:    return getattr(operator, name)
        if name in ['pack', 'unpack']:    return getattr(struct, name)
        if name == 'input':               return input
        raise NotImplementedError("no")
    def persistent_load(self, pid):
        pickelang = Pickelang(BytesIO(pid))
        pickelang.memo = self.memo  # SHARED memo across nested loads!
        return pickelang.load()

print(Pickelang(BytesIO(bytes.fromhex(input('pickelang > ')))).load())
```

So we get:
- `operator.add` — only arithmetic (no subtract, no multiply)
- `operator.getitem` — index into sequences
- `struct.pack/unpack` — bytes ↔ ints
- `builtins.input` — read input
- **`BINPERSID` (`Q`)** — pop bytes from stack, run as nested pickle, **share the memo**

Constraints: A in [2, 32767], B in [1, 32767], C in [32768, 65535]. Result fits in 16 bits.

KOTH = "King of the Hill" — shortest valid submission wins.

## The Hard Part: Strings, Bytes, and No Real Ops

Three immediate brick walls:

1. **str → bytes is forbidden.** `input()` returns a `str` like `"[5, 3, 100]"`. `BINPERSID` needs `bytes`. There's no `int()`, `bytes()`, `chr()`, `ord()`, `eval()`, `.encode()` available.
2. **No multiplication or subtraction.** Only `add`. Computing `A * B mod C` with only `+` and `getitem` is... interesting.
3. **No comparison or branching.** No `<`, `==`, `if`. We have to express "if x then a else b" as `(a, b)[x]`.

## Trick #1: String→Bytes via Translation Table

We can't decode the input string, but we CAN translate each character to a piece of pre-baked pickle bytes that, concatenated, form a valid inner pickle:

```python
TABLE = {
    '[': b'(I',     # MARK + INT-prefix
    '0'-'9': digit, # digit chars themselves
    ',': b'\nI',    # terminate INT, start next INT
    ' ': b'',       # skip
    ']': b'\nl.',   # terminate INT, build LIST, STOP
}
```

Translating `"[5, 3, 100]"` yields `b'(I5\nI3\nI100\nl.'` — a valid pickle that loads to `[5, 3, 100]`.

Iterate over input characters, look each up in the dict, concatenate via `add`, then `BINPERSID` the result.

To avoid handling variable input length, **pad the input** with `']' * 30` so we always do exactly 21 character iterations. Extra `']'`s just append `\nl.` AFTER the first `STOP` byte, where they're harmless.

## Trick #2: Russian-Peasant Multiplication

Without `*`, multiply via shift-and-add:

```
mul(x, y):
  r = 0
  for each bit of y (MSB first):
    r = (r + r) mod C       # double
    if bit: r = (r + x) mod C  # add x conditionally
  return r
```

We do 16 iterations (one per bit of y, since y < 2^16). The conditional uses `(d_r, add_x)[bit]` — a 2-tuple indexed by the bit.

## Trick #3: Mod C Without Subtraction

Standard trick: precompute `-C` once, then `mod_c(x)` works as:

```
diff = x + (-C)
sign_byte = pack('>i', diff)[0]    # 0x00 if diff >= 0, 0xFF if negative
idx = SIGN_DICT[sign_byte]          # {0:0, 255:1}
result = (diff, x)[idx]
```

When `x` is in `[0, 2C-1]` (always the case after one add), this gives `x mod C`.

## Trick #4: Computing -C

We can't subtract, so how do we get `-C`? Via two's complement byte manipulation:

```
pack('>H', C) → 2 bytes [hi, lo]
COMPLEMENT[i] = 255-i  (256-byte lookup table)
neg_high = COMPLEMENT[hi]
neg_low  = COMPLEMENT[lo]
neg_bytes = pack('>BBBB', 0xff, 0xff, neg_high, neg_low)  # bytes for -C-1
unpack('>i', neg_bytes)[0] = -C - 1
add(-C-1, 1) = -C
```

The `COMPLEMENT` table costs 263 bytes but enables negation everywhere.

## Trick #5: Bit Extraction via the `pack('>H', byte+byte)` Trick

To extract the top bit of a byte AND shift the byte left by 1 in a single op:

```
doubled = pack('>H', byte + byte)
# doubled[0] = top bit (0 or 1)  -- the carry-out
# doubled[1] = (byte << 1) & 0xFF -- the new byte
```

This eliminates separate `HALF` and `TOP_BIT` lookup tables (saving ~512 bytes vs the naive approach).

## Trick #6: Square-and-Multiply for Exponentiation

Same MSB-first pattern for `pow(A, B, C)`:

```
result = 1
base = A
for each bit of B (MSB first):
  square = mul(result, result)
  cand   = mul(square, base)
  result = (square, cand)[bit]
```

Since B < 2^15, the highest bit (bit 15) is always 0 — we can skip the first iter.

## The Real Optimization Game

A working payload is "easy" — getting it small enough to actually submit is the challenge. The remote service feeds your hex via `input()`, and Linux's MAX_CANON limit truncates stdin lines at 4095 characters. **Any hex longer than 4094 chars gets silently chopped, producing pickle errors at the cut point.**

Our naive working payload was ~3823 bytes (7646 hex chars) → got truncated → errored.

### Subroutines via BINPERSID

Define a function once as raw pickle bytes stored in memo, then call it via `bg(slot) + BINPERSID`. The nested pickle reads/writes the SAME memo (key insight: persistent_load shares the memo). So subroutines can take args from fixed memo slots and return values via STOP.

Major catch: **the inner pickle's BINPUT does NOT persist to the outer memo** (Python wraps the memo or the `bp` opcodes use a different write path). So the subroutine can't mutate outer state directly — it must RETURN values that the caller stores.

### The Big Win: Tuple-Packed State (v9 → v13)

v9 returned a 2-tuple `(new_r, new_byte)`, and the caller did:
```
bg(72) BINPERSID bp(64) POP                            # save tuple
bg(2) bg(64) push_int(0) TUPLE2 REDUCE bp(82) POP     # extract [0]
bg(2) bg(64) push_int(1) TUPLE2 REDUCE bp(85) POP     # extract [1]
```
= 28 bytes per call.

**v13's insight**: store the (r, byte) tuple directly in a memo slot. The subroutine reads it from the slot, returns a new tuple. The caller just overwrites the slot:

```
bg(72) BINPERSID bp(88) POP    # 6 bytes!
```

Save 22 bytes per call × 32 calls (16 mul + 16 pow) = **704 bytes saved**.

The only extra cost: extracting r/byte from the tuple at the start of each subroutine (~22 bytes once per sub), and final r extraction outside the loop (~10 bytes once per outer routine). Net savings dominate.

### Other Cuts in v13

- **21 parse iters instead of 22** — max input is `[12345, 12345, 12345]` = 21 chars. Saved ~23 bytes.
- **15 pow iters instead of 16** — B < 2^15 so bit 15 is always 0. The first iter would just square `1*1=1` and add nothing. Skip it; just advance the byte. Saved ~30 bytes.
- **Cached `'>H'` format string in memo[6]** — used many times during the bit-extraction trick.

## Final Memo Layout

```
0: TABLE dict (parse)
1: add, 2: getitem, 5: SIGN dict, 7: pack, 21: unpack
6: '>H' format string (cached)
8: A, 9: B, 10: C, 11: -C
15: COMPLEMENT (255-i lookup)
24: result, 25: base, 26: pack(B)
40-44: mod_c scratch
50-51: mul args, 60-65: mul/pow scratch
70: mul subroutine
71: mod_c subroutine
72: mul_iter subroutine (returns (r, byte) tuple)
73: pow_iter subroutine (returns (result, byte) tuple)
74: parse_full subroutine
80, 81: x, pack(y)
88: mul state tuple (r, byte)
89: pow state tuple (result, byte)
```

## Building the Exploit

See `work/build_min13.py` for the full builder. Key pieces:

```python
def build_mul_iter_v13():
    p = b''
    # Extract r and byte from the state tuple at outer[88]
    p += bg(2) + bg(88) + push_int(0) + TUPLE2 + REDUCE + bp(30) + POP   # r
    p += bg(2) + bg(88) + push_int(1) + TUPLE2 + REDUCE + bp(31) + POP   # byte
    # doubled = pack('>H', byte+byte) — bit-extract trick
    p += bg(7) + bg(6) + bg(1) + bg(31) + bg(31) + TUPLE2 + REDUCE + TUPLE2 + REDUCE + bp(60) + POP
    p += bg(2) + bg(60) + push_int(0) + TUPLE2 + REDUCE + bp(63) + POP   # bit
    p += bg(2) + bg(60) + push_int(1) + TUPLE2 + REDUCE + bp(64) + POP   # new_byte
    # d_r = mod_c(r+r); add_x = mod_c(d_r + x); new_r = (d_r, add_x)[bit]
    p += bg(1) + bg(30) + bg(30) + TUPLE2 + REDUCE + call_modc() + bp(61) + POP
    p += bg(1) + bg(61) + bg(80) + TUPLE2 + REDUCE + call_modc() + bp(62) + POP
    p += bg(2) + bg(61) + bg(62) + TUPLE2 + bg(63) + TUPLE2 + REDUCE + bp(65) + POP
    # Return (new_r, new_byte) tuple
    p += bg(65) + bg(64) + TUPLE2
    p += STOP
    return p

def call_mul_iter():
    return bg(72) + BINPERSID + bp(88) + POP   # 6 bytes per call
```

## Running It

```
$ python3 build_min13.py
Total: 1779 bytes (hex: 3558)
OK: [5, 3, 100] -> 25 (expected 25)
OK: [2, 10, 65535] -> 1024 (expected 1024)
OK: [12345, 678, 54321] -> 48537 (expected 48537)
OK: [32767, 32767, 65535] -> 65533 (expected 65533)
OK: [2, 1, 32768] -> 2 (expected 2)
OK: [7, 100, 50000] -> 10001 (expected 10001)
OK: [100, 200, 60000] -> 40000 (expected 40000)
OK: [2, 32767, 32768] -> 0 (expected 0)
OK: [32767, 1, 32768] -> 32767 (expected 32767)
OK: [2, 16384, 65521] -> 16 (expected 16)
All tests passed: True
```

50/50 random stress tests also pass. Submit `out/payload_v13.bin` (1779 raw bytes) to the KOTH service.

## The MAX_CANON Saga

The most painful part of this challenge was discovering that **all of our earlier "working" payloads silently failed remotely** because their hex exceeded Linux's 4095-char canonical-mode stdin limit. We hit this three times:

1. **v3 (3823 bytes / 7646 hex)** → remote `UnpicklingError: invalid load key, '"'` (truncation hit byte 0x22)
2. **Submitted v8 by mistake (8126 hex)** → `invalid load key, '8'` (truncation hit byte 0x38)
3. **v13 (3558 hex)** → fits! All tests pass remotely.

The lesson: **the local test harness doesn't replicate remote stdin limits**. Always test the actual submission path.

## Key Takeaways

- **Pickle is a real Turing-complete VM.** With just `add`, `getitem`, and shared-memo recursion via `BINPERSID`, you can build modular exponentiation in under 2KB.
- **The string→bytes barrier** is the hardest part. The translation-table trick (each input char maps to a piece of pre-baked pickle) is the killer idea.
- **Mutable state in subroutines** requires returning values (inner BINPUT doesn't escape). Packing state into tuples stored at fixed memo slots minimizes per-call cost.
- **Two's complement via lookup tables** is how you get negation when there's no subtract operator.
- **The `pack('>H', byte+byte)` trick** is gorgeous: top bit and shifted byte in one operation.
- **Always test remote, not just local.** MAX_CANON is a silent killer for hex-pasted payloads.

## Files

- `work/build_min13.py` — the final builder
- `work/out/payload_v13.bin` — 1779-byte pickle payload (the submission)
- `work/out/payload_v13.hex` — same payload as 3558 hex chars
- `work/helpers.py` — pickle constants and test harness
- `work/build_min2.py` — base subroutines (mod_c, neg_c) used unchanged across versions
