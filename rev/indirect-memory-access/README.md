# Indirect Memory Access

**Category:** Reversing | **Difficulty:** Hard | **Flag:** `bctf{aSbaabababaaabbasaaSbsaaaasLaRRbaaDaaaaDbRaabasaRaabsbSabas}`

## TL;DR

A Game Boy Advance ROM hides a 450-gate boolean circuit where each gate's type is determined by a DMA timing race between three GBA DMA channels. We empirically probed the seven truth tables using a patched ROM under mGBA, extracted the full circuit topology with Unicorn Engine, solved the 128-bit input constraint with Z3, and decoded the result from bit stream back to button presses.

## What We're Given

A single file: `chal.gba` (59,380 bytes). The challenge description is a pointed hint:

> "Did you know the GBA has 4 DMA channels?"

That's your entire prompt. No source. No hints about what it does. Just a GBA ROM and an implied warning that you're about to learn more about direct memory access than you ever wanted to know.

## Initial Recon

`file chal.gba` confirms it's a GBA ROM (Nintendo Game Boy Advance ROM image). Running it in an emulator (mGBA works great here) shows a text prompt: `Press Button:` and then it sits there waiting for input.

Pressing buttons one at a time causes characters to appear on screen — things like `a`, `b`, `S`, `L`, `R`, `U`, `D`, and so on. After enough presses the ROM either says "correct!" or... doesn't.

`strings chal.gba` gives some useful clues:

```
absSRLUDrl
your emulator sucks :(
Press Button:
flag is 'bctf{
```

That string `absSRLUDrl` is the key mapping — A, B, select, Start, Right, Left, Up, Down, R, L. Each button press contributes bits to a buffer. When the buffer has 128 bits, the validator runs. If it passes, the flag is printed.

"your emulator sucks :(" is not an insult directed at us personally (though it felt that way for a while). It's a sanity check embedded in the ROM that fires if the emulator doesn't model GBA hardware accurately enough. More on why that matters in a moment.

Looking at the ROM's memory layout with a disassembler: there's a block copied from ROM to IWRAM at startup. That block is the check function — it lives at 0x03000024 and gets called 450 times during validation.

## The Vulnerability / Trick

Here's the real meat of this challenge: the check function implements a **boolean logic gate using GBA DMA timing races**.

### GBA DMA Background

The GBA has four DMA channels (DMA0–DMA3), each capable of copying blocks of memory with different trigger conditions and priorities. DMA0 can be triggered on every horizontal blank (hblank — the brief pause between scanlines). DMA1 and DMA3 trigger immediately. When multiple DMAs fire at once on overlapping destination addresses, the result depends on hardware execution order, priority, and timing — things that vary between emulators.

### The Gate Mechanism

The check function at 0x03000024 does this (simplified):

1. Waits for a VCount IRQ to synchronize to a specific scanline
2. Runs a 172-iteration delay loop (~700 cycles) to align to just before an hblank
3. Enables DMA3 — copies 8 halfwords from a ROM address (DMA3SAD) to EWRAM at 0x02000000
4. Enables DMA0 — hblank-triggered, copies 2 halfwords from 0x02000002 (decrement) to 0x02000006 (increment)
5. Enables DMA1 — immediate, copies 2 halfwords from 0x02000004 (increment) to 0x02000006 (increment)
6. Reads back specific EWRAM halfwords to produce the output

The two inputs (call them A and B) are either `0x0000` (logical 0) or `0x8000` (logical 1). DMA0 fires only if A's bit 15 is set; DMA1 fires only if B's bit 15 is set.

The **DMA3SAD** — the source address that DMA3 reads its constants from — is what determines which gate is being computed. There are seven distinct ROM addresses, each pre-loaded with a different constant pattern. The three-way DMA race (DMA3 loads constants, DMA0 and DMA1 conditionally overwrite based on inputs) produces a different truth table for each source.

This is why "your emulator sucks :(" exists: if the emulator doesn't get GBA DMA priority and hblank timing exactly right, the gates compute wrong values and the whole circuit is garbage. The string is literally checking whether the emulator is accurate enough before the real work begins.

### The Seven Gates

We probed all seven truth tables empirically (more on how below). The results:

| DMA3SAD    | f(0,0) | f(0,1) | f(1,0) | f(1,1) | Gate      |
|------------|--------|--------|--------|--------|-----------|
| 0x08008b7c | 1      | 1      | 0      | 1      | A implies B (IMP_ab) |
| 0x08008b7e | 0      | 1      | 1      | 1      | OR        |
| 0x08008b84 | 1      | 1      | 1      | 0      | NAND      |
| 0x08008b86 | 0      | 0      | 0      | 1      | AND       |
| 0x08008b88 | 0      | 1      | 1      | 0      | XOR       |
| 0x08008b8e | 1      | 0      | 0      | 0      | NOR       |
| 0x08008b94 | 1      | 0      | 1      | 1      | B implies A (IMP_ba) |

The circuit uses 450 of these gate calls total, distributed as: AND (158), NAND (100), IMP_ba (43), NOR (42), IMP_ab (40), XOR (34), OR (33).

## Building the Exploit

The solve has four phases:

### Phase 1: Probe the Truth Tables

We can't analyze the DMA timing analytically — the interactions between DMA queuing, hblank timing, and priority are gnarly enough that even attempting a cycle-accurate model just gave wrong answers. Instead, we wrote a 324-byte Thumb patch that:

1. Runs the same DMA setup as `sub_280`
2. Loops through all 28 combinations (7 source addresses × 4 input combinations)
3. Calls the original check function for each
4. Stores results at EWRAM address 0x02001000

We patched main's entry point to jump to this code, burned it into `chal_patched.gba`, ran it in mGBA with the GDB stub enabled (under Xvfb for a headless display), and read the result block via GDB's memory commands. Clean, repeatable truth tables every time.

One failed approach first: we tried directly injecting register values and calling the check function via the GDB stub, overwriting PC/registers during a halt. mGBA kept desyncing — the GDB stub and the emulator's halt state don't play nice together when you start poking at PC. The ROM-patch approach was more reliable.

### Phase 2: Extract the Circuit with Unicorn Engine

Unicorn Engine is an embeddable CPU emulator — think of it as running a slice of the binary in a sandboxed CPU without a full emulator around it. We use it here to trace `sub_310` without needing to run the actual GBA hardware.

The key insight is that `sub_310` has **no input-dependent branches** — the call graph is completely static. Whether the button bits are 0 or 1 doesn't change which gates get called or in what order. Only the gate outputs change. This means we can run the function with dummy token inputs and just record the structure.

The trick: pre-load the 128-slot input buffer with unique IDs (`0x2000` through `0x207f`). Then hook the check function at 0x03000024 — instead of letting it run the DMA race, we intercept it, record `(input_A_id, input_B_id, DMA3SAD)`, and return a fresh unique ID (`0x4000`, `0x4001`, ...) as the fake output. This builds a complete dataflow graph of all 450 gate calls.

```python
def hook_code(uc, addr, size, user):
    if addr == 0x03000024:
        r0 = uc.reg_read(UC_ARM_REG_R0) & 0xffff  # input A
        r1 = uc.reg_read(UC_ARM_REG_R1) & 0xffff  # input B
        lr = uc.reg_read(UC_ARM_REG_LR)
        idx = len(calls)
        out_id = CALL_BASE + idx  # assign fresh token to this call's output
        calls.append({'idx': idx, 'r0_in': r0, 'r1_in': r1, 'sad': current_sad[0], 'out_id': out_id})
        uc.reg_write(UC_ARM_REG_R0, out_id)
        uc.reg_write(UC_ARM_REG_PC, lr | 1)  # return immediately
```

We also hook writes to the DMA3SAD register (0x040000d4) to track which gate is active for each call.

### Phase 3: Solve with Z3

Z3 is a satisfiability solver — you give it boolean variables and constraints, it figures out if there's an assignment that satisfies all of them, and if so, tells you what it is.

We create 128 Z3 boolean variables (one per input bit), then walk the circuit topology from Phase 2, building up Z3 expressions for each gate's output:

```python
def gate(name, a, b):
    return {
        'AND':    lambda: And(a, b),
        'OR':     lambda: Or(a, b),
        'NAND':   lambda: Not(And(a, b)),
        'NOR':    lambda: Not(Or(a, b)),
        'XOR':    lambda: Xor(a, b),
        'IMP_ab': lambda: Or(Not(a), b),   # A → B means "not A, or B"
        'IMP_ba': lambda: Or(Not(b), a),   # B → A means "not B, or A"
    }[name]()
```

The final constraint: the last gate's output must be `True` (that's what makes `sub_310` return 1 and print the flag). Z3 solves this in under a second and — critically — the solution is **unique**. There's exactly one 128-bit input that satisfies the circuit.

The solution bits:
```
10001011101101101111010110011100010100111110010000011000010000101110000000111110000000101000011101100110000111010010100011011001
```

### Phase 4: Decode Bits to Button Presses

This is the most satisfying part to figure out. The ROM processes button presses as follows: each button has a fixed bit position in the GBA's KEYINPUT register. When you press a button, the ROM stores *each bit from position 0 up through and including that button's bit position* into the buffer, LSB first. So:

- Button `a` (bit 0) contributes just `[1]` — one bit, value 1
- Button `b` (bit 1) contributes `[0, 1]` — two bits
- Button `S` (bit 2) contributes `[0, 0, 1]` — three bits
- And so on up to `l` (bit 9) contributing `[0, 0, 0, 0, 0, 0, 0, 0, 0, 1]`

The MSB of each press is always 1. Everything before it in the press's contribution is 0.

So decoding is simple: scan for the next `1` bit. The distance from the start of the current press tells you which button was pressed. Emit that button's character and advance past the `1`.

```python
def decode_bits(bits):
    buttons = "absSRLUDrl"
    result = ""
    i = 0
    while i < len(bits):
        j = i
        while j < len(bits) and bits[j] == 0:
            j += 1
        if j >= len(bits):
            break
        pos = j - i          # distance = button bit position
        result += buttons[pos]
        i = j + 1            # skip past the terminating 1
    return result
```

Running this on the 128-bit solution gives us 59 button presses using exactly all 128 bits.

## Running It

```
$ python3 solve.py
Extracting circuit...
Got 450 check calls
Solving with Z3...
Bits: 10001011101101101111010110011100010100111110010000011000010000101110000000111110000000101000011101100110000111010010100011011001
Flag: bctf{aSbaabababaaabbasaaSbsaaaasLaRRbaaDaaaaDbRaabasaRaabsbSabas}
```

The full script runs in a few seconds on any modern machine. The Z3 solve is the fastest part — the Unicorn trace takes a moment to set up but the circuit has no branching, so it flies through.

## Key Takeaways

**The core trick:** GBA DMA channels can be used to implement boolean logic by timing multiple DMA transfers to race on the same memory addresses. Different ROM source patterns plus conditional DMA enables based on input values produce different truth tables. This is an extremely hardware-specific trick that would only work (or make sense) on actual GBA hardware or a cycle-accurate emulator.

**What "your emulator sucks" actually means:** It's not flavor text. The ROM verifies that the emulator handles DMA priority and hblank timing correctly before proceeding. On any emulator that gets DMA wrong, the gates misbehave and the validation logic is incoherent. This is simultaneously a clever anti-debugging measure and a very targeted troll.

**The empirical probing trick:** When you can't reason about timing analytically, patch the ROM to run your test cases and read results out of memory. This is a general technique — if something is hard to model, let the hardware (or emulator) do the work and just observe the outputs.

**Unicorn for circuit extraction:** When a validator has no data-dependent branches, you can use Unicorn with token/stub inputs to extract the full dataflow graph without needing to understand the hardware effects. The trick of assigning unique IDs to inputs and intercepting function calls to return fresh unique IDs is a clean way to build a symbolic circuit trace.

**Z3 for boolean circuits:** Once you have a set of boolean constraints (even hundreds of them), Z3 eats them for breakfast. If you ever see a validation function that's pure combinational logic — no loops depending on the answer, no timing, just gates — Z3 is the move.

**The prefix code encoding:** The button-to-bits encoding is a variable-length prefix code where each button's bit length equals its KEYINPUT bit position + 1. The terminating `1` bit makes it self-delimiting and unambiguous. Recognizing this pattern was the last unlock before decoding the flag.

For more on GBA DMA: the GBATek reference (https://problemkaputt.de/gbatek.htm#gbadmacontrol) covers DMA control registers, priority, and timing in exhaustive detail. Understanding which DMA fires first when multiple are pending is exactly what makes this challenge work the way it does.
