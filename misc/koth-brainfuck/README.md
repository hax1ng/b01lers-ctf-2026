# Brainfuck

**Category:** Misc (King of the Hill) | **Difficulty:** Medium-Hard | **Flag:** N/A — KoTH scoring

> This is a King-of-the-Hill challenge. There's no `bctf{...}` flag to submit. Instead, your score is determined by how small your Brainfuck program is while still passing all test cases. Shorter is better. The leaderboard is your scoreboard.

## TL;DR

Write a Brainfuck program that computes `pow(a, b, c)` (modular exponentiation) for inputs in the range a∈[10,999], b∈[50,100], c∈[100,999]. The catch: your program is scored by its byte count — smallest wins. We ended up at **6014 bytes** by using the BF-it compiler, a base-100 number representation, and a brutal variable-ordering search that saved hundreds of bytes for free.

## What We're Given

The handout is a Docker container and a Python test runner (`runner.py`). The runner:

1. Generates 50 random test cases where `a`, `b`, `c` are picked from their respective ranges
2. Feeds the input as `"{a}\n{b}\n{c}\n"` to your Brainfuck program via stdin using `bfci` (a Brainfuck interpreter)
3. Expects the decimal representation of `pow(a, b, c)` on stdout, no leading zeros
4. Times out any single test after 10 seconds
5. Reports how many of the 50 cases you passed

The BF interpreter is [bfci](https://github.com/primo-ppcg/bfci), which is fast and uses 8-bit wrapping cells. That last detail matters a lot — each cell holds a value from 0 to 255, wrapping around on overflow/underflow. Our numbers go up to 999, so they do not fit in one cell.

## Initial Recon

Before touching Brainfuck, let's think about what we're actually computing.

`pow(a, b, c)` means `a^b mod c`. With `b` up to 100 and `a` up to 999, this is textbook modular exponentiation. Python does it in one line. Brainfuck... does not.

The fundamental challenge is that Brainfuck has exactly eight instructions (`+`, `-`, `<`, `>`, `[`, `]`, `.`, `,`) and a tape of byte-sized cells. Writing readable, correct arithmetic for 3-digit numbers in raw Brainfuck is possible, but writing *short* BF for it by hand is basically impossible for anything this complex. Experienced BF golfers still use helpers.

A quick look at the input format tells us we need:
- Parse two or three ASCII digits for `a` (range 10–999 means sometimes 2 digits, sometimes 3)
- Parse two or three ASCII digits for `b` (range 50–100 means the special case `100` has 3 digits but `50`–`99` have 2)
- Parse exactly three ASCII digits for `c` (range 100–999, always 3 digits)
- Run modular exponentiation
- Print the result without leading zeros

That's a fair bit of logic. Let's think about how to handle numbers bigger than 255.

## The Core Trick: BF-it + Base-100 Arithmetic

### BF-it: a compiler so we don't go insane

Writing raw Brainfuck for anything complex is painful. The trick is to use [BF-it](https://github.com/bf-it/bf-it) — a compiler that takes a C-like language and produces Brainfuck. The source language looks like a stripped-down C: you get `int` variables, `while` loops, `if`/`else`, `readchar()`, `printchar()`, and basic arithmetic. The compiler figures out the tape layout and emits the BF instructions.

This is not cheating — the output is still Brainfuck that has to be small. We're just writing the *logic* in a readable language and then golfing the output.

### Base-100: fitting big numbers in small cells

BF cells are 8-bit, so they hold 0–255. Our numbers go up to 999. The naive fix is three cells per number (one per decimal digit), but BF-it's cost model makes that expensive to work with — every arithmetic operation on a 3-cell array becomes a lot of pointer movement.

Instead, we use **base-100 representation**: two cells per number, where `value = hi * 100 + lo` with `hi ∈ [0..9]` and `lo ∈ [0..99]`. This works because:
- Maximum value is `9 * 100 + 99 = 999` — exactly our range
- Both cells stay safely within 0–255, so no wrap-around surprises
- Addition with carry is simple: add the `lo` parts; if the result is ≥ 100, subtract 100 and carry 1 into `hi`
- Comparison is easy: compare `hi` first, break ties with `lo`

We could also do base-10 (one digit per cell, three cells), but base-100 wins because the inner loop runs `a` iterations, and with base-100 you loop up to 999 times total (one per unit of `a`), while base-10 would require the same loop structure anyway but with more cells to manage per step. Fewer cells means less pointer movement in the generated BF, which is what we're optimizing.

### The algorithm: modular exponentiation by repeated addition

Standard fast modular exponentiation uses square-and-multiply, which needs bit manipulation — painful in BF. With `b ≤ 100`, the simpler approach works fine:

```
r = 1
for i in range(b):
    r = (r * a) mod c
```

And `r * a mod c` is computed by repeated addition:

```
accumulator = 0
counter = a   (a copy, which we decrement to zero)
while counter > 0:
    counter -= 1
    accumulator += r
    if accumulator >= c:
        accumulator -= c
```

Since `accumulator < c` before each addition and `r < c`, the sum is `< 2c`, so we only ever need to subtract `c` once. No loops needed for the modulo step — just a single conditional subtraction.

This inner loop runs up to 999 iterations per multiplication, and we do up to 100 multiplications, so worst case is ~99,900 iterations of the inner loop. With bfci's speed, this is well within the 10-second timeout.

## Building the Solution

### Version 1: three-digit decimal, 22441 bytes

The first version (pow10) used three cells per number (one per decimal digit) and `printint` for output. It passed all tests but weighed in at 22,441 bytes. That's our baseline.

### The big jump: switching to base-100

Moving to a two-cell base-100 representation (pow88) dropped the output dramatically. Fewer variables + simpler carry logic = fewer BF instructions to move the pointer around. This gave us **5,821 bytes** — a 74% reduction from baseline. Not bad, but we can go further.

### Optimization 1: kill `printint`

BF-it's built-in `printint` is a general-purpose decimal printer. It handles any value, including multi-digit numbers, by doing repeated division. In BF, that's expensive. But we know our output structure exactly:

- `r_hi` is the "hundreds" digit (0–9), but our result `r = r_hi * 100 + r_lo`
- The actual decimal representation is: hundreds digit = `r_hi`, tens digit = `r_lo / 10`, units digit = `r_lo % 10`

So instead of calling `printint(r_hi * 100 + r_lo)`, we do:

```c
nh = r_lo / 10;
nl = r_lo - nh * 10;
if (r_hi) {
    printchar(r_hi + 48);
    printchar(nh + 48);
} else if (nh) {
    printchar(nh + 48);
}
printchar(nl + 48);
```

`printchar(x + 48)` converts a digit 0–9 to its ASCII character ('0' = 48) and outputs it. Much cheaper than `printint`. BF-it compiles `printchar` to a handful of BF instructions; `printint` compiles to hundreds.

The `r_lo % 10` and `r_lo / 10` expressions also compile smaller than manual `r_lo - t * 10` thanks to how BF-it handles the modulo idiom internally.

### Optimization 2: smarter input parsing

Reading ASCII digits from stdin in Brainfuck boils down to: read a character, subtract 48 to get the digit value. For multi-digit numbers you multiply by 10 as you go. A naive two-digit read is:

```c
digit1 = readchar() - 48;
digit2 = readchar() - 48;
value = digit1 * 10 + digit2;
```

We can collapse this to one expression, saving a variable allocation:

```c
a_lo = readchar() * 10 + readchar() - 528;
```

Why 528? Because `(d1 * 10 + d2) - 528` equals `(d1 - 48) * 10 + (d2 - 48)` when you expand it: `d1*10 + d2 - 48*10 - 48 = d1*10 + d2 - 528`. Same result, one fewer intermediate variable, and BF-it generates smaller code for a single compound expression than two separate ones.

### Optimization 3: handling the `b = 100` edge case cheaply

`b` is in [50, 100]. That's either a 2-digit number (50–99) or the single 3-digit value 100. How do we tell them apart without reading ahead?

We read two digits and compute `b = readchar() * 10 + readchar() - 528`. For the range 50–99, this gives values 50–99. For "1" and "0" (the first two chars of "100"), it gives `'1'*10 + '0' - 528 = 490 + 48 - 528 = 10`. 

So if `b < 48`, we know it was actually the string "100" and need to read one more character. We set `b = 100` and consume the extra '0':

```c
b = readchar() * 10 + readchar() - 528;
if (b < 48) { b = 100; readchar(); }
```

The threshold 48 works because the smallest valid 2-digit `b` value is 50, and the "100" parse gives 10. There's a clean gap between them — no ambiguity.

Similarly for `a`: we read two chars, then peek at the third. If it's `'\n'` (ASCII 10), `a` was 2 digits and we're done. If it's anything else, `a` is 3 digits.

```c
a_lo = readchar() * 10 + readchar() - 528;
e = readchar();
if (e != 10) { a_hi = a_lo / 10; a_lo = (a_lo % 10) * 10 + e - 48; readchar(); }
```

When `e != 10`, the two chars we already read are the hundreds and tens digits of `a`, and `e` is the ones digit. So `a_hi = a_lo / 10` gets the hundreds digit, and `(a_lo % 10) * 10 + e - 48` builds the new `a_lo` from the tens and ones digits.

### Optimization 4: the variable ordering search

This is the weird one, and the one that nobody expects to matter.

BF-it assigns each variable a fixed cell on the tape in the order they're declared. The BF pointer starts at cell 0 and moves around as operations need different variables. Moving the pointer from cell 5 to cell 12 costs 7 `>` characters. Moving from cell 5 to cell 6 costs 1. So variables that are used *together* in the inner loop should be *adjacent* on the tape.

Our hot variables — the ones touched in every inner loop iteration — are `c_lo`, `c_hi`, `ak_hi`, `r_hi`, `r_lo`, `ak_lo`, `nl`, `nh`. There are 8! = 40,320 ways to order them. We wrote a script that ran all 40,320 permutations through BF-it and measured the output size.

The best ordering (`c_lo, c_hi, ak_hi, r_hi, r_lo, ak_lo, nl, nh`) produced the final `solution.bf` at **6,014 bytes**. The worst orderings were hundreds of bytes larger — same algorithm, same logic, just different variable declaration order in the source. This was genuinely surprising: you can save significant bytes without changing a single line of *logic*, just by reordering your variable declarations.

### Optimization 5: remove unused variables

BF-it allocates a tape cell for every declared variable, even if you never use it. Each extra cell shifts all the other cells, increasing average pointer travel distances across the whole program.

We had a leftover variable `d` from earlier prototyping. Removing it saved 54 bytes. Always clean up dead variables.

### Optimization 6: post-compile minification

After BF-it compiles the `.code` file to BF, we apply a simple string-level minification pass: strip non-BF characters (comments, whitespace), then repeatedly collapse cancel-pairs (`+-`, `-+`, `<>`, `><`) until no more simplifications are possible. This handles cases where BF-it generates something like `>><<` (net zero movement) or `++-` (net one increment).

## The Final Solution

Here's the complete BF-it source (`solution.code`):

```c
int main() {
    int a_hi; int a_lo; int e; int b;
    int c_lo; int c_hi; int ak_hi; int r_hi; int r_lo; int ak_lo; int nl; int nh;

    a_lo = readchar() * 10 + readchar() - 528;
    e = readchar();
    if (e != 10) { a_hi = a_lo / 10; a_lo = (a_lo % 10) * 10 + e - 48; readchar(); }

    b = readchar() * 10 + readchar() - 528;
    if (b < 48) { b = 100; readchar(); }
    readchar();

    c_hi = readchar() - 48;
    c_lo = (readchar() - 48) * 10 + readchar() - 48;

    r_lo = 1;

    while (b) {
        b--;
        nh = 0; nl = 0;
        ak_hi = a_hi; ak_lo = a_lo;

        while (ak_hi + ak_lo) {
            if (ak_lo) ak_lo--;
            else { ak_lo = 99; ak_hi--; }

            nl = nl + r_lo;
            nh = nh + r_hi;
            if (nl >= 100) { nl -= 100; nh++; }

            if ((nh > c_hi) || (nh == c_hi && nl >= c_lo)) {
                nl = nl + 100 - c_lo;
                nh--;
                if (nl >= 100) { nl -= 100; nh++; }
                nh -= c_hi;
            }
        }
        r_hi = nh; r_lo = nl;
    }

    nh = r_lo / 10;
    nl = r_lo - nh * 10;
    if (r_hi) {
        printchar(r_hi + 48);
        printchar(nh + 48);
    } else if (nh) {
        printchar(nh + 48);
    }
    printchar(nl + 48);
}
```

The variable declarations on line 2–3 are in the optimized order found by the permutation search. The hot 8 variables are declared last (line 3), in the exact order that minimizes tape pointer travel.

## Running It

```
$ python runner.py solution.bf
50/50 passed
```

At **6,014 bytes**, this passes every test case comfortably within the timeout.

For comparison, here's the optimization journey:

| Version | Description | Size |
|---------|-------------|------|
| pow10 | First working version, 3-cell decimal, `printint` | 22,441 bytes |
| pow.bf | Initial 2-cell base-100 attempt | 37,716 bytes |
| pow88 | Base-100 + `printchar` output + smart parsing | 5,821 bytes |
| pow91 | Suboptimal variable ordering | 6,305 bytes |
| solution.bf | Optimal variable ordering + minification | 6,014 bytes |

(pow88 is smaller than pow91 because pow88 had a slightly different variable order discovered by hand before the full permutation search was run. The full search in the solution.code order yields the 6,014 byte final output after minification.)

## Key Takeaways

**The technique:** BF-it (or any BF compiler) plus systematic micro-optimization beats hand-coded BF for problems of this complexity. Write the algorithm correctly first, then squeeze the output.

**Base-100 beats base-10 here** because you need fewer cells per number, and fewer cells means less average pointer travel in the BF output. Pick your representation with the cost model of BF in mind, not just mathematical convenience.

**Variable declaration order is a real optimization.** In any BF compiler that does a linear tape allocation, the order you declare variables controls which cells they get. Variables used together in hot loops should be adjacent. If you have a small set of hot variables, it's worth running a search over all their permutations — 8! = 40,320 is cheap enough to brute-force in a few minutes.

**Compound expressions reduce variable pressure.** `a_lo = readchar() * 10 + readchar() - 528` is not just clever — it literally saves a tape cell compared to splitting it into two assignments. In BF-it, fewer variables means a shorter tape and less pointer movement everywhere.

**The `printint` anti-pattern.** BF-it's `printint` is convenient but large. If you know the structure of what you're printing (e.g., at most a 3-digit number with known digit bounds), replace it with explicit `printchar` calls. The savings are dramatic.

**Dead ends worth mentioning:** We initially tried a 3-cell decimal representation because it felt more natural (one digit per cell). It worked, but the BF output was enormous — three variables per logical number means three times the pointer movement overhead. Switching to 2-cell base-100 was the single biggest win.

We also briefly considered binary search tricks to handle the `b = 100` edge case, before noticing the cute gap in the parsed values (10 vs 50+) that makes the `b < 48` check work cleanly.

If you want to go deeper on Brainfuck golf, the [esolangs wiki BF algorithms page](https://esolangs.org/wiki/Brainfuck_algorithms) has canonical snippets for common operations. And if you're serious about competing on a BF KoTH, consider writing your own BF compiler — the more the compiler knows about your specific usage patterns, the better it can optimize.
