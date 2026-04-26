#!/usr/bin/env python3
"""
BF generator for pow(a,b,c).

Strategy: represent all numbers as "unary count" stored as the total sum of digits.
No, that's weird.

Let me use a clean 2-cell base-100 representation. Values 10-999:
  high cell: value / 100  (0..9)
  low cell:  value % 100  (0..99)
  tens_cell: (value / 10) % 10 (0..9)
  Actually, this is just 3-digit decimal.

Cleanest algorithm (avoiding carry propagation entirely):

Represent each value as ONE cell containing the "unary encoded" value, but we need values up to 999 > 255. So we can use 2 cells:
  a = 256 * A_hi + A_lo
And store values such that A_lo only holds 0..99 and A_hi only holds 0..9, so we use them like "hundred" and "rest_of_two_digits". Values in these cells don't wrap.

Arithmetic primitives:
  ADD a+b:      a_lo += b_lo; if a_lo >= 100: a_lo -= 100; a_hi += 1; a_hi += b_hi
  SUB a-b (assuming a>=b): a_lo -= b_lo; if borrow: a_lo += 100; a_hi -= 1; a_hi -= b_hi
  COMPARE >= : compare hi first; if equal compare lo.

Problem: "if a_lo >= 100" requires detecting this. We can detect it by subtracting 100 and checking the borrow: if a_lo was >= 100, a_lo - 100 is in [0..?], positive; else a_lo - 100 wraps to large number.
Detecting wrap (8-bit): hard without divmod or compare.

=====

ALTERNATIVE FINAL IDEA: use "3-digit decimal, each digit in its own cell, but allow digits to grow beyond 9 during mul; normalize only before compare and output."

This avoids complex inter-digit borrow chains. After a mul we normalize.

But we still need compare (for mod), which requires normalized form.

=====

Best clean idea: store all 16-bit values as a 2-cell (lo, hi) base-256 representation with 8-bit cells. Implement primitives:
  add16, sub16, dec16, compare16, read_decimal_to_16, print_16_as_decimal.

Algorithm:
  r = 1
  for _ in range(b):
    # r = (r*a) mod c
    new = 0
    acnt = a (copy)
    while acnt > 0:
      new = new + r (16-bit)
      if new >= c: new = new - c  (at most once since new < 2*c < 2000)
      acnt -= 1 (16-bit decrement)
    r = new
  print r

I'll just buckle down and implement 16-bit primitives. The key insight is the 16-bit inc-with-carry and its partner dec-with-borrow.

== 16-bit INC (cell lo at P, hi at P+1; scratch s at P+2 must be 0) ==
  >+           hi preemptively += 1
  <+           lo += 1
  [>-]>[<+>    if lo becomes 0: we keep the hi++. else: undo.
  Hmm let me think more carefully.

Standard 16-bit increment pattern:
  Pointer at lo.
  lo++
  if lo == 0 after increment: hi++

"if lo == 0" test (non-destructive): use 2 scratch cells T, F.
  T,F init 0
  [->+>+<<]   — destroy lo into T and F
  >[-<+>]     — move T back to lo
  <            — now at F, F==0 iff lo was 0

But we want "if lo is 0" (after inc) — essentially if lo was 255 before inc.

Cristofani's well-known 16-bit inc (assumes tape: lo, hi, 0, 0, 0 with pointer at lo):

  +[>+[-]<]<   -- no, something like that.

I'll implement my own cleanly:
  # preserve lo's zero-ness: scratch s=1 initially
  # tape: lo, hi, s=1, t=0, pointer at lo
  +          # lo++
  [-         # if lo != 0: decrement lo by 1 and set s=0
    >>>[-]    # clear t (unused)
    <<-       # s -= 1 (now s==0)
    >>+<<     # put lo back... messy
    hmm
  ]+         # make lo=1 again? No.

This is getting tangled. Let me just use "subtract-to-zero" techniques that are known.

Known working 16-bit INC snippet (pointer at lo, expects lo,hi,0,0):
  +[>+[-]<]

Wait that's just "set hi=1 if lo!=0 after increment".
  +          lo++ (now lo is 1..255 for non-wrap, 0 for wrap)
  [>+[-]<]   if lo != 0: (hi += 1, clear lo? no, "[-]" inside is on the current cell which is hi)
    Let me trace: after '+', pointer at lo.
    '[' lo nonzero?
      '>' move to hi
      '+' hi += 1
      '[-]' clear hi (!)
      '<' back to lo
    ']' back to top

That's obviously wrong. Let me think differently.

The most robust 16-bit INC I know:
  Tape: [lo, hi, tmp0, tmp1]  with tmp0=tmp1=0

  +               lo++
  [               if lo != 0 (no wrap):
    >>>+<<<       set tmp1 = 1 (marker: "no carry needed")
    [-]           clear lo? No!
  ]

This also destroys lo.

OK let me use the safe pattern: save lo to tmp before incrementing, then check if tmp was 255.

  Tape: [lo, hi, t0, t1]
  pointer at lo.
  [->+>+<<]     lo=0, t0=lo, t1=lo (copy)
  >[-<+>]       restore lo from t0
  >[-]          clear t1 (we're done with "is lo original zero" test)
  <<+           lo += 1

But we need to know if lo was 255 (wrap), not 0.

  Better: check if lo is 255 before incrementing. "255" means "after adding 1 equals 0".
  Test: copy lo, add 1 to copy, check if copy==0.

  [->+>+<<]     lo=0, t0=lo_copy1, t1=lo_copy2
  >[-<+>]       restore lo from t0  (lo restored, t0=0)
  >+            t1 += 1 (t1 now == lo+1)
  [<<+>>[-]]    if t1 != 0: lo += 1; clear t1
                if t1 == 0 (meaning lo was 255): skip, so lo stays 255... then we wrap by decrementing? Hmm.
                Actually we want lo to wrap to 0 AND hi to increment.

Let me try different: unconditionally increment lo, then detect wrap by observing lo is 0:
  +             lo++
  [             if lo != 0 (normal, no wrap):
    (nothing, stay and exit loop)
    ... but [..] would loop, we need to exit.

BF "if nonzero" pattern:
  Use t0 as flag: flag=1; x[flag-x[-]]; x no longer works if we want to preserve x.

Actually the standard "if-nonzero preserve x":
  Tape: [x, flag=1, t]  pointer at x.
  [>-<    flag-- (flag=0 iff x was nonzero)
    >>+<<  t++ (save "x was nonzero" fact? But we need more than that)
    [-]    clear x
  ]
  >[-<+>]<  restore x from t (t was t, uh)

Hmm this is really tangled. Let me just USE A KNOWN GOOD SNIPPET FROM A LIBRARY.

From https://esolangs.org/wiki/Brainfuck_algorithms:
  "if (x) { code1 } else { code2 }"
    temp0[-]
    temp1[-]
    x[temp0+temp1+x-]temp1[x+temp1-]
    temp0[code1 temp0-]
    temp1[code2 temp1-]

Err, that's if-else; makes x back into temp0 style.

OK I'll use a different approach entirely: reject 16-bit and use a **1.5-byte trick**: since values fit in 10 bits, use 1 cell for the "hundreds" digit (0-9) and 1 cell for the rest (0-99). Carry is easier.

Representation: value = 100*H + L where H∈[0..9], L∈[0..99].
16-bit add: L_dst += L_src; if L_dst >= 100: L_dst -= 100; H_dst += 1. H_dst += H_src.
Still need "if L >= 100" test.

=====

NEW CLEAN APPROACH: store each value as a "unary count of hundreds" + "unary count of tens" + "unary count of ones" (not decimal digits in 0-9, but as a counter that lets us easily loop).

Actually that IS just the 3-cell decimal representation.

Let me use 3-cell decimal and handle carry cleanly:

For a+b (both 3-digit, result 4-digit):
  N0 N1 N2 N3 all start 0 (our destination)
  N3 += a[2]; N3 += b[2]   — N3 might be up to 18
  N2 += a[1]; N2 += b[1]
  N1 += a[0]; N1 += b[0]
  Now normalize: repeat {
    while N3 >= 10: N3 -= 10; N2 += 1
    while N2 >= 10: N2 -= 10; N1 += 1
    while N1 >= 10: N1 -= 10; N0 += 1
  }

We need "while Ni >= 10". Trick: subtract 10; if result is 0..245, it was >=10 originally; if 246..255, it wrapped (was < 10, restore).

But detecting "is value 246..255" is hard in BF without comparison.

=====

SIMPLEST: use "Ni - 10 if it's at least 10" via copy+subtract+compare idiom.

The easiest working approach in BF for "if Ni >= 10 then Ni -= 10; Nj += 1":

  Subtract 10 ten-and-check via counters.

  Approach using an auxiliary loop:
    T = Ni
    Ni = 0
    count_tens = 0
    while T > 0:
      T -= 1
      Ni += 1
      if Ni == 10: Ni = 0; count_tens += 1
    add count_tens to Nj; Ni holds the remainder.

  "If Ni == 10" test: after incrementing Ni to possibly 10, copy to temp, subtract 10, ... still needs comparison.

  Actually: every 10 iterations, reset Ni. We can do this by counting an extra "tens counter":
    state: Ni=0, tens=0, T=value
    loop T times:
      Ni += 1
      tens += 1  (will be reset)
      if tens == 10: ... — same problem.

Easier: unroll! Use a "decimal counter" with modular increment:
  For each unit in T:
    ones++; if ones reaches 10: ones=0, tens++; if tens reaches 10: tens=0, hundreds++...

"if ones reaches 10" — this is fundamentally hard without arithmetic comparison.

Actually, there's a classic BF idiom that handles exactly this. Let me look it up properly.

From the "to divmod by 10" idiom:
  n [>+>-[>+>>]>[+[-<+>]>+>>]<<<<<<]

This takes a cell with value n, uses a specific offset layout, and produces (q, r) where q=n/10, r=n%10.

Tape layout: starting at n, needs [n, 0, 0, 0, 0, ...]
After the snippet, something like [0, 0, 0, 0, 0, q, r]? I forget exactly.

Let me just TEST this snippet directly.
"""

# I'm going to stop designing on paper and just test the divmod-10 idiom in BF.
print("skipping gen")
