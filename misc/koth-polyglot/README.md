# polyglot

**Category:** misc (king of the hill) | **Difficulty:** medium | **Score:** 4 languages

## TL;DR

KoTH challenge: write a **single source file** that runs correctly in as many of 19 languages as possible, computing `a^b mod c` from three lines of stdin. We got to **4 languages — bash + perl + julia + C** — all passing 50/50 tests. The scoring is per-submission: each submission picks a set of language checkboxes, and your score equals the number of checked languages your file passes in.

## What We're Given

A sample `handout/` with:
- `runner.py` — runs `code` against 50 random test cases in each language you list
- `languages.toml` — per-language compile/run commands (tcc for C, erlc for erlang, bun for TS, etc.)
- `Dockerfile` — the exact environment (Alpine + 19 language toolchains)
- 19 target languages: `bash, zig, C, elixir, erlang, fish, golfscript, haskell, J, java, julia, lua, odin, perl, python0, scheme, rust, typescript, whitespace`

Input: three lines (a, b, c). Output: `pow(a, b, c)` where `a < 2^16, b < 2^8, c < 2^12`.

## The Scoring Trap

The first thing that bit us: we assumed scoring was **shortest byte count wins**, and went off to golf GolfScript to 7 bytes (which we did — `~\@\?\%`). That IS one way to score, but the bigger play is the **multi-language submission**: when you submit, you check N language boxes, and if the same file passes all N, you get N points.

So to score 4, you don't need four separate submissions — you need **one file** that passes in bash AND perl AND julia AND C, all at the same time. That's a polyglot.

## The Core Challenge: Mutually Hostile Syntax

Every language has its own idea of what's a comment, what's a statement, what starts a block. A polyglot survives by finding **overlaps** — tokens that are "ignore me" in some langs and "execute me" in exactly one.

Key comment tokens across our target langs:

| Language | Line comment | Block comment |
|---|---|---|
| bash | `#` | — |
| perl | `#` | `=pod ... =cut` |
| julia | `#` | `#= ... =#` |
| lua | `--` | `--[[ ... ]]` |
| C | `//` | `/* ... */` + `#if 0 ... #endif` |
| rust | `//` | `/* ... */` |
| typescript | `//` | `/* ... */` |
| haskell | `--` | `{- ... -}` |
| scheme | `;` | `#\| ... \|#` |

The magic token that unlocks our 4-lang polyglot: **`#if 0 ... #endif`**. It's:
- A `#` line comment in bash/perl/julia (all three treat `#` as "ignore rest of line")
- A C preprocessor directive that tells C to skip the block entirely

That gets us the separation: bash/perl/julia run the "top half," C runs the "bottom half," and they ignore each other's code.

## Building the 2-Lang: bash + C

This worked on the first try. The trick: `#if 0` is a `#` comment in bash, and `#endif` too. Between them, bash sees ordinary commands; C's preprocessor strips the whole block before compilation.

```
#if 0
read a;read b;read c;echo "$a^$b%$c"|bc;exit
#endif
#include<stdio.h>
int main(){long a,b,c,r=1;scanf("%ld %ld %ld",&a,&b,&c);a%=c;while(b){if(b&1)r=r*a%c;a=a*a%c;b/=2;}printf("%ld\n",r);return 0;}
```

Passed 50/50 in both bash and C locally. Submitted and...

### First Remote Failure: `bc` doesn't exist

Local Alpine ships with `bc`. The challenge Docker image doesn't. Our bash solution `echo "$a^$b%$c"|bc` got empty output on remote.

**Fix:** do the modular exponentiation in pure bash. The numbers involved are small enough that 64-bit arithmetic is fine *if* we reduce modulo c first:

```bash
read a;read b;read c
r=1
a=$((a%c))
while((b));do
  ((b&1)) && r=$((r*a%c))
  a=$((a*a%c))
  b=$((b>>1))
done
echo $r
```

With `a < 4096` after the first `%c`, `a*a < 16M` — fits in 64-bit long easily. No external tools needed.

### Similar trap with perl

Tried `print<>**<>%<>` — 14 bytes. Gorgeous. Returns `NaN` because `**` in Perl returns a float that overflows for `65535^255`. Fix: `use bigint` and force numeric context:

```perl
use bigint;print((0+<>)**(0+<>)%(0+<>))
```

(The `0+<>` coerces the string from stdin into a BigInt. Without it, bigint stringifies and the exponentiation dies.)

## Growing to 3 Langs: + perl

Perl treats `#` as a line comment, so all the `#if 0` / `#endif` / `#include` lines are automatic comments. The bash code on line 2 — `read a;read b;read c;...` — is NOT a comment though, and Perl errors on it (`read` wants different args in Perl).

**Solution:** wrap the bash line in Perl's POD (plain old documentation) block. `=pod` at column 1 starts a POD block that Perl ignores until `=cut`:

```
#if 0
=pod
read a;read b;read c;r=1;a=$((a%c));...;echo $r;exit
=cut
use bigint;print((0+<>)**(0+<>)%(0+<>));__END__
#endif
```

Now Perl:
- `#if 0` — comment
- `=pod` — start ignoring
- bash line — ignored
- `=cut` — resume parsing
- `use bigint;print...;__END__` — runs, then `__END__` stops parsing the rest

Bash doesn't care about `=pod`/`=cut` (they error as commands, but bash has already `exit`ed before reaching them).

## Growing to 4 Langs: + julia

Julia treats `#` as line comment and `#= ... =#` as block comment. Strategy: wrap the Perl/bash section in Julia's `#= =#`, put Julia code after, and wrap the C section in another `#= =#` so Julia doesn't see the C syntax.

```
#if 0
#=
=pod
read a;read b;read c;r=1;a=$((a%c));...;echo $r;exit
=cut
use bigint;print((0+<>)**(0+<>)%(0+<>));__END__
=#
a,b,c=parse.(Int,readlines());print(powermod(a,b,c));exit()
#=
#endif
#include<stdio.h>
int main(){...}/*
=#
*/
```

What each language sees:
- **bash**: `#` comments everywhere except the shell line, which `exit`s before reaching C
- **perl**: `#if 0` → comment; `#=` → comment; `=pod`→`=cut` skipped; then runs the `use bigint` line ending in `__END__`, rest ignored
- **julia**: `#if 0` → `#` comment; `#=` starts block comment covering perl/bash; `=#` closes; runs the `a,b,c=parse...` line ending in `exit()`; next `#=` starts another block comment through the C code; the trailing `=#` closes it (the `*/` is inside a C `/* */` comment added specifically to hide `=#` from C)
- **C**: `#if 0 ... #endif` strips everything julia-ish; `#include<stdio.h>` + `int main()` compiles normally; trailing `/* =# */` is just a C comment

Each language's parser follows a completely different path through the same bytes. It's beautiful when it works.

### The `/* =# */` trick at the end

Julia needs `=#` to close its second block comment. But `=#` is not valid C. So we wrap `=#` in a C block comment: `/* =# */`. Julia ignores the `/*` and `*/` (they're already inside the `#=` block it's currently in), but sees the `=#` and closes. C ignores the whole thing as a block comment.

## Running It

```
$ docker compose run --rm polyglot-local bash,perl,julia,c solve.poly
--- bash ---
  passed all 50 tests
--- perl ---
  passed all 50 tests
--- julia ---
  passed all 50 tests
--- c ---
  passed all 50 tests
```

Submitted with bash + perl + julia + C all checked. **Scored 4.**

## The 5th Language Wall

We tried hard for a 5th (rust, typescript, lua, scheme, haskell) and each hit the same wall: **Julia's `#=...=#` is structurally incompatible with C-family `/* ... */` at the file-top level**. Any attempt to add TS/rust/lua broke either julia or one of the existing 4.

Some of what we tried and why it failed:

- **rust**: rust accepts `#!...` shebangs on line 1 (good!), but once past it, `#if 0` is a parse error — rust wants `#[attribute]` or `#![inner_attribute]`. Wrapping the whole content in `/* */` works for rust but breaks julia (`/*` is `/ *` → parse error). No overlap.
- **typescript**: accepts shebang on line 1, but line 2 onward must be valid TS. `#=` (needed for julia) is a syntax error in TS. No way to get both on early lines.
- **lua**: `--[[` at line 1 breaks julia (`--` is not a unary op). Put lua content inside julia's `#= =#`? Then lua sees `#=` which is a parse error.
- **scheme**: `#| ... |#` block comment could wrap the C section, but `/*` elsewhere breaks scheme, and `#include<stdio.h>` breaks scheme reader. Interleaving scheme's `#|` with C's `#if` got tangled fast.

The top team had **14 languages**. They clearly found a different structural backbone — probably NOT using `#if 0` + `#=` as the spine. Possibly building the whole thing as a chain of wrapped strings (`"""` in julia, `[[ ]]` in lua, backtick strings in perl, etc.) where each language evaluates one region and strings-out the rest. That's a full night's project — we got started too late.

## Key Takeaways

- **Polyglot construction is all about finding tokens that mean different things in each lang.** `#if 0 ... #endif` is a gem because `#` is a line comment in three different scripting languages AND a preprocessor directive in C.
- **Perl has more hiding tricks than you'd expect**: `=pod`/`=cut` for POD blocks, `__END__`/`__DATA__` for "stop parsing," `#!` shebang that perl ignores if it points to perl itself.
- **Julia's `#=...=#` is convenient but exclusive.** If you build around it, you can't easily co-host rust/TS/lua, all of which want `/* */` or `--[[` as their block comment start — which julia can't parse as code.
- **Test against the challenge Docker image, not just your local setup.** `bc` was the canonical example — Alpine locally had it, the remote didn't. Cost us several submissions before we noticed.
- **Numeric overflow is the other silent killer.** Lua `^`, Perl `**`, C `pow()` all return doubles that NaN out for the challenge's number range. Always use `powermod`/`BigInt`/manual modexp.
- **For multi-lang polyglots, restart from scratch when expanding.** We kept trying to bolt a 5th language onto the 4-lang skeleton. Better strategy: when adding a hard language (rust/TS), build the polyglot with THAT language as the backbone and retrofit the easy ones.

## Files

- `solve.poly` — the 4-language polyglot source
- `solve.gs` — the 7-byte GolfScript solve (unused for multi-lang strategy, would score 1)
- `analysis.md` — session notes
