# qss (Quantum Secret Sharing)

**Category:** Crypto | **Difficulty:** Hard | **Flag:** `bctf{phy51c5_1s_l1k3_s3x}`

## TL;DR

The server runs a Quantum Secret Sharing protocol where we (Bob) must eavesdrop on a secret while convincing the protocol monitors we're not. The trick is to design a 3-qubit unitary that entangles Alice's ancilla qubit with Bob and Charlie's qubits at just the right angle (22.5°) — stealing just enough information to beat the minimum mutual information threshold while keeping our QBER (error rate) at the maximum allowed edge.

## What We're Given

A single Python file, `challenge.py`, which is the server source. It runs a 96-round Quantum Secret Sharing (QSS) protocol using Qiskit. We connect to the server and interact with it over the wire.

At the start, we submit:
1. A 2-element complex vector — our **ancilla statevector** (an extra qubit we get to prepare however we like)
2. An **8x8 unitary matrix** — a quantum operation we apply to the combined 3-qubit system (Alice, Bob, Charlie)

Then, for each of 96 rounds, the server:
- Picks a random secret bit, a random "set" (S0 or S1), a random basis for Alice, and whether the round is a "test" or "info" round
- Asks us to **pre-announce** a basis and outcome *before* it reveals any of those choices
- Reveals the set and Alice's basis
- If it's a test round: measures Alice and checks our announced outcome against the expected value
- If it's an info round: lets us measure qubits B and C, shows us the outcomes, and asks us to guess the secret

To get the flag, we have to satisfy all of these simultaneously:
- **QBER ≤ 0.32** — our error rate on test checks can't be too high (we can't make too many mistakes)
- **Mutual info ≥ 0.5 bits** — we have to actually learn the secret, not just guess randomly
- **Frontier check** — our (QBER, mutual_info) point must land within 0.25 bits of the theoretical QSS tradeoff curve
- **≥ 16 kept info rounds** with **≥ 60% raw accuracy**
- Our basis announcements can't be too lopsided (balance < 0.5)

This is essentially a scored eavesdropping challenge. We're supposed to find the optimal attack on a QSS protocol.

## Initial Recon

The challenge title is "Quantum Secret Sharing" and the server literally imports Qiskit. So right off the bat we know we're in quantum crypto territory.

Reading `challenge.py` reveals the QSS state space. The server picks Bell states based on two bits:

```
set=0, secret=0  →  phi- = (|00⟩ - |11⟩)/√2
set=0, secret=1  →  psi+ = (|01⟩ + |10⟩)/√2
set=1, secret=0  →  phi_up = (phi- - psi+)/√2
set=1, secret=1  →  psi_up = (phi- + psi+)/√2
```

One critical observation: `set=0` states use the Z-like basis (the standard Bell basis), while `set=1` states are their X-rotated equivalents. These four states span a **2D subspace** — even though they look like 4 different Bell states, they're really just two conjugate bases over the same two-dimensional space. This is exactly like how |0⟩, |1⟩, |+⟩, |−⟩ all live in the same qubit Hilbert space.

Also critical: the protocol requires a **pre-commitment**. Before the server reveals the set or Alice's basis, we announce what outcome we "measured." This is the paper's honest Bob model — in the real protocol, an honest Bob measures before learning this information. We're trying to cheat, but we have to make our cheating look like honest behavior.

## The Vulnerability / Trick

The core insight is the **information-disturbance tradeoff** in quantum cryptography. In any quantum protocol, if you try to learn information about a qubit, you inevitably disturb it — and that disturbance shows up as errors (QBER). You can't steal information for free; there's a fundamental tradeoff governed by quantum mechanics.

The QSS protocol is designed around this tradeoff. The frontier check (`|I_max(QBER) - I_emp| ≤ 0.25`) is the key constraint: it checks that our (error rate, information extracted) pair is consistent with being an **optimal quantum eavesdropper** — not a magic cheater who somehow gets perfect information with zero errors, but also not a sloppy cheater who gets too many errors for the info they gain.

In other words: the server wants us to demonstrate that we are *actually performing a quantum attack* on the protocol, following the physical laws. Pure classical guessing would give high info but no errors in the right pattern. Naive quantum cloning would give too many errors. We need to find the sweet spot.

**The sweet spot: θ = 22.5°**

Here's the attack. We design a unitary U that acts on the 3-qubit system (Alice ⊗ Bob ⊗ ancilla-we-injected) as follows:

For set=0 (Z-basis):
- phi- ⊗ |0⟩ → cos(θ)|000⟩ + sin(θ)|101⟩ (Alice mostly measures 0)
- psi+ ⊗ |0⟩ → cos(θ)|110⟩ + sin(θ)|011⟩ (Alice mostly measures 1)

At θ = 22.5°, cos²(22.5°) ≈ 0.854 and sin²(22.5°) ≈ 0.146. This means:

**For test rounds (set=0, Alice in Z basis):**
- Alice measures 0 with probability ~85.4% for phi- (secret=0)
- Alice measures 1 with probability ~85.4% for psi+ (secret=1)
- We pre-announce the expected outcome, so we're wrong about 14.6% of the time
- **QBER_Z ≈ 0.146** — well below the 0.32 threshold

**For info rounds (set=0):**
After Alice measures and we see outcomes B and C, the post-measurement state of qubit B tells us the secret perfectly:
- phi- → qubit B collapses to |0⟩ regardless of alice's outcome (secret=0)
- psi+ → qubit B collapses to |1⟩ regardless of alice's outcome (secret=1)

Bob just reads qubit B in the Z basis. **100% accuracy for set=0 info rounds.**

**For set=1 (X-basis):**
The X-basis states (phi_up, psi_up) are superpositions of the Z-basis states, and our unitary doesn't map them as cleanly. Alice's measurement is essentially random (50/50), giving **QBER_X ≈ 0.5** for test rounds. For info rounds, measuring B and C in the X basis gives us about 85% accuracy.

The overall QBER averages out to roughly 0.32 — right at the threshold. And our combined info accuracy (~92.5% for set=0 + ~85% for set=1) gives us well above the 0.5-bit mutual information requirement.

**The frontier check:**
The server computes `I_max(QBER)` using the formula for the maximum information an eavesdropper could theoretically extract at a given disturbance level. The formula is:

```
I_max(D) = 1 - h((1 - √(1 - (4D-1)²)) / 2)
```

where h() is binary entropy. At QBER ≈ 0.3, I_max ≈ 0.92 bits. Our empirical I_emp ≈ 0.62 bits lands within 0.25 bits of that — we pass the frontier check.

This is the elegant part: θ = 22.5° is not chosen arbitrarily. It's the angle that keeps QBER at the threshold while maximizing our information gain, landing us inside the valid frontier band.

**Pass rate:**
Not every run succeeds. The QBER is measured on a random sample of test rounds, and with finite samples there's variance. Our expected QBER is right at the threshold (0.32), so roughly 20% of runs come in under it. We retry until we win.

## Building the Exploit

The solve script has two main pieces: building the unitary, and playing the protocol rounds.

**Step 1: Build the unitary from input-output pairs**

We define the unitary by specifying what it does to an orthogonal basis. The key columns are the images of our two attack states:

```python
def perfect_info_U(theta_deg):
    phi_minus = np.array([1, 0, 0, -1], dtype=np.complex128) / sqrt2
    psi_plus = np.array([0, 1, 1, 0], dtype=np.complex128) / sqrt2
    # ... build input basis
    basis_in = np.column_stack([
        np.kron(phi_minus, anc0), np.kron(psi_plus, anc0),
        # ... other orthogonal basis vectors for completeness
    ])
    theta = np.deg2rad(theta_deg)
    c = np.cos(theta); s = np.sin(theta)
    e = np.eye(8, dtype=np.complex128)
    # phi- ⊗|0⟩ → cos(θ)|000⟩ + sin(θ)|101⟩
    out0 = c * e[:, 0] + s * e[:, 5]
    # psi+ ⊗|0⟩ → cos(θ)|110⟩ + sin(θ)|011⟩
    out1 = c * e[:, 6] + s * e[:, 3]
    # ... other outputs chosen to keep U unitary
    basis_out = np.column_stack([out0, out1, ...])
    return basis_out @ basis_in.conj().T
```

We specify where 8 orthogonal input vectors go, then compute U = output_matrix @ input_matrix†. The remaining 6 input vectors (the complement of our 2D attack subspace) get mapped to arbitrary orthogonal outputs — we chose them to keep U unitary without affecting our attack.

**Step 2: Precompute optimal measurement strategies**

For each combination of (set_bit, alice_basis), we enumerate all possible measurement plans for qubits B and C (Z or X basis for each), and for each plan, find the optimal guess mapping. This is done in `optimal_bob.py`:

```python
def best_strategy(U, ancilla):
    for set_bit in (0, 1):
        for alice_basis in ('z', 'x'):
            for b_basis in ('z', 'x'):
                for c_basis in ('z', 'x'):
                    # Compute P(b,c | secret=0) and P(b,c | secret=1)
                    # For each (b,c) outcome, guess whichever secret is more likely
                    acc += 0.5 * max(p_s0, p_s1)
```

This gives us a lookup table: `strategy[(set_bit, alice_basis)]` → `(measurement_plan, guess_map)`.

**Step 3: Play the rounds**

Pre-announcement is tricky because we have to commit before seeing the set or alice_basis. Our strategy: alternate Z and X announcements to maintain balance, and always announce outcome=0 (which is optimal for the Z check given our unitary design).

```python
if z_count <= x_count:
    basis = 'z'; z_count += 1; outcome = 0
else:
    basis = 'x'; x_count += 1; outcome = 0
r.sendline(json.dumps({"basis": basis, "outcome": outcome}).encode())
```

For info rounds that are "kept" (where our announced basis matches alice_basis), we send our precomputed measurement plan and then look up the guess from the outcomes:

```python
plan, guess_map, _ = strategy[(set_bit, alice_basis)]
# ... send plan, receive measurement outcomes
guess = guess_map[(b_val, c_val)]
```

**Step 4: Retry until we win**

Since our QBER hovers right at the threshold, some runs will fail. We wrap everything in a retry loop:

```python
for attempt in range(args.tries):
    output = play_one(args.theta, args.host, args.port)
    if re.search(r'bctf\{[^}]+\}', output):
        # We got it!
        break
```

**One parsing gotcha worth mentioning:** the server prints `measurement_outcomes:` and `secret_guess_bit>` on separate lines, but the naive `recvline()` approach can miss the outcomes line. The fix was to use `recvuntil(b"secret_guess_bit>")` and then regex-extract the outcomes from the captured buffer. This kind of I/O parsing issue is the CTF tax you pay when working with interactive protocols.

## Running It

A typical successful run looks like:

```
=== Attempt 1/30 ===
... (server output trimmed) ...
No flag yet: QBER too high. Attack detected during test rounds.

=== Attempt 4/30 ===
=== score ===
info_rounds=26
correct=24
kept_info_accuracy=0.9231
raw_info_accuracy=0.6833
qber=0.1250
max_qber=0.3200
bctf{phy51c5_1s_l1k3_s3x}

!!! FLAG: bctf{phy51c5_1s_l1k3_s3x}
```

In this winning run:
- 26 kept info rounds, 24 correct guesses → 92.3% accuracy
- QBER of 0.125 (we got lucky — the random sample had a low error rate this run)
- Raw accuracy 0.68 — well above the 0.60 floor

## Key Takeaways

**The big concept: information-disturbance tradeoff.** Quantum mechanics imposes a hard limit on how much information you can steal without leaving a trace. The QSS protocol is designed to detect eavesdroppers using this principle. Our attack lives right on the edge of that theoretical frontier — we're the optimal quantum eavesdropper, not an unphysical one.

**Designing quantum attacks via input-output unitary specification.** Rather than trying to construct a unitary from scratch using quantum gates, we specified what our 8 basis vectors map to, then recovered U = output @ input†. This is a clean way to design quantum operations when you know what you want the unitary to *do* rather than what circuit implements it.

**The Bell state subspace structure.** The four states (phi-, psi+, phi_up, psi_up) used in QSS are really just two conjugate bases for a 2D subspace — analogous to Z and X bases of a single qubit. Recognizing this collapses the apparent complexity of 4 states into a much simpler picture and reveals why θ = 22.5° works: it's the 1/8 turn that balances Z-basis precision against X-basis disturbance.

**Protocol frontier checks are tricky.** The `|I_max(QBER) - I_emp| ≤ 0.25` check is the hardest constraint. It rules out attacks that get high info with low QBER (too good to be physical) AND attacks that get high info with high QBER (just sloppy). You have to be an *optimally calibrated* eavesdropper. If you're building a similar challenge or trying to understand quantum key distribution security proofs, this frontier function is the thing to study.

**Retry loops are legitimate.** When your expected pass rate is 20%, you retry 30 times. This isn't a hack — it's probability. The attack is sound; the variance in small-sample QBER estimation is what creates uncertainty. On any given run we might get unlucky on the test round sample.

If you want to dig deeper into the actual QSS protocol being attacked here, search for "quantum secret sharing Hillery Buzek Berthiaume" — the original 1999 paper. The information-disturbance tradeoff we're exploiting is analyzed in depth in Scarani et al.'s review of quantum cryptography security proofs.

The flag, fittingly: **`bctf{phy51c5_1s_l1k3_s3x}`** — physics *is* like sex. You work out all the theory, and then you retry four times before it actually works.
