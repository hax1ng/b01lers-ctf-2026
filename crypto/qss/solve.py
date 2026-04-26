"""QSS solver - connects to server and runs the attack."""
import sys
import json
import argparse
import numpy as np
from pwn import remote, log, context

sys.path.insert(0, '/home/kali/CTF/b01lers CTF 2026/crypto/qss')
from run_full_sim import build_general_U
from optimal_bob import best_strategy, qber_for_U

sqrt2 = np.sqrt(2.0)
context.log_level = 'error'


def complex_to_json(c):
    c = complex(c)
    if abs(c.imag) < 1e-15:
        return c.real
    return f"{c.real}+{c.imag}i" if c.imag >= 0 else f"{c.real}{c.imag}i"


def matrix_to_json(M):
    rows = []
    for i in range(M.shape[0]):
        row = [complex_to_json(M[i, j]) for j in range(M.shape[1])]
        rows.append(row)
    return json.dumps(rows)


def play_game(host, port, theta_deg=15, phi_indices=(7, 1), psi_indices=(5, 3), verbose=True, design='general'):
    U = build_general_U(theta_deg, phi_indices, psi_indices)
    anc = np.array([1.0, 0.0], dtype=np.complex128)

    strategy = best_strategy(U, anc)
    qber_lookup = {(z, x): qber_for_U(U, anc, z, x) for z in (0, 1) for x in (0, 1)}
    best_announce = min(qber_lookup.items(), key=lambda kv: (kv[1]['z'] + kv[1]['x']) / 2)
    announce_z_out = int(best_announce[0][0])
    announce_x_out = int(best_announce[0][1])

    if verbose:
        print(f"Config: θ={theta_deg}, phi_indices={phi_indices}, psi_indices={psi_indices}")
        print(f"Announce: z={announce_z_out}, x={announce_x_out}")
        print(f"Expected QBER: Z={best_announce[1]['z']:.3f}, X={best_announce[1]['x']:.3f}")

    r = remote(host, port, ssl=True)
    try:
        r.recvuntil(b"ancilla_statevector_json>")
        r.sendline(json.dumps([1.0, 0.0]).encode())

        r.recvuntil(b"unitary_8x8_json>")
        u_json = matrix_to_json(U)
        r.sendline(u_json.encode())

        z_count = 0
        x_count = 0

        for round_idx in range(96):
            # Read round header & prompt
            header = r.recvuntil(b"pre_public_announce_json>").decode()
            if verbose:
                print(header, end='')
            round_type = "test" if "round_type: test" in header else "info"

            # Balance z/x
            if z_count <= x_count:
                basis = 'z'
                z_count += 1
                outcome = announce_z_out
            else:
                basis = 'x'
                x_count += 1
                outcome = announce_x_out
            r.sendline(json.dumps({"basis": basis, "outcome": outcome}).encode())

            if round_type == "test":
                # Read through test_check_valid line
                tail = r.recvuntil(b"test_check_valid:", timeout=60).decode()
                # Read to end of line
                line_end = r.recvline(timeout=10).decode()
                if verbose:
                    print(tail + line_end, end='')
            else:
                # Read through info_keep: line
                tail = r.recvuntil(b"info_keep:", timeout=60).decode()
                line_end = r.recvline(timeout=10).decode()
                combined = tail + line_end
                if verbose:
                    print(combined, end='')

                kept = "yes" in line_end
                if kept:
                    # Parse set_bit and alice_basis
                    set_bit = 0 if "S0" in combined else 1
                    alice_basis = 'z' if "public_alice_basis: z" in combined else 'x'

                    # Send plan
                    plan, guess_map, acc = strategy[(set_bit, alice_basis)]
                    plan_list = [["b", plan[0]], ["c", plan[1]]]
                    r.recvuntil(b"measurement_plan_json>")
                    r.sendline(json.dumps(plan_list).encode())

                    # Read measurement outcomes
                    outcomes_line = r.recvline(timeout=10).decode()
                    if verbose:
                        print(outcomes_line, end='')
                    # Parse outcomes - measurement_outcomes: b:z=0 c:z=0
                    parts = outcomes_line.replace("measurement_outcomes:", "").strip().split()
                    bits = {}
                    for part in parts:
                        name_basis, val = part.split('=')
                        name, base = name_basis.split(':')
                        bits[name] = int(val)
                    b_val = bits.get('b', 0)
                    c_val = bits.get('c', 0)
                    guess = guess_map[(b_val, c_val)]

                    r.recvuntil(b"secret_guess_bit>")
                    r.sendline(str(guess).encode())
                    if verbose:
                        print(f"[guess: {guess}]")

        # Read final score
        final = r.recvall(timeout=10).decode()
        print(final)
        return final
    finally:
        try:
            r.close()
        except:
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="qss.opus4-7.b01le.rs")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--theta", type=float, default=15)
    parser.add_argument("--phi", nargs=2, type=int, default=[7, 1])
    parser.add_argument("--psi", nargs=2, type=int, default=[5, 3])
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    output = play_game(args.host, args.port, args.theta, tuple(args.phi), tuple(args.psi), args.verbose)
    import re
    m = re.search(r'bctf\{[^}]+\}', output)
    if m:
        with open("flag.txt", "w") as f:
            f.write(m.group(0))
        print(f"FLAG: {m.group(0)}")
