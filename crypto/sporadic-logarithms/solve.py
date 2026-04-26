#!/usr/bin/env python3
"""
Sporadic Logarithms solver.

hol_pow((g,c), x)[0] = prod_{i=0}^{x-1} c^i * g * c^{-i}

Since c has order m (<=8), write x = q*m + r:
  h = G^q * P_r
where G = prod of one full period, P_r = partial product of first r elements.

BSGS on G to find q, try each r in 0..m-1.
"""

import sys
import math
import re
from pwn import remote, log, context

context.log_level = 'info'

HOST = "sporadiclogarithms.opus4-7.b01le.rs"
PORT = 8443
BOUND = 262144
ROUNDS = 5


class BB:
    def __init__(self, io):
        self.io = io
        self._drain_prompt()

    def _drain_prompt(self):
        # Reads until "bb> " prompt (no newline at end)
        self.io.recvuntil(b"bb> ", timeout=30)

    def _cmd(self, cmd):
        self.io.sendline(cmd.encode())
        # Response is a line of digits/text, then "bb> "
        line = self.io.recvuntil(b"\nbb> ", timeout=15)
        return line.decode().strip().rstrip("bb> ").strip()

    def mul(self, a, b):
        return int(self._cmd(f"mul {a} {b}"))

    def inv(self, a):
        return int(self._cmd(f"inv {a}"))

    def phi(self, a):
        return int(self._cmd(f"phi {a}"))

    def eq(self, a, b):
        return self._cmd(f"eq {a} {b}") == "1"

    def submit(self, x):
        self.io.sendline(f"submit {x}".encode())
        # Read until correct/wrong
        resp = self.io.recvuntil([b"correct", b"wrong"], timeout=15)
        return b"correct" in resp


def solve_round(io, ridx):
    # Read setup lines until group= line
    c_order = None
    handles_line = None
    while True:
        line = io.recvline(timeout=15).decode().strip()
        log.debug(f"< {line}")
        m = re.search(r'c order=(\d+)', line)
        if m:
            c_order = int(m.group(1))
        if line.startswith("group="):
            handles_line = line
            break

    m = re.search(r'one=(\d+)\s+g=(\d+)\s+c=(\d+)\s+h=(\d+)', handles_line)
    one_h, g_h, c_h, h_h = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
    log.info(f"Round {ridx}: c_order={c_order}, g={g_h}, c={c_h}, h={h_h}")

    bb = BB(io)

    mo = c_order

    # Compute g_i = phi^i(g) for i=0..mo-1
    gi = [g_h]
    cur = g_h
    for i in range(1, mo):
        cur = bb.phi(cur)
        gi.append(cur)

    # Compute partial products P[r] = g_0 * g_1 * ... * g_{r-1}
    # P[0] = one, P[mo] = G (full period)
    P = [one_h]
    cur = one_h
    for i in range(mo):
        cur = bb.mul(cur, gi[i])
        P.append(cur)
    G = P[mo]

    log.info(f"Full period product G={G}")

    # BSGS: find q such that G^q = h * P[r]^{-1}
    max_q = BOUND // mo + 1
    step = int(math.isqrt(max_q)) + 1
    log.info(f"BSGS: max_q={max_q}, step={step}")

    # Baby steps: compute G^j for j=0..step-1
    baby = {}
    Gpow = one_h
    for j in range(step):
        if Gpow not in baby:
            baby[Gpow] = j
        if j < step - 1:
            Gpow = bb.mul(Gpow, G)
    # Gpow = G^{step-1} now, compute G^step
    G_step = bb.mul(Gpow, G)
    G_step_inv = bb.inv(G_step)

    log.info(f"Baby table size={len(baby)}")

    for r in range(mo):
        Pr_inv = bb.inv(P[r])
        target = bb.mul(h_h, Pr_inv)

        cur_t = target
        for i in range(max_q // step + 2):
            if cur_t in baby:
                j = baby[cur_t]
                q = i * step + j
                x = q * mo + r
                if 0 <= x <= BOUND:
                    log.success(f"Found x={x} (q={q}, r={r})")
                    ok = bb.submit(x)
                    if ok:
                        log.success("Correct!")
                        # Drain any trailing newline
                        return True
                    else:
                        log.error(f"Wrong! x={x}")
                        return False
            cur_t = bb.mul(cur_t, G_step_inv)

    log.error("BSGS failed")
    return False


def main():
    io = remote(HOST, PORT, ssl=True)
    line = io.recvline(timeout=10).decode().strip()
    log.info(f"Banner: {line}")

    for ridx in range(1, ROUNDS + 1):
        if not solve_round(io, ridx):
            log.error("Failed!")
            remaining = io.recvall(timeout=5)
            print(remaining.decode())
            return

    remaining = io.recvall(timeout=10)
    output = remaining.decode()
    print(output)
    m = re.search(r'bctf\{[^}]+\}', output)
    if m:
        flag = m.group(0)
        log.success(f"FLAG: {flag}")
        with open("flag.txt", "w") as f:
            f.write(flag + "\n")


if __name__ == "__main__":
    main()
