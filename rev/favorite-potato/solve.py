#!/usr/bin/env python3
"""Invert the favorite_potato code.bin program."""
import sys
sys.path.insert(0, '.')
from macro_emu import parse_program, execute

def invert(program, A, X, Y):
    for op, imm in reversed(program):
        if op == 'SWAP_AY': A, Y = Y, A
        elif op == 'SWAP_AX': A, X = X, A
        elif op == 'SWAP_XY': X, Y = Y, X
        elif op == 'ROR_A':
            n = imm % 8
            if n:
                # Forward: A = ROR(A, n). Inverse: A = ROL(A, n) = ROR(A, -n) = ROR(A, 8-n).
                A = ((A << n) | (A >> (8 - n))) & 0xFF
        elif op == 'XOR_AY':
            # Forward: A = A ^ Y (Y unchanged). Inverse: A = A ^ Y (involution).
            A ^= Y
        elif op in ('XOR_A_IMM', 'XOR_A_IMM_FINAL'):
            A ^= imm
        elif op == 'ADD_A_IMM':
            A = (A - imm) & 0xFF
        elif op == 'ADD_X_A':
            # Forward: X += A (A unchanged). Inverse: X -= A.
            X = (X - A) & 0xFF
        elif op == 'ADD_Y_A':
            Y = (Y - A) & 0xFF
        else:
            raise Exception(f'Unknown op {op}')
    return A, X, Y

if __name__ == '__main__':
    data = open(sys.argv[1] if len(sys.argv) > 1 else 'code.bin', 'rb').read()
    program = parse_program(data)
    print(f'Parsed {len(program)} macros', file=sys.stderr)
    # Self-test: forward then inverse should match
    import os
    for trial in range(20):
        A0, X0, Y0 = os.urandom(3)
        Af, Xf, Yf = execute(program, A0, X0, Y0)
        Ai, Xi, Yi = invert(program, Af, Xf, Yf)
        ok = (Ai, Xi, Yi) == (A0, X0, Y0)
        print(f'Trial {trial}: in=({A0},{X0},{Y0}) -> out=({Af},{Xf},{Yf}) -> inv=({Ai},{Xi},{Yi})  {"OK" if ok else "MISMATCH!"}')
