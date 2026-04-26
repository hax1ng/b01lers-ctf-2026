#!/usr/bin/env python3
"""
Piano solver — final.

Each node i starts at length flag[i] (after sub_4036f0 init).
Main runs 297 ops in sequence:
 - ADD(A,B): len(A) += len(B)   [from sub_403730]
 - SUB(A,B): len(A) -= len(B)   [from sub_403750]
 - INIT30: len(30) += 218       [from sub_403810]
 - BULK(A, target): len(A) = a*len(A) + b (from single-arg list transformer)
   where (a,b) is bulk_coeffs[target].

After main, check[i] requires len(i) at check entry == required[i].

Track node lengths as affine combos over the 30 unknown flag chars.
Use sympy for exact solution.
"""
import json
from sympy import symbols, Eq, solve as sym_solve, Integer, Rational
from parse import extract_ops, parse_disasm

REQUIRED = {0:19947, 1:36338, 2:15136, 3:17102, 4:48722, 5:6273, 6:1602,
            7:34918, 8:431, 9:44585, 10:14112, 11:2980, 12:24712, 13:951,
            14:70, 15:467, 16:19345, 17:43155, 18:77, 19:49333, 20:43705,
            21:49948, 22:2499, 23:6665, 24:18970, 25:19054, 26:32911,
            27:41660, 28:160, 29:47694, 30:4956, 31:19797, 32:24709,
            33:32229, 34:451, 35:49449}

KNOWN = {0:ord('b'), 1:ord('c'), 2:ord('t'), 3:ord('f'), 4:ord('{'), 35:ord('}')}

def add(a, b):
    o = dict(a)
    for k,v in b.items(): o[k]=o.get(k,0)+v
    return o

def sub(a, b):
    o = dict(a)
    for k,v in b.items(): o[k]=o.get(k,0)-v
    return o

def mul_add(combo, mul, const):
    """Return mul * combo + const."""
    o = {}
    for k,v in combo.items():
        o[k] = v * mul
    o['const'] = o.get('const', 0) + const
    return o

def main():
    with open('bulk_coeffs.json') as f:
        bulk = {int(k,16): tuple(v) for k,v in json.load(f).items()}

    lines = parse_disasm('./chal')
    ops, _ = extract_ops(lines)
    print(f"Ops: {len(ops)}")

    # Initial lengths: flag[i]
    lens = {i: {i: 1} for i in range(36)}

    for addr, op, a, b in ops:
        if op == 'INIT30':
            lens[a] = add(lens[a], {'const': 218})
        elif op == 'ADD':
            lens[a] = add(lens[a], lens[b])
        elif op == 'SUB':
            lens[a] = sub(lens[a], lens[b])
        elif op == 'BULK':
            # b is the target address
            if b not in bulk:
                print(f"Missing bulk {b:#x}")
                return
            (aa, bb) = bulk[b]
            lens[a] = mul_add(lens[a], aa, bb)

    # Build symbolic equations
    f = symbols('f0:36', integer=True)
    eqs = []
    for i in range(36):
        expr = Integer(0)
        for k,v in lens[i].items():
            if k == 'const': expr += Integer(v)
            else: expr += Integer(v) * f[k]
        eqs.append(Eq(expr, REQUIRED[i]))

    sub_list = [(f[i], v) for i,v in KNOWN.items()]
    eqs_s = [e.subs(sub_list) for e in eqs]
    unknowns = [f[i] for i in range(36) if i not in KNOWN]
    sol = sym_solve(eqs_s, unknowns, dict=True)
    print(f"Solutions: {len(sol) if sol else 0}")
    if not sol:
        for i,e in enumerate(eqs_s):
            print(f'  eq{i}: {e}')
        return

    s = sol[0]
    chars = []
    for i in range(36):
        if i in KNOWN: v = KNOWN[i]
        else: v = int(s[f[i]])
        chars.append(v)
    print("vals:", chars)
    flag = ''.join(chr(v) for v in chars)
    print("FLAG:", flag)
    if all(32<=v<=126 for v in chars):
        with open('flag.txt','w') as fp:
            fp.write(flag+'\n')
        print("flag.txt saved")
    else:
        print("non-printable, something is wrong")

if __name__=='__main__':
    main()
