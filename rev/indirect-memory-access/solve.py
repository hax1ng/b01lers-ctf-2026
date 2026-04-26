#!/usr/bin/env python3
"""
Solve for the b01lers CTF 2026 "indirect memory access" challenge.

The challenge is a GBA ROM that reads button presses and stores bits in a buffer.
After 128 bits, a complex boolean circuit (sub_310 + helper funcs) validates the buffer.
Each "gate" in the circuit is implemented via DMA0/DMA1/DMA3 interplay — the
DMA3 source (one of 7 ROM addresses) picks which of 7 logic gates is applied.

Our approach:
1. Identify the 7 truth tables (empirically probed via a patched ROM + mGBA GDB):
   - 0x08008b7c: a→b (IMP)
   - 0x08008b7e: OR
   - 0x08008b84: NAND
   - 0x08008b86: AND
   - 0x08008b88: XOR
   - 0x08008b8e: NOR
   - 0x08008b94: b→a
2. Use Unicorn Engine to emulate sub_310 and extract the 450-call circuit
   topology (recording which buffer bits feed which calls, and which gate per call).
3. Use Z3 to solve for the 128 input bits that make the final output TRUE.
4. Decode the bit stream back into button keypresses (prefix code with buttons
   "absSRLUDrl", where bit k = 1 terminates a press with MSB at position k).
"""
import json
from z3 import *
from unicorn import *
from unicorn.arm_const import *

ROM_PATH = "chal.gba"
with open(ROM_PATH, "rb") as f:
    rom = f.read()

GATES = {
    0x08008b7c: 'IMP_ab',
    0x08008b7e: 'OR',
    0x08008b84: 'NAND',
    0x08008b86: 'AND',
    0x08008b88: 'XOR',
    0x08008b8e: 'NOR',
    0x08008b94: 'IMP_ba',
}
BUF_BASE = 0x2000
CALL_BASE = 0x4000

# Phase 1: Extract the circuit via Unicorn symbolic tracing.
def extract_circuit():
    mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    mu.mem_map(0x08000000, 0x01000000, UC_PROT_READ | UC_PROT_EXEC)
    padded = rom + b'\x00' * (0x01000000 - len(rom))
    mu.mem_write(0x08000000, padded)
    mu.mem_map(0x02000000, 0x40000)
    mu.mem_map(0x03000000, 0x8000)
    mu.mem_write(0x03000000, rom[0xcff8:0xd078])
    mu.mem_write(0x03000394, rom[0xd078:0xe7ec])
    mu.mem_map(0x04000000, 0x1000)
    mu.reg_write(UC_ARM_REG_SP, 0x03007f00)

    calls = []
    current_sad = [0x08008b86]

    def hook_write(uc, access, addr, size, value, user):
        if addr == 0x040000d4 and size == 4:
            current_sad[0] = value
    mu.hook_add(UC_HOOK_MEM_WRITE, hook_write, begin=0x04000000, end=0x04001000)

    def hook_code(uc, addr, size, user):
        if addr == 0x03000024:
            r0 = uc.reg_read(UC_ARM_REG_R0) & 0xffff
            r1 = uc.reg_read(UC_ARM_REG_R1) & 0xffff
            lr = uc.reg_read(UC_ARM_REG_LR)
            idx = len(calls)
            out_id = CALL_BASE + idx
            calls.append({'idx': idx, 'r0_in': r0, 'r1_in': r1, 'sad': current_sad[0], 'out_id': out_id})
            uc.reg_write(UC_ARM_REG_R0, out_id)
            uc.reg_write(UC_ARM_REG_PC, lr | 1)
            cpsr = uc.reg_read(UC_ARM_REG_CPSR)
            cpsr |= (1 << 5)
            uc.reg_write(UC_ARM_REG_CPSR, cpsr)
    mu.hook_add(UC_HOOK_CODE, hook_code, begin=0x03000024, end=0x03000026)

    for i in range(128):
        mu.mem_write(0x030000a0 + i*2, (BUF_BASE + i).to_bytes(2, 'little'))
    mu.mem_write(0x040000d4, (0x08008b86).to_bytes(4, 'little'))

    cpsr = mu.reg_read(UC_ARM_REG_CPSR)
    cpsr |= (1 << 5)
    mu.reg_write(UC_ARM_REG_CPSR, cpsr)
    LR = 0x08e00000
    mu.reg_write(UC_ARM_REG_LR, LR | 1)
    try:
        mu.emu_start(0x08000310 | 1, LR, timeout=60*1000*1000)
    except UcError:
        pass
    return calls

# Phase 2: Build Z3 formula and solve.
def solve_circuit(calls):
    buf = [Bool(f'b{i}') for i in range(128)]
    call_out = [None] * len(calls)

    def gate(name, a, b):
        return {
            'AND': lambda: And(a, b),
            'OR': lambda: Or(a, b),
            'NAND': lambda: Not(And(a, b)),
            'NOR': lambda: Not(Or(a, b)),
            'XOR': lambda: Xor(a, b),
            'IMP_ab': lambda: Or(Not(a), b),
            'IMP_ba': lambda: Or(Not(b), a),
        }[name]()

    def resolve(v):
        if BUF_BASE <= v < BUF_BASE + 128:
            return buf[v - BUF_BASE]
        if CALL_BASE <= v < CALL_BASE + len(calls):
            return call_out[v - CALL_BASE]
        if v == 0:
            return BoolVal(False)
        return BoolVal((v & 0x8000) != 0)

    for i, c in enumerate(calls):
        a = resolve(c['r0_in'])
        b = resolve(c['r1_in'])
        call_out[i] = gate(GATES[c['sad']], a, b)

    s = Solver()
    s.add(call_out[-1] == True)
    assert s.check() == sat
    m = s.model()
    return [1 if is_true(m[b]) else 0 for b in buf]

# Phase 3: Decode bits to button presses.
def decode_bits(bits):
    buttons = "absSRLUDrl"  # bit 0=A, 1=B, 2=Select, 3=Start, 4=Right, 5=Left, 6=Up, 7=Down, 8=R, 9=L
    result = ""
    i = 0
    while i < len(bits):
        j = i
        while j < len(bits) and bits[j] == 0:
            j += 1
        if j >= len(bits):
            break
        pos = j - i
        if 0 <= pos < 10:
            result += buttons[pos]
        i = j + 1
    return result

if __name__ == "__main__":
    print("Extracting circuit...")
    calls = extract_circuit()
    print(f"Got {len(calls)} check calls")
    print("Solving with Z3...")
    bits = solve_circuit(calls)
    print(f"Bits: {''.join(str(b) for b in bits)}")
    chars = decode_bits(bits)
    flag = f"bctf{{{chars}}}"
    print(f"Flag: {flag}")
    with open("flag.txt", "w") as f:
        f.write(flag + "\n")
