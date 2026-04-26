"""v13: Pack (r, byte) state as tuple in outer memo. Sub returns new tuple.
Saves ~22 bytes per call.

Outer slot 88 = mul state tuple (r, byte). Sub reads outer[88], returns new tuple.
Outer slot 89 = pow state tuple (result, byte).

Init: build initial tuple, store in 88/89.
Per iter: bg(72) BINPERSID bp(88) POP = 6 bytes.
After: extract r from outer[88][0].
"""
import struct
from helpers import run_payload
import build_final as bf
import build_min2 as bm2

short_unicode = bf.short_unicode
short_bytes = bf.short_bytes
bin_bytes = bf.bin_bytes
push_int = bf.push_int
bg = bf.bg
bp = bf.bp

PROTO = bf.PROTO
EMPTY_DICT = bf.EMPTY_DICT
EMPTY_TUPLE = bf.EMPTY_TUPLE
TUPLE2 = bf.TUPLE2
REDUCE = bf.REDUCE
BINPERSID = bf.BINPERSID
MARK = bf.MARK
SETITEMS = bf.SETITEMS
STOP = bf.STOP
POP = bf.POP


def setup_v13():
    p = PROTO
    p += bf.build_table_dict() + bp(0)
    p += bf.PUSH_ADD + bp(1)
    p += bf.PUSH_GETITEM + bp(2)
    p += EMPTY_DICT + MARK + push_int(0) + push_int(0) + push_int(255) + push_int(1) + SETITEMS + bp(5)
    p += bf.PUSH_PACK + bp(7)
    p += bf.PUSH_UNPACK + bp(21)
    p += bin_bytes(bytes(255 - i for i in range(256))) + bp(15)
    p += short_unicode('>H') + bp(6)
    return p


def build_modc_bytes():
    p = bg(1) + bg(40) + bg(11) + TUPLE2 + REDUCE + bp(41) + POP
    p += bg(7) + short_unicode('>i') + bg(41) + TUPLE2 + REDUCE + bp(42) + POP
    p += bg(2) + bg(42) + push_int(0) + TUPLE2 + REDUCE + bp(43) + POP
    p += bg(2) + bg(5) + bg(43) + TUPLE2 + REDUCE + bp(44) + POP
    p += bg(2) + bg(41) + bg(40) + TUPLE2 + bg(44) + TUPLE2 + REDUCE + STOP
    return p


def call_modc():
    return bp(40) + POP + bg(71) + BINPERSID


# mul_iter: reads outer[80]=x, outer[88]=(r, byte) tuple
# Returns new (new_r, new_byte) tuple.
# Inner memo: 30=r, 31=byte, 60=doubled, 63=bit, 64=new_byte, 61=d_r, 62=add_x, 65=new_r
def build_mul_iter_v13():
    p = b''
    # Extract r and byte from outer[88]
    p += bg(2) + bg(88) + push_int(0) + TUPLE2 + REDUCE + bp(30) + POP   # r
    p += bg(2) + bg(88) + push_int(1) + TUPLE2 + REDUCE + bp(31) + POP   # byte
    # doubled = pack('>H', byte+byte)
    p += bg(7) + bg(6) + bg(1) + bg(31) + bg(31) + TUPLE2 + REDUCE + TUPLE2 + REDUCE + bp(60) + POP
    p += bg(2) + bg(60) + push_int(0) + TUPLE2 + REDUCE + bp(63) + POP   # bit
    p += bg(2) + bg(60) + push_int(1) + TUPLE2 + REDUCE + bp(64) + POP   # new_byte
    # d_r = mod_c(r+r)
    p += bg(1) + bg(30) + bg(30) + TUPLE2 + REDUCE + call_modc() + bp(61) + POP
    # add_x = mod_c(d_r + x)
    p += bg(1) + bg(61) + bg(80) + TUPLE2 + REDUCE + call_modc() + bp(62) + POP
    # new_r = (d_r, add_x)[bit]
    p += bg(2) + bg(61) + bg(62) + TUPLE2 + bg(63) + TUPLE2 + REDUCE + bp(65) + POP
    # Return tuple (new_r, new_byte)
    p += bg(65) + bg(64) + TUPLE2
    p += STOP
    return p


def call_mul_iter():
    return bg(72) + BINPERSID + bp(88) + POP   # 6 bytes!


def build_mul_bytes_v13():
    p = b''
    p += bg(50) + bp(80) + POP      # x
    p += bg(7) + bg(6) + bg(51) + TUPLE2 + REDUCE + bp(81) + POP   # pack(y)

    # Init state for high byte: (r=0, byte=high)
    p += push_int(0) + bg(2) + bg(81) + push_int(0) + TUPLE2 + REDUCE + TUPLE2 + bp(88) + POP
    for _ in range(8):
        p += call_mul_iter()
    # After high byte: extract r from state, build new state (r, low_byte)
    p += bg(2) + bg(88) + push_int(0) + TUPLE2 + REDUCE
    p += bg(2) + bg(81) + push_int(1) + TUPLE2 + REDUCE
    p += TUPLE2 + bp(88) + POP
    for _ in range(8):
        p += call_mul_iter()
    # Extract final r
    p += bg(2) + bg(88) + push_int(0) + TUPLE2 + REDUCE
    p += STOP
    return p


# pow_iter: reads outer[25]=base, outer[89]=(result, byte) tuple
# Returns (new_result, new_byte)
def build_pow_iter_v13():
    p = b''
    p += bg(2) + bg(89) + push_int(0) + TUPLE2 + REDUCE + bp(30) + POP   # result
    p += bg(2) + bg(89) + push_int(1) + TUPLE2 + REDUCE + bp(31) + POP   # byte
    # doubled / bit / new_byte
    p += bg(7) + bg(6) + bg(1) + bg(31) + bg(31) + TUPLE2 + REDUCE + TUPLE2 + REDUCE + bp(60) + POP
    p += bg(2) + bg(60) + push_int(0) + TUPLE2 + REDUCE + bp(63) + POP
    p += bg(2) + bg(60) + push_int(1) + TUPLE2 + REDUCE + bp(64) + POP
    # square = mul(result, result) - call mul subroutine at outer[70]
    p += bg(30) + bp(50) + POP + bg(30) + bp(51) + POP
    p += bg(70) + BINPERSID + bp(61) + POP
    # cand = mul(square, base)
    p += bg(61) + bp(50) + POP + bg(25) + bp(51) + POP
    p += bg(70) + BINPERSID + bp(62) + POP
    # new_r = (square, cand)[bit]
    p += bg(2) + bg(61) + bg(62) + TUPLE2 + bg(63) + TUPLE2 + REDUCE + bp(65) + POP
    p += bg(65) + bg(64) + TUPLE2
    p += STOP
    return p


def call_pow_iter():
    return bg(73) + BINPERSID + bp(89) + POP   # 6 bytes


def build_pow_v13():
    p = b''
    p += push_int(1) + bp(24) + POP
    p += bg(8) + bp(25) + POP
    p += bg(7) + bg(6) + bg(9) + TUPLE2 + REDUCE + bp(26) + POP   # pack(B)

    # Init pow state: (result=1, byte=high)
    p += push_int(1) + bg(2) + bg(26) + push_int(0) + TUPLE2 + REDUCE + TUPLE2 + bp(89) + POP
    # B < 2^15 so bit 15 always 0; skip first iter.
    # First iter would compute: square = 1*1 = 1, cand = 1*A, bit=0 -> new_r = square = 1.
    # Just need to advance byte: byte = pack('>H', byte+byte)[1]
    # And update state. Build new state (1, doubled_byte)
    p += push_int(1)
    p += bg(2)                                                      # getitem
    p += bg(7) + bg(6) + bg(1) + bg(2) + bg(89) + push_int(1) + TUPLE2 + REDUCE
    p += bg(2) + bg(89) + push_int(1) + TUPLE2 + REDUCE
    p += TUPLE2 + REDUCE + TUPLE2 + REDUCE                          # doubled bytes
    p += push_int(1) + TUPLE2 + REDUCE                              # doubled[1] = new_byte
    p += TUPLE2 + bp(89) + POP
    for _ in range(7):
        p += call_pow_iter()
    # After high byte: extract result, build (result, low_byte)
    p += bg(2) + bg(89) + push_int(0) + TUPLE2 + REDUCE
    p += bg(2) + bg(26) + push_int(1) + TUPLE2 + REDUCE
    p += TUPLE2 + bp(89) + POP
    for _ in range(8):
        p += call_pow_iter()
    # Extract final result to memo[24]
    p += bg(2) + bg(89) + push_int(0) + TUPLE2 + REDUCE + bp(24) + POP
    return p


def build_parse_full():
    p = b''
    p += short_bytes(b'') + bp(30) + POP
    for i in range(21):
        p += bg(1) + bg(30) + bg(2) + bg(0) + bg(2) + bg(3) + push_int(i)
        p += TUPLE2 + REDUCE + TUPLE2 + REDUCE + TUPLE2 + REDUCE
        p += bp(30) + POP
    p += bg(30) + STOP
    return p


def build():
    p = setup_v13()
    p += bin_bytes(build_modc_bytes()) + bp(71)
    p += bin_bytes(build_mul_iter_v13()) + bp(72)
    p += bin_bytes(build_mul_bytes_v13()) + bp(70)
    p += bin_bytes(build_pow_iter_v13()) + bp(73)
    p += bin_bytes(build_parse_full()) + bp(74)

    p += bg(1) + bf.PUSH_INPUT + EMPTY_TUPLE + REDUCE + short_unicode(']' * 30) + TUPLE2 + REDUCE + bp(3) + POP
    p += bg(74) + BINPERSID + bp(4) + POP
    p += bg(4) + BINPERSID + bp(14) + POP
    for idx, slot in [(0, 8), (1, 9), (2, 10)]:
        p += bg(2) + bg(14) + push_int(idx) + TUPLE2 + REDUCE + bp(slot) + POP

    p += bm2.neg_c_v2()
    p += build_pow_v13()
    p += bg(24) + STOP
    return p


if __name__ == '__main__':
    p = build()
    print(f'Total: {len(p)} bytes (hex: {len(p)*2})')

    test_cases = [
        ('[5, 3, 100]', pow(5, 3, 100)),
        ('[2, 10, 65535]', pow(2, 10, 65535)),
        ('[12345, 678, 54321]', pow(12345, 678, 54321)),
        ('[32767, 32767, 65535]', pow(32767, 32767, 65535)),
        ('[2, 1, 32768]', pow(2, 1, 32768)),
        ('[7, 100, 50000]', pow(7, 100, 50000)),
        ('[100, 200, 60000]', pow(100, 200, 60000)),
        ('[2, 32767, 32768]', pow(2, 32767, 32768)),
        ('[32767, 1, 32768]', pow(32767, 1, 32768)),
        ('[2, 16384, 65521]', pow(2, 16384, 65521)),
    ]
    all_ok = True
    for inp, expected in test_cases:
        try:
            result = run_payload(p, inp)
            status = 'OK' if result == expected else 'FAIL'
            if result != expected:
                all_ok = False
            print(f'{status}: {inp} -> {result} (expected {expected})')
        except Exception as e:
            all_ok = False
            print(f'EXC: {inp} -> {e}')

    import os
    os.makedirs('out', exist_ok=True)
    with open('out/payload_v13.hex', 'w') as f:
        f.write(p.hex())
    print(f'Saved to out/payload_v13.hex')
    print(f'All tests passed: {all_ok}')
