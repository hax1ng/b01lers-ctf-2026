"""Submit payload to remote pickelang challenge.

Usage: python3 submit.py HOST PORT [hex_file]
Default hex file: out/payload_v9.hex

Handles MAX_CANON 4095-char stdin line limit by sending in chunks
(if remote uses canonical mode, we may still hit the limit).
"""
import sys
import socket
import os

def submit(host, port, hex_payload, test_input='[5, 3, 100]'):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((host, port))

    # Read pwn.red banner
    data = b''
    while b'pickelang >' not in data and b'> ' not in data:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    print(f'[*] Got prompt, sent banner: {data!r}')

    # Send hex payload + newline
    msg = (hex_payload + '\n').encode()
    s.sendall(msg)
    print(f'[*] Sent {len(msg)} bytes (hex payload)')

    # Now the script will call input() for the [A,B,C] - but actually no,
    # the runner only loads the pickle. The pickle itself calls input() for [A,B,C].
    # So next prompt is just '> ' or whatever input() emits with no prompt.
    # Send test input.
    s.sendall((test_input + '\n').encode())
    print(f'[*] Sent test input: {test_input}')

    # Read response
    out = b''
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    except socket.timeout:
        pass

    print(f'[*] Response: {out!r}')
    s.close()
    return out

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print('Usage: python3 submit.py HOST PORT [hex_file]')
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2])
    hex_file = sys.argv[3] if len(sys.argv) > 3 else 'out/payload_v9.hex'
    with open(hex_file) as f:
        hex_payload = f.read().strip()
    print(f'[*] Loaded {len(hex_payload)} hex chars from {hex_file}')
    submit(host, port, hex_payload)
