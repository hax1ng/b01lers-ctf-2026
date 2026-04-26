#!/usr/bin/env python3
"""Solve tiles+ai challenge: connect to remote server and submit the 3-round solution."""
import socket
import ssl

HOST = "tiles--ai.opus4-7.b01le.rs"
PORT = 8443

# Precomputed solutions for the 3 rounds (via BFS on simplified model)
ROUND_INPUTS = [
    "01e2e210f3f3f3010101",
    "01f320e201",
    "0120a2a2c231f2f2f2109393019311e320b211e3e300e31010923092921111c311d230e23030d310f3209201e2e210b3b3b30101",
]

def main():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((HOST, PORT), timeout=30)
    ssock = ctx.wrap_socket(sock, server_hostname=HOST)
    
    output = b""
    # Read up to 3 prompts
    for i, ans in enumerate(ROUND_INPUTS):
        # Read prompt like "N> "
        while b"> " not in output:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            output += chunk
        print(f"[Recv] {output!r}")
        # Send answer
        payload = ans.encode() + b"\n"
        ssock.send(payload)
        print(f"[Send] {payload!r}")
        # Reset output so we re-read the next prompt
        # Remove the last prompt already received
        idx = output.rfind(b"> ") + 2
        output = output[idx:]
    # Read remaining (flag)
    while True:
        try:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            output += chunk
            print(f"[Recv] {chunk!r}")
        except Exception as e:
            print(f"[Error] {e}")
            break
    print(f"\n[Final output]:\n{output.decode(errors='replace')}")

if __name__ == "__main__":
    main()
