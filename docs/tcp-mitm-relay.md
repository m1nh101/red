# TCP MITM Relay + Command Injection

Field notes for the **authenticated** variant of the `interceptor_communication` lab —
the one where you cannot just impersonate the server, you have to sit **in the middle**
of a live TCP connection, pass an authentication handshake through untouched, and
**rewrite one command** in flight.

Companion to [`tcp-interception.md`](tcp-interception.md) and
[`udp-spoofing.md`](udp-spoofing.md). Read `tcp-interception.md` first: it covers the
plain "get on-path with ARP spoofing and be the server" case. This doc is what changes
when being the server is *not enough*.

The working exploit is [`../pwn/interceptor_communication/mitm.py`](../pwn/interceptor_communication/mitm.py).

---

## TL;DR

- The flag lives **on the server** and is only sent in reply to the command `flag`
  ([`run:68-70`](../pwn/interceptor_communication/run#L68-L70)). The client never sends
  `flag` — it sends `echo` ([`run:28`](../pwn/interceptor_communication/run#L28)). So
  impersonating the server toward the client gets you **nothing**: the client has no
  flag to leak.
- The server only answers after a correct **per-connection secret**, which it
  re-randomises on every `accept()`
  ([`run:52`](../pwn/interceptor_communication/run#L52)) and which the client reads
  **out-of-band** from the server's shared memory
  ([`run:22`](../pwn/interceptor_communication/run#L22)). You cannot know or guess it.
- Therefore the only path is a **relay**: terminate the client's connection, open your
  own connection to the real server, **forward the secret handshake verbatim** (the
  client computes a valid secret for you for free), then **replace the client's `echo`
  with `flag`** and read the flag off your server connection.
- On this lab's box there is **no `iptables` / no `nf_nat`**, so you cannot REDIRECT or
  alias your way in. The inbound (client-facing) TCP is handled **by hand in scapy**;
  the outbound (server-facing) side is an ordinary kernel socket.
- The whole thing only works if the client talks **exclusively to you**. A single
  direct client→server connection re-randomises the secret and desyncs your relay, so
  the ARP poisoning has to be **aggressive and bidirectional**.

---

## 1. The protocol (why this variant is hard)

```
        client (10.0.0.2)                         server (10.0.0.3)
              │                                          │
              │  ── TCP SYN :31337 ───────────────────▶  │  accept()  -> secret = urandom(32)   (run:50-52)
              │  ◀──────────────────── "secret: " ─────  │
   reads server.secret   <<< out-of-band shared memory (run:22) >>>
              │  ── secret.hex() ─────────────────────▶  │  if hex != secret: close  (run:55-58)
              │  ◀──────────────────── "command: " ────  │
              │  ── "echo" ───────────────────────────▶  │  (run:62-64)
              │  ── "Hello, World!" ──────────────────▶  │  echo branch: send it back
              │  ◀──────────────────── "Hello, World!" ─ │
```

The flag branch is the one the client never takes:

```python
elif command == "flag":
    connection.sendall(flag.encode())    # run:68-70
```

Two independent locks:

1. **The flag is on the server**, gated behind a command the client never sends.
   *Being the server* can't produce it.
2. **Auth requires a live secret** the attacker can't know. *Being the client* to the
   real server can't produce it either — until you borrow the real client's secret by
   relaying.

The only key that opens both is a man-in-the-middle **relay** that forwards the secret
and swaps the command.

---

## 2. The attack

```
   client ──SYN──▶  [ you, 10.0.0.1 ]  ──SYN──▶  server
          ◀────────   relay / rewrite   ◀────────
```

Lock-step, driven by [`run_session()`](../pwn/interceptor_communication/mitm.py):

| step | direction | what you do |
|---|---|---|
| 1 | server → client | read `b"secret: "` from your upstream socket, forward to client |
| 2 | client → server | read the client's `secret.hex()`, forward **verbatim** (this authenticates you) |
| 3 | server → client | read `b"command: "`, forward to client |
| 4 | client → ~~server~~ | read the client's real command (`echo`) and **drop it** |
| 5 | you → server | send `b"flag"` instead |
| 6 | server → you | receive the flag |

Step 2 is the trick: the client reads the secret for *whatever server connection is
currently live* out of shared memory. Because you keep exactly one upstream connection
open, the secret the client hands you is exactly the one your upstream connection needs.
You never have to understand it — you just pass the bytes along.

---

## 3. Getting the packets (no NAT on this box)

The textbook move (see `tcp-interception.md`) is *be the server*: hand `10.0.0.3` to your
kernel, or `iptables -t nat ... REDIRECT` the traffic to a local socket. **Neither is
available here:**

```
$ lsmod | grep -E 'nf_nat|iptable_nat'    # nothing
$ which iptables                           # not installed
```

So:

- **You cannot alias `10.0.0.3`.** If you did, your upstream
  `create_connection(("10.0.0.3", 31337))` would loop back to your own listener instead
  of reaching the real server.
- **A plain `bind()`/`accept()` never fires.** After ARP spoofing, the client's SYN
  arrives at your NIC but its destination IP (`10.0.0.3`) isn't yours, so the kernel
  silently drops it — `accept()` hangs forever. (This is the classic *"it just sits at
  `listening...`"* symptom.)

The fix is to split the two sides across two different machineries:

- **Client-facing side — raw scapy.** Sniff the client's frames off the wire and speak
  TCP yourself: answer the SYN with a SYN-ACK, ACK the client's data, emit the server's
  replies as raw packets with `IP(src=10.0.0.3)`. The kernel isn't involved, so it
  being "not our IP" doesn't matter. This is the
  [`ClientTCP`](../pwn/interceptor_communication/mitm.py) class — a tiny hand-rolled TCP
  server (SYN-ACK, sequence/ack bookkeeping, payload ACKs). The lab is lock-step with
  one-second gaps, so no congestion control or fast retransmit is needed.
- **Server-facing side — kernel socket.** A normal
  `socket.create_connection(("10.0.0.3", 31337))`. It reaches the **real** server
  precisely because you did *not* alias `10.0.0.3` and did *not* poison your own ARP
  cache, so your kernel resolves `10.0.0.3` to the real server's MAC.

```
   ┌──────────────────── your host (10.0.0.1) ─────────────────────┐
   client ──raw frames──▶  AsyncSniffer ─▶ ClientTCP (scapy TCP)    │
          ◀─raw frames───                      │                    │
                                               ▼  relay + rewrite   │
                                     kernel socket ───────────────── server (10.0.0.3)
   └───────────────────────────────────────────────────────────────┘
```

---

## 4. The ARP war (the part that actually took the effort)

Getting the client to send to **you** was the hard bit, and the failures were
instructive.

### 4a. Unsolicited replies alone are ignored

Spraying gratuitous ARP **replies** (`op=2`, "`10.0.0.3` is-at `<me>`") did nothing: the
client already had a valid cache entry for `10.0.0.3`, and Linux did not adopt the
unsolicited reply. tcpdump showed our replies leaving and **zero** client traffic
arriving.

Fix: also send ARP **requests** (`op=1`, `psrc=10.0.0.3, hwsrc=<me>`). Processing an ARP
request *rewrites the sender's entry* even when gratuitous replies are dropped — you can
confirm it works because the client starts **replying** to the request.

### 4b. The real server keeps winning the cache

Even with requests landing, the client still connected **directly** to the real server.
Reason: while a client↔server connection is alive (and each one lasts several seconds
because of the `time.sleep(1)`s), every packet the client receives *from* the real
server refreshes its ARP entry back to the **real** MAC. The server "owns" the cache for
most of each cycle, and the next `connect()` fires before a slow poison loop flips it
back.

Fixes, both needed:

1. **Poison fast** — every ~20 ms
   ([`POISON_INTERVAL`](../pwn/interceptor_communication/mitm.py)) so the entry is
   *yours* at the instant the client calls `connect()`.
2. **Poison both directions** — also tell the **server** that `10.0.0.2` (the client)
   is at your MAC. Now the real server can no longer reach the client to refresh its
   cache, and any direct client SYN that still slips through has its SYN-ACK
   black-holed, so it never completes the handshake.

### 4c. Why bidirectional poisoning also fixes the *secret* race

The server re-randomises `self.secret` on **every** `accept()`
([`run:52`](../pwn/interceptor_communication/run#L52)). If a direct client↔server
connection accepts in between your relay reading the secret and the server validating
it, the shared secret changes underneath you and the server rejects your forwarded hex
(you see an empty `command:` prompt and the session restarts).

Black-holing direct connections kills this race for free: a direct SYN whose SYN-ACK is
dropped **never reaches `accept()`**, so it never re-randomises the secret. With the
client talking only to you and exactly one upstream open at a time, the secret is stable
for the whole session.

---

## 5. Running it

Run as root inside the `user_host` (10.0.0.1) namespace — i.e. the shell the `run`
file drops you into:

```bash
python3 mitm.py
```

Expected output (logging is intentionally minimal):

```
[hh:mm:ss] poisoning 10.0.0.2(mac ..) & 10.0.0.3(mac ..) -> <our mac> via eth0 every 0.02s
[hh:mm:ss] [*] iface=eth0 our_mac=..
[hh:mm:ss] [*] relay up; waiting to intercept 10.0.0.2 -> 10.0.0.3:31337
[hh:mm:ss] [+] FLAG: pwn.college{...}
```

The client retries forever, so you get unlimited attempts; the relay loops and retries
on any error until one session completes cleanly.

---

## 6. Code map

[`mitm.py`](../pwn/interceptor_communication/mitm.py), top to bottom:

- **`pick_iface` / `OUR_MAC` / `CLIENT_MAC` / `SERVER_MAC`** — discover the 10.0.0.0/24
  interface and resolve both victims' MACs up front (needed to poison each side).
- **`arp_poison`** — every 20 ms, blast `op=1` requests **and** `op=2` replies at **both**
  the client (`10.0.0.3 -> us`) and the server (`10.0.0.2 -> us`).
- **`arp_responder`** — an `AsyncSniffer` that instantly answers any `who-has` for the
  spoofed target, so a fresh ARP query can't briefly reach the real host.
- **`ClientTCP`** — the hand-rolled, client-facing TCP endpoint (SYN-ACK, `send_payload`,
  `recv_payload`, `reset`), all over raw scapy frames with `IP(src=10.0.0.3)`.
- **`run_session`** — the relay/attack: kernel socket to the real server, forward
  `secret:` → hex → `command:`, then send `b"flag"` in place of `echo` and return the
  flag.
- **`main`** — start the poisoner + responder, `AsyncSniffer` the client's TCP into a
  queue, and for each client SYN build a `ClientTCP`, establish, and run a session until
  one yields the flag.

---

## 7. Takeaways

- **Where does the secret/flag actually live?** Here it's on the *server*, behind a
  command the client never issues — so impersonation is a dead end and a true relay is
  mandatory. Always locate the asset before picking an interception style.
- **A relay doesn't need to understand the auth** — it only has to forward the right
  bytes at the right time. The secret was unknowable, yet irrelevant.
- **"On-path" is not a one-shot** — it's a cache you must *hold*. The real endpoint
  fights back by refreshing its peer's ARP, so poison fast and poison **both** ends.
- **Match the mechanism to the box** — no NAT and no spare IP means the kernel can't
  deliver the packets for you, so you handle one side of the TCP yourself with scapy.
