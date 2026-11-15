# Debug report: "shell spawns but dies the moment I type a command"

**Lab:** `hijack-to-shellcode` (pwn.college style stack-smash → shellcode)
**Symptom reported:** the payload runs and a shell appears to spawn, but pressing
Enter on the first command terminates the process. Suspicion: *"the process is
already terminated, but stdin keeps it alive until I type something."*

**Verdict:** that suspicion is correct. The process is **already dead before you
type anything**. The true bug is a **stale, hard-coded return address**; the
promptless pipe shell only makes a dead process *look* like a live shell.

---

## TL;DR

| | Before | After |
|---|---|---|
| Return address | hard-coded `0x7fffffffcae0` | computed from the address the program leaks |
| Behaviour under `process()` | `ret` misses the nop sled → **SIGSEGV (-11)** | `ret` lands in the sled → `execve("/bin/sh")` |
| What you saw | blank "shell", dies on Enter | real shell, `id` returns `uid=1000(vscode)` |

The one-line cause: **the absolute stack address is not the same in every
environment, so a hard-coded address is fragile. Read the address the binary
prints and compute the target at runtime.**

---

## 1. How the target actually works (from the source)

`binary-exploitation-hijack-to-shellcode-w.c`:

```c
struct { char input[19]; } data = {0};
unsigned long size = 0;
...
size = 4096;                                   // FIXED, line 118 — no length is read
printf("Send your payload (up to %lu bytes)!\n", size);
int received = read(0, &data.input, (unsigned long) size);   // single read, line 125
...
printf("The input buffer begins at %p\n", &data.input);      // <-- it LEAKS the address
return 0;                                       // <-- ret happens here
```

Key facts this establishes:

* **No length prompt.** `size` is hard-wired to `4096`, so your
  `recvuntil('… up to 4096 bytes)!')` is fine — nothing needs to send a length.
* **One `read()` into a 19-byte buffer with a 4096 cap** → classic overflow.
* The saved return address sits **40 bytes** after the buffer start
  (`analyst.md`: `0xca98 - 0xca70 = 0x28 = 40`). Your 40-byte pad + `RET` is the
  right geometry.
* The function **leaks `&data.input`** ("The input buffer begins at %p"). This is
  the gift that makes a robust exploit possible.
* Mitigations are down: no canary, no PIE, NX off / **stack executable**, and a
  constructor (`disable_aslr`) turns ASLR off by re-`execve`-ing itself.

Payload layout used by the exploit:

```
offset 0    40        48                 148            190
       | 40×'A' | 8-byte RET | 100×0x90 (nop sled) | shellcode |
                 ^            ^-- sled: buf+48 .. buf+148 --^
                 overwrites the saved return address
```

`RET` must point **into `buf+48 .. buf+148`** (the sled) so execution slides down
into the shellcode.

---

## 2. Reproducing the failure

Running the *original* exploit under `process()` with the absolute binary path:

```
REPORTED buffer addr via process(): 0x7fffffffd180
EOFError: process already dead -> shell did NOT survive
poll (exit status): -11            # -11 = SIGSEGV
```

Same run, both the stale and the dynamic address at the **same** leaked buffer
`0x7fffffffd180`:

```
CASE 1: stale hard-coded RET = 0x7fffffffcae0
        -> EOFError, process is DEAD      (0xcae0 is ~1.7 KB away from the sled)

CASE 2: dynamic RET = buf + 60 = 0x7fffffffd1bc
        -> shell ALIVE and responsive -> b'PROOF_42'
```

So at a fixed, real address the stale value misses the sled entirely and the
process crashes; the computed value lands in the sled and the shell works.

### Why the address drifted

`analyst.md` was captured in a run where the buffer was at `0x7fffffffca70`, so
`0xcae0 = buf + 0x70` happened to sit inside the sled. But the **stack base
moves** whenever the process environment changes:

* the length of `argv[0]` (`./binary…` vs the long absolute path),
* environment variables,
* the current working directory.

ASLR being disabled only means the layout is **deterministic for a fixed
environment** — it does **not** mean the number is identical across different
launch conditions. Run it under a different tool, path, or shell and the buffer
moves (here, to `0x7fffffffd180`). The hard-coded `0xcae0` then points at stale
stack bytes and the `ret` segfaults.

### Why it *looked* like "spawns, then dies on command"

1. The `ret` jumps outside the sled → **SIGSEGV at (or just after) the `ret`**,
   before/at `execve`. The process is already gone.
2. A `/bin/sh` launched with its stdin on a pipe prints **no prompt**. So
   `p.interactive()` shows a blank screen that is indistinguishable from a shell
   waiting for input.
3. `interactive()` keeps your terminal in its input loop regardless. The moment
   you hit Enter, pwntools writes to the dead process and the **EOF surfaces** —
   which feels exactly like "it died when I typed a command."

That is precisely the *"already terminated but stdin keeps it alive"* effect you
described. It was never a shell-stdin problem; it was a crash hidden by a
promptless pipe shell.

---

## 3. The fix

Don't hard-code the address — **read the one the program prints** and aim at the
sled:

```python
p.recvuntil(b'input buffer begins at ')
buf = int(p.recvuntil(b',').strip(b','), 16)   # e.g. 0x7fffffffd180
ret_target = buf + 40 + 8 + 20                 # buf+68, safely inside the sled
payload = b'A'*40 + p64(ret_target) + b'\x90'*100 + SHELLCODE
```

Because `RET_OFFSET` (40), the sled, and the shellcode are all **relative to the
leaked `buf`**, the exploit is correct no matter where the stack lands.

Nothing else about the exploit needed changing — the shellcode itself is fine:
`setuid(0)` then `execve("//bin/sh", {NULL}, NULL)` (`//bin/sh` behaves like
`/bin/sh`; a `NULL` argv is accepted by dash/bash).

### Verification

Driving the fixed `exploit.py` with commands piped into interactive mode:

```
$ printf 'id\nexit\n' | python3 exploit.py
[*] leaked input buffer @ 0x7fffffffd180 -> returning to 0x7fffffffd1c4
[*] Switching to interactive mode
uid=1000(vscode) gid=1000(vscode) groups=1000(vscode)
```

`id` runs and returns output — the shell is genuinely alive and executing
commands.

---

## 4. Notes & gotchas worth remembering

* **A promptless shell is still a shell.** Over a pipe, `sh` prints no `$`. Blank
  ≠ dead. Type `id` / `ls` / `cat flag` and look for output. To force a prompt
  you can run `export PS1='pwn> '` or spawn an interactive one with
  `exec /bin/sh -i` once you're in.
* **Check `poll()` to tell "no prompt" from "dead".** `p.poll()` returns `None`
  while running, or an exit/`-signal` if it ended. `-11` = SIGSEGV = your return
  address was wrong.
* **If you ever send the payload and the shell gets EOF immediately** (exit 0,
  not a crash): that's the genuine stdin-EOF case. Use `p.interactive()` (keeps
  stdin open) rather than `send()`-then-exit. Here, though, the crash came first.
* **Prefer leaked/relative addresses over hard-coded ones.** Hard-coding only
  works if you reproduce the exact capture environment. When the binary hands you
  an address, use it.
* The old `RET = b'\xe0\xca…'` constant and `payload.bin` are leftovers from the
  `0xca70` capture; they are environment-specific and should not be reused.

---

## 5. "But I don't need a leak" — you're right, and here's the real catch

Your mental model is correct: with the stack executable (NX off) and ASLR off,
you only need to overwrite the saved return address so it points into a nop sled
that slides into your shellcode. **A memory leak is a convenience, not a
requirement.** The leak-based `exploit.py` is just the easy mode; it is not the
only way.

So why did your hard-coded address — which you *watched* point into the sled in
GDB — still fail? Because an ASLR-off address is only deterministic **for a fixed
environment**, and **GDB is a different environment than the real run.** GDB
injects its own env vars (`LINES`, `COLUMNS`, ...) and uses a different
`argv[0]`, both of which sit on the stack *below* `main`, so they push your whole
stack frame to a different address. Measured on this binary:

| Where you read the address | buffer address |
|---|---|
| **Inside GDB** (`run`) | `0x7fffffffd110` |
| Binary run directly | `0x7fffffffd1a0`  (**+0x90 = 144 bytes**) |
| pwntools `process(BIN)` | `0x7fffffffd180` |
| pwntools `process(BIN, env={})` | `0x7fffffffdc70` (stable every run) |

Four different addresses for the same binary with ASLR **off**. Nothing is
random — each environment is individually deterministic — but the GDB address is
not the address your pwntools exploit runs at. You sampled the right spot in the
wrong world. `0xcae0` really was in the sled *in GDB*; at runtime the sled had
moved.

### The leak-free recipe for hard labs (no leak, no source)

This is what `exploit_noleak.py` does, and it is what you want when the address is
not printed and no source is given:

1. **Stabilize the environment** so the runtime address is reproducible. Launch
   with a cleared, fixed environment: `process(BIN, env={})`. With ASLR off,
   identical launch conditions → identical stack address on every run (measured:
   `0x7fffffffdc70` on all 3 runs).
2. **Sample the address in that *same* environment.** Debug with the matching
   env so GDB and the exploit agree — `gdb.debug(BIN, env={})`:

   ```python
   io = gdb.debug(BIN, env={}, gdbscript='''
       break read
       continue
       finish
       printf "RSP = %p\\n", $rsp
   ''')
   ```

   Now the GDB offset is gone (both sides share `env={}`), so the address you
   read is the address you exploit at. Hard-code it.
3. **Use a big nop sled** to absorb any residual slack — a few hundred to ~1024
   bytes. The `read()` cap is 4096 and the 19-byte buffer overflows freely, so
   there is plenty of room. A wider sled means a near-miss still lands in nops.

Verified leak-free (`env={}` + hard-coded RET into a 1024-byte sled), 3/3 runs:

```
[*] no-leak: returning into nop sled at 0x7fffffffde30
uid=1000(vscode) gid=1000(vscode) groups=1000(vscode)
```

### Caveat: a big sled is a margin, not a substitute for knowing the address

A big sled only helps if your guess lands **inside** the sled's span. A blind
guess far from the real stack still crashes (tested: a guess 1 KB below the sled
→ SIGSEGV even with a 2000-byte sled). The sled widens your error budget; it does
not remove the need to know roughly where the stack is. In a real hard lab you
still get that "rough where" from step 2 (GDB under matching env), from a partial
leak, or from brute-forcing candidate addresses when ASLR is off.

### Quick reference: two exploits in this folder

* `exploit.py` — **leak-based** (easy mode). Reads the address the program prints
  and computes the target. Most robust *when a leak exists*.
* `exploit_noleak.py` — **leak-free** (hard-lab mode). `env={}` + big sled + a
  hard-coded address derived once via `gdb.debug(env={})`. Use this when nothing
  is printed and no source is given.

---

*Education / authorized-lab use only.*
