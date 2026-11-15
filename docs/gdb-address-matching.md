# Making GDB's stack addresses match the real run

A note on why an address you read in GDB is not the address your exploit sees at
runtime, and how to line them up. All numbers below were measured on
`hijack-to-shellcode/binary-exploitation-hijack-to-shellcode-w` with ASLR off.

## Why GDB's address differs

The stack base is pushed down by everything the kernel places *below* `main`'s
frame: **every environment variable** (name + value) and the **`argv` strings**
(especially `argv[0]`). GDB changes both:

1. It injects `LINES`, `COLUMNS`, and `_=/usr/bin/gdb` — and plugins
   (GEF/pwndbg) can add more.
2. The loader lays out `argv[0]`/auxv slightly differently under `ptrace`,
   leaving a small **constant** residual even after the environment is identical.

Part (1) is large and variable (hundreds of bytes). Part (2) is small and fixed.
ASLR being off makes each individual environment deterministic — but GDB is a
*different* environment than the real run, so the numbers differ.

Measured for the same binary:

| Where the address was read | buffer address |
|---|---|
| Inside GDB (plain) | `0x7fffffffd120` |
| GDB, `unset env LINES` + `unset env COLUMNS` | `0x7fffffffd140` |
| GDB (`-nx`) + `unset env` (empty env) | `0x7fffffffdbd0` |
| Direct run, empty env (`env -i`) | `0x7fffffffdc70` |

## How to make manual GDB match the real run

### Step 1 — clear the environment inside GDB

This removes the big, variable part of the gap:

```gdb
gdb -nx ./binary-exploitation-hijack-to-shellcode-w
(gdb) unset env                 # clears ALL env vars (LINES, COLUMNS, _, ...)
(gdb) run < /dev/null
```

- `-nx` skips your `.gdbinit` / GEF / pwndbg so plugins can't shift the stack.
- `unset env` with **no argument** empties the whole environment, matching a real
  run started with `env -i ./binary` (or pwntools `process(BIN, env={})`).

### Step 2 — match `argv[0]` exactly

The path string you hand GDB *is* `argv[0]`, and its length moves the stack.
Start GDB with the **same path string** you use at runtime: if the exploit runs
`./binary`, use `gdb -nx ./binary` (relative), not the absolute path.

### Step 3 — account for the constant residual

Even after steps 1–2 a fixed offset remains. Here it is exactly `0xA0`
(160 bytes), identical on every run:

```
direct (env -i):      0x7fffffffdc70
gdb -nx + unset env:  0x7fffffffdbd0     # always 0xA0 lower
```

Both are perfectly stable across runs, so you can either:

- **Measure once, subtract:** `real_addr = gdb_addr + 0xA0`. Do it one time for
  your setup, or
- **Use a nop sled bigger than the offset.** Read any address near the sled in
  GDB, aim at the middle of a few-hundred-byte sled, and the 160-byte error
  disappears into the nops. This is what most people actually do.

## Reading the buffer address manually in GDB

The program calls `read(0, &data.input, size)`, so break on `read` and the second
argument (`rsi`) is your buffer:

```gdb
(gdb) unset env
(gdb) break read
(gdb) run
(gdb) print $rsi          # rsi = &data.input  -> the buffer address
(gdb) print $rsp          # frame base, if you prefer offsets from rsp
```

## Takeaway

Don't chase a byte-exact GDB match — it depends on the gdb version, plugins,
`argv[0]`, and the `_` variable. Instead:

1. **Clear env on both sides** (`unset env` in GDB ↔ `env -i` / `env={}` at
   runtime) to remove the big swing, then
2. **Absorb the small constant residual with a nop sled** (or subtract it once).

That is exactly why `hijack-to-shellcode/exploit_noleak.py` pairs `env={}` with a
1024-byte sled.

## Why a constant residual remains even after removing the environment

A natural question: if ASLR is off and I clear the environment on *both* sides,
why is there still a fixed ~`0xA0` gap? Measured with the environment made
byte-for-byte identical on both sides:

```
direct  env -i A=B         : 0x7fffffffdc70
gdb     set env A B         : 0x7fffffffdbf0
direct  env -i (empty)      : 0x7fffffffdc70
gdb     unset env (empty)    : 0x7fffffffdbf0
```

Making the environment identical does **not** close the gap, so the residual is
**not** an environment mismatch. (Adding `A=B` didn't even move either address —
the variable was small enough that 16-byte stack alignment absorbed it.)

The cause is structural. The kernel builds the initial stack below `main` like
this, high address downward:

```
[ stack top ]
  AT_RANDOM (16 B), AT_PLATFORM "x86_64", AT_EXECFN "<full exec path>"   <- strings
  argv[0] string, env strings
  padding to 16-byte alignment
  auxv[]   (AT_* key/value pairs, AT_NULL-terminated)
  envp[]   pointers + NULL
  argv[]   pointers + NULL
  argc
[ initial RSP ]        <- everything above pushes this down
```

GDB launches the target through **ptrace**, and lays out that argv/env/auxv block
slightly differently from a bare `execve`: the **auxiliary vector** can differ
(entry count/order, how `AT_EXECFN`/vDSO are populated) and the loader places its
own copies of the `argv[0]` / `AT_EXECFN` path strings. Whatever small byte
difference results is then **rounded to 16-byte stack alignment**, so it shows up
as a fixed step rather than a few stray bytes. It is a GDB/loader artifact, not
anything in your program.

Evidence it is GDB-side: the value shifted from `0xdbd0` to `0xdbf0` just by
changing how GDB was invoked (`-ex` on the command line vs `-x file`). So the
residual depends on the gdb version and invocation, which is why you cannot
reliably zero it out from inside gdb — you pin your invocation, measure the
constant once, and subtract it (or let a nop sled absorb it).

## Getting the exact address with NO leak

The deciding factor is **ASLR, not the leak**:

* **ASLR off (this challenge).** The runtime stack address is 100%
  deterministic for a fixed `(environment, argv, cwd)`. So you can get the exact
  address with no leak at all — pin those three, measure the address *once* under
  the real launch conditions, and hard-code it. It will be identical every run.
  Ways to measure it once:
  - Run the real binary directly and read it (here the program prints it; in
    general, a one-off `ltrace`/`strace`/instrumented run).
  - Read it in GDB and add the calibrated gdb→runtime constant (the `0xA0`).
  - Make the address itself *computable*: launch with `env -i` and a fixed-length
    `argv[0]`, so the stack top is a known constant and buffer = top − fixed.

* **Address-independent trick (no stack address needed at all) — the general
  idea.** On a non-PIE binary you can overwrite the saved return address with the
  fixed `.text` address of a stack-pivot gadget:
  - `jmp rsp` / `call rsp` / `push rsp; ret`: after `ret`, `rsp` points at the
    bytes right after the overwritten slot (your shellcode), so execution jumps
    straight in — you never need the stack address.
  - `jmp rax` / `call rax` (or any register): works only if that register already
    points into your controlled buffer at the moment of `ret`.

  **This specific binary does NOT allow it.** A byte scan finds no
  `jmp rsp`/`call rsp`/`push rsp; ret`. It *does* have `jmp rax` @ `0x40120c` and
  `call rax` @ `0x401014`, but `challenge()` ends with `mov $0x0,%eax; leave;
  ret`, so `rax = 0` at the `ret` — `jmp rax` would jump to address 0. No
  register points into the buffer. So here you fall back to the deterministic
  "ASLR-off, pin env+argv, measure once" method above (that is what
  `exploit_noleak.py` does).

* **ASLR on.** Now no amount of pinning helps — each run randomizes the stack —
  and you genuinely need a runtime leak, a brute force over the (often small)
  entropy, or a pivot to a non-randomized region. That is the case a leak exists
  for; this challenge deliberately disables ASLR so you don't need one.

## The gdb-to-runtime offset is NOT a constant

A warning about the `0xA0` above: it is **not** universal. The offset scales with
the length of `argv[0]` (the path string you launch the binary with), so a
different binary — or even the *same* binary via a different path — gives a
different offset. Measured (same binary, three path lengths, env cleared on both
sides):

| `argv[0]` length | runtime addr | gdb addr | offset (runtime − gdb) |
|---|---|---|---|
| 18 | `0x…dcc0` | `0x…dc90` | **0x30** (48) |
| 56 | `0x…dca0` | `0x…dc40` | **0x60** (96) |
| 97 | `0x…dc70` | `0x…dbf0` | **0x80** (128) |

A longer path magnifies the gdb-vs-`execve` layout difference (quantized to
16-byte alignment). The offset also depends on the environment and the exact gdb
invocation. So it is valid only for one fixed
`(binary path, environment, gdb invocation)`.

### How to calculate it

Measure the same address two ways under identical env + `argv[0]`, then subtract:

```
offset = runtime_address − gdb_address
```

- **gdb address:**
  ```
  gdb -nx -q -batch -ex 'unset env' -ex 'break read' \
      -ex 'run </dev/null' -ex 'printf "%p\n",$rsi' ./target
  ```
  (`$rsi` is the buffer argument at the `read(0, buf, n)` call.)
- **runtime address:** run directly with matching (empty) env and read it —
  `env -i ./target </dev/null` (here the program prints it; otherwise use a
  one-off `strace`/instrumented run).

Both measurements MUST use the same path string and the same environment, or you
are subtracting two unrelated numbers.

### Practical consequences

1. **Keep `argv[0]` and env identical in gdb and in the exploit.** If gdb runs
   `/long/abs/path/target` but the exploit runs `./target`, the addresses differ
   by far more than the residual. In pwntools pass the *same* path string to
   `process()` that you gave gdb, and pin env (`env={}` ↔ gdb `unset env`).
2. **Prefer a nop sled over calibrating.** For normal paths the offset is well
   under ~256 bytes, so a 512–1024 byte sled lets you use the gdb address
   *uncorrected* and the gap disappears into the nops.
3. **Hard lab, no leak:** the offset depends only on `argv[0]` length + env + gdb
   invocation, **not** on the binary's code. So you can calibrate it with a tiny
   helper that prints its own `$rsp`, launched via a path of the *same string
   length* as the target, then apply that offset to the target read in gdb. In
   practice the big sled is simpler.

---

*Education / authorized-lab use only.*
