# Making GDB and Direct-Run Stack Addresses Match

When you leak or compute a stack address (buffer location, saved return
address, an environment variable's address for `ret2env`, etc.) **inside GDB**,
that address is usually **wrong** when you run the binary directly. The exploit
that worked under the debugger fails in the real run.

This guide explains *why*, and gives you two ways to deal with it:

- **Option A — Neutralize it (recommended).** Force both runs to share the
  exact same stack layout so the addresses are identical. No math.
- **Option B — Measure and compensate.** Compute the byte delta between the two
  environments and adjust your leaked address by hand, using
  [`scripts/envsize.py`](../scripts/envsize.py).

---

## Why the addresses differ

At process startup the Linux kernel builds the top of the stack like this
(highest address at the top):

```
          +--------------------------+  <- highest stack address
          |  env strings  KEY=VALUE\0 |   each var: len("KEY=VALUE") + 1 bytes
          |  argv strings  arg\0      |   each arg: len(arg) + 1 bytes
          |  auxv (auxiliary vector)  |
          |  envp[]  (char* + NULL)   |
          |  argv[]  (char* + NULL)   |
          |  argc                     |
          +--------------------------+  <- initial %rsp
          |   ... your stack frames   |
          |   (main, buffers, ...)    |
          v  (grows downward)
```

Everything below that top block — including `main`'s frame and your
buffer — sits at an address determined by **how big the top block is**.
Two things change that size between a direct run and a GDB run:

1. **Environment variables.** GDB injects or changes vars such as `LINES`,
   `COLUMNS`, and `_` (the path of the launched program). More/longer env
   strings push your buffer to a **lower** address.
2. **`argv[0]`** (the program path). Running `./target` stores an 8-byte
   string; GDB launches it as `/full/absolute/path/to/target`, which is
   longer. That difference shifts the stack too.

So the golden rule: **identical environment + identical argv[0] => identical
stack addresses.**

---

## Option A — Neutralize it (recommended)

Make both runs use a **fixed, minimal environment** and the **same program
path**. Then no address math is needed at all.

### A.1 Direct run

Use `env -i` to wipe the environment and set only what you need:

```bash
env -i PATH=/bin ./target
```

`env -i` starts from an empty environment. Add back only variables the program
genuinely needs (often just `PATH`, sometimes none at all).

### A.2 GDB run

Tell GDB to launch the target through the **same** `env -i` wrapper using
`exec-wrapper`:

```gdb
# inside gdb (or in a .gdbinit / -ex flags)
set exec-wrapper env -i PATH=/bin
run
```

`exec-wrapper` runs the program via the given command, so the child process
ends up with exactly the environment you specified — the same one as the direct
run.

### A.3 Match `argv[0]` too

`exec-wrapper` fixes the environment but **not** the program path. If you start
GDB as `gdb ./target`, argv[0] is still `./target`, which matches a direct
`./target` run. But if you launch with an absolute path (e.g.
`gdb /workspaces/binary_exploitation/target`), run the binary directly with
that **same** absolute path:

```bash
# direct run must use the identical path string GDB used
env -i PATH=/bin /workspaces/binary_exploitation/target
```

The string must match **character for character** — `./target`,
`target`, and `/abs/target` are all different lengths and shift the stack
differently.

### A.4 One-shot example (`pwntools`)

`pwntools` makes this automatic and consistent across both modes:

```python
from pwn import *

context.binary = elf = ELF('./target')

env = {'PATH': '/bin'}          # the fixed environment used in BOTH modes

# Direct run
io = process([elf.path], env=env)

# GDB run — same binary path, same env => same stack addresses
io = gdb.debug([elf.path], env=env, gdbscript='b *main\ncontinue')
```

Because the argv (`[elf.path]`) and `env` are identical in both calls, a stack
address you find in the `gdb.debug` session is valid in the `process` run.

### A.5 Verify they match

Put a breakpoint at `main`, note `$rsp` (or your buffer's address) under GDB,
then compare with a direct run that prints an address (a debug leak, or
`gdb`-less `ltrace`/manual leak). They should be **equal**. A quick check:

```gdb
# under gdb, with the exec-wrapper set as above
break main
run
print $rsp
```

If it still differs, re-check: same argv[0] string? any stray env var? a
`.gdbinit` adding environment? shell differences (`set environment` lines)?

---

## Option B — Measure and compensate

If you cannot control both environments (e.g. a remote target), measure the
byte difference and adjust your leaked address manually. Use
[`scripts/envsize.py`](../scripts/envsize.py).

### B.1 Capture each environment

```bash
# the real/direct environment
env > scripts/env_direct

# the GDB environment — dump what the *debugged process* actually sees.
# inside gdb, after `run`:
#   (gdb) call (int) system("env > /abs/path/scripts/env_gdb")
# or inspect with:  (gdb) show environment
```

### B.2 Compare

```bash
# env only
python3 scripts/envsize.py --diff scripts/env_direct scripts/env_gdb

# env + the differing argv[0] path (A = direct, B = gdb)
python3 scripts/envsize.py --diff scripts/env_direct scripts/env_gdb \
    --argv ./target /workspaces/binary_exploitation/target
```

The script prints a line like:

```
env+argv string-block delta (B - A): +66 bytes
A stack address that appears in B will be shifted by roughly -66 bytes ...
```

### B.3 Apply the correction

"B" is the GDB run. "More bytes in B" means the GDB stack top is larger, so
addresses in GDB are **lower**. To convert a GDB address to the direct-run
address, **add** the delta back:

```
direct_addr = gdb_addr + delta        # delta = (B - A) bytes
```

In the example, `direct_addr = gdb_addr + 66`.

> **Caveat — this is an approximation.** The loader 16-byte-aligns the
> argv/env block and inserts auxv entries and padding, which can absorb or
> round small deltas. Treat Option B's number as *very close*, then confirm
> the last few bytes empirically (a leak, or `x/40gx $rsp` at `main`).
> Option A avoids all of this and is strongly preferred when you control the
> launch.

---

## Quick reference

| Goal | Command |
| --- | --- |
| Fixed direct run | `env -i PATH=/bin ./target` |
| Fixed GDB run | `(gdb) set exec-wrapper env -i PATH=/bin` then `run` |
| pwntools direct | `process([elf.path], env={'PATH':'/bin'})` |
| pwntools GDB | `gdb.debug([elf.path], env={'PATH':'/bin'})` |
| Measure env size | `python3 scripts/envsize.py --current` |
| Measure .env file | `python3 scripts/envsize.py scripts/.env` |
| Diff two envs (+argv) | `python3 scripts/envsize.py --diff A B --argv ./t /abs/t` |

**Remember:** identical environment **and** identical `argv[0]` string =>
identical stack addresses. Fix both, and the offset problem disappears.
