# canary-in-a-cage

![language](https://img.shields.io/badge/language-C-blue)
![license](https://img.shields.io/badge/license-MIT-green)

Full ASLR, PIE, stack canaries, NX, Full RELRO, FORTIFY_SOURCE. The
canary sits in its cage. It doesn't stay there.

A challenge in exploit development against a fully hardened network
service.

## 0. Scenario

You take on the role of a security tester who, as part of a
penetration test, has been asked to assess an internal network service
of a fictional company: a small "User Registration Service" that
registers employee accounts over a proprietary, binary TCP protocol
and reports their status. The client assumes the service is secure
because it was "built with all modern compiler protection mechanisms"
(ASLR, PIE, stack canary, NX, full RELRO, FORTIFY_SOURCE — see Section
4). Your assignment: show whether that assumption holds by building a
working proof of concept that reads a local file on the server
(`build/flag.txt`, standing in for a sensitive artifact such as a
configuration or credentials file) and sends it back to yourself —
with no valid credentials, purely over the network protocol.

This is not an artificial "find the one buggy line" puzzle. It mirrors
how real exploit development against modern mitigations typically
works: code audit, identifying multiple cooperating vulnerabilities,
and an exploit chain that works around or defeats every single
protection mechanism in turn, rather than switching any of them off.

## 1. Objective

You are given a small TCP service, compiled with full hardening
(ASLR, PIE, stack canary, NX, full RELRO, FORTIFY_SOURCE). Your task:

1. Analyze the service (source and/or binary) and find the
   vulnerability/vulnerabilities that enable a remote attack.
2. Build a working proof-of-concept exploit in Python that — despite
   all active mitigations — reads the contents of `build/flag.txt` and
   sends them back to the attacker.
3. Document your approach: which vulnerability/vulnerabilities you
   found, how you defeated each mitigation, and why your strategy
   works.

It is **not** specified how many independent bugs you need or exactly
where they are — that is part of the assignment.

**Use of AI/LLMs:** Using AI tools (ChatGPT, Claude, Copilot, local
models, etc.) for this exercise is explicitly **allowed and
encouraged** — just as in a real security tester's day-to-day work.
Briefly document in your submission where you used AI assistance and
for what (e.g. code review, explaining a mitigation mechanism,
debugging the ROP chain). The work that is genuinely yours is finding
the actual vulnerability in this service, understanding the analysis,
and actually getting the exploit to work against the running binary —
no generic model knows this specific code version and its exact
offsets in advance.

---

## 2. Real-World Examples of Related Vulnerabilities

Bugs involving client-controlled length values are not a niche
phenomenon from the 2000s. Three recent (no older than about two
years), well-known examples with publicly available, working PoC
exploits, exploitable in similarly structured ways:

- **CVE-2025-2263** — Sante PACS Server, March 2025, CVSS 9.8. PoC:
  two public exploit scripts on GitHub (see the NVD references).
- **CVE-2025-22457** — Ivanti Connect Secure / Policy Secure / ZTA
  Gateways, April 2025, CVSS 9.8, on CISA's KEV list. PoC: publicly
  documented multiple times, including an official Rapid7 Metasploit
  module.
- **CVE-2026-3055** — Citrix NetScaler ADC/Gateway ("CitrixBleed 3"),
  March 2026, CVSS 9.3, on CISA's KEV list. PoC: public exploit script
  on GitHub.

Older, but name-giving, precursors in the same area: Heartbleed
(CVE-2014-0160, OpenSSL, 2014) and "CitrixBleed" (CVE-2023-4966,
NetScaler, 2023).

---

## 3. The Target

The service is handed to you as a self-contained project, with its own
public documentation — the way you would find it on a real audit
target. It lives in [`service/`](service/):

- [`service/README.md`](service/README.md) — what the service is, how
  to build and run it, operational model.
- [`service/PROTOCOL.md`](service/PROTOCOL.md) — full, byte-level
  description of the wire protocol with concrete examples for both
  commands.
- [`service/tools/legit_client.py`](service/tools/legit_client.py) — a
  working example of legitimate use of both commands; useful to verify
  that your own build and environment (Section 5) work correctly.

This documentation deliberately contains no implementation details.

### Source for the analysis

In addition, the full source code is available for your vulnerability
analysis (Section 1): [`service/src/service.c`](service/src/service.c)
and [`service/src/protocol.h`](service/src/protocol.h).

All commands and paths in the rest of this document (`build/service`,
`src/service.c`, `make`, …) assume your working directory is
[`service/`](service/) — `cd service` first.

---

## 4. Security Hardening

The service is **not** built with a plain `gcc -o service service.c`
(which would provide little hardening on many systems), but with the
following command:

```bash
gcc -O2 -g -m64 -fmessage-length=0 -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong -fstack-clash-protection -fcf-protection=full \
    -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
    -o build/service src/service.c
```

(this is exactly what `make` in [`service/`](service/) runs — see
[`service/Makefile`](service/Makefile)). Build the service yourself
with this command (or an equivalent toolchain configuration, see
Section 5). Verify the result with `checksec`; on a toolchain that
actually implements all of these flags, you should get something like:

```
RELRO       Stack Canary  CFI          NX          PIE          FORTIFY
Full RELRO  Canary Found  SHSTK & IBT  NX enabled  PIE Enabled  Yes
```

(The exact CFI line depends on your gcc/binutils — what matters is
Full RELRO, Canary, NX, and PIE.)

What each mechanism means, in case any of them is unfamiliar:

- **Full RELRO**: the GOT is made read-only after loading; no GOT
  overwrites.
- **Stack Canary** (`-fstack-protector-strong`): a random value placed
  before the saved registers/return address is checked before the
  function epilogue.
- **CFI / SHSTK & IBT**: compile-time marker for Intel CET (shadow
  stack, indirect branch tracking). Check for yourself whether the CPU
  you're testing on actually supports this feature
  (`grep -o -E 'shstk|ibt' /proc/cpuinfo`) — without hardware support,
  the marker has no effect.
- **NX**: the stack and heap are not executable.
- **PIE**: the binary is loaded at a randomized base address (ASLR).
- **FORTIFY_SOURCE=2**: additional runtime checks for certain libc
  functions (e.g. the `*_chk` variants) where the buffer length is
  known at compile time.

Also note: ASLR must be active on your system (the Linux default),
meaning every restart of the service results in a new base address
for the binary, libc, and the stack.

---

## 5. Set Up Your Own Environment

There is **no prepared image and no prescribed distribution/version**
for this exercise — you must set up your own test environment
completely from scratch (e.g. in a VM or container of your choice) and
build the service there yourself with the command above. This is
deliberately part of the assignment: a real security assessment almost
never happens on a system specially prepared for you, and the concrete
addresses/offsets you will need later depend on your own build and
your own glibc version anyway — you would have to reproduce and
document a ready-made environment yourself regardless (`gcc --version`,
`ldd --version` / `rpm -q glibc` / `dpkg -l libc6`, `uname -r`).

Requirements for the environment you choose:

- A gcc (or compatible compiler) that supports the flags listed in
  Section 4 (a recent `gcc` or `clang` on any current Linux
  distribution satisfies this).
- ASLR enabled (the Linux default; usually nothing to do).
- Python 3 with `pwntools`.

Recommended tools (install these yourself):

- `pwntools` — including the CLI tools `checksec`, `ROPgadget`,
  `cyclic`, `shellcraft`, `disasm`/`asm` etc. that come with it.
- `gdb`, ideally with an extension such as `gef` or `pwndbg` for more
  comfortable work with memory, registers, and mitigation status.
- `objdump` / `readelf` (usually part of `binutils`, often already
  installed).
- `strace` / `ltrace` for runtime observation.

If you need a memory offset that cannot be derived from a public
formula or symbol but must be measured empirically: the standard
technique is to set a software breakpoint via `ptrace` at an
instruction address of your choosing and read a register value (e.g.
`RSP`) at runtime. A ready-made script for this is deliberately **not**
part of this exercise — implementing it is part of the assignment, if
you need this technique.

You will also need a file for local testing that the exploit should
read at the end. Create one yourself with arbitrary content in the
**same directory as the compiled program**, i.e. at `build/flag.txt`
(next to `build/service`):

```bash
mkdir -p build
echo "TRAINING{my_test_flag}" > build/flag.txt
```

### Alternative: prebuilt release binary

If you don't want to set up a full build toolchain, a precompiled
binary is attached to each [GitHub Release](../../releases) of this
repository (`user_registration_service-linux-x86_64`). It is built
with the exact same hardening flags as above, but **statically
linked** (`-static-pie`) specifically so that it runs on any x86-64
Linux system without depending on the host's installed glibc version.

Two things to know if you use it instead of building from source:

- Because it is self-contained, there is no separately mapped libc to
  work with — any code you need for your exploit chain lives inside
  this one binary instead of being split across the binary and a
  separate `libc.so`. The underlying vulnerabilities are identical
  either way; only how you locate usable code in memory changes.
- `checksec` will not report a `FORTIFY` line for this binary. This is
  a detection limitation of `checksec` for statically linked binaries
  (it looks for `*_chk` functions imported from a dynamic libc, which
  a static binary doesn't have as imports), not an actual absence of
  the protection — the compiler flag is identical to the dynamically
  linked build, and the `*_chk` functions are still present inside the
  binary itself.

Building it yourself (recommended, matches the rest of this exercise)
remains the primary path; the release binary is a convenience option.

---

## 6. Exploit Constraints

- The exploit must work against the `build/service` you compiled
  yourself (start it locally: `./build/service &`).
- It must work reliably across multiple restarts of the service (=
  different ASLR bases), not just once against a specific run.
- In the end, the contents of `build/flag.txt` must reach the attacker
  (your exploit script) and be printed out — the exfiltration path
  (response on the same connection, a new connection, a connect-back,
  …) is up to you, as long as it is consistent with how the service
  actually behaves.

---

## 7. Submission

- Your exploit script (Python, `pwntools` allowed and recommended).
- A short written write-up (one to two pages):
  - Which vulnerability/vulnerabilities did you find, and where in the
    code are they?
  - How did you deal with each individual active mitigation (ASLR/PIE,
    stack canary, NX, full RELRO)?
  - Why does your solution work reliably across multiple restarts of
    the service?
  - Which environment (distribution, gcc/glibc version) you worked
    with.
