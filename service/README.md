# user_registration_service

Lightweight TCP network service for registering usernames and querying
service status. Speaks a simple, binary, custom protocol (not HTTP),
with no authentication and no encryption — intended for use on a
network assumed to be trusted.

## Features

- Two commands: register a user, query service status
- A single TCP port, no external dependencies beyond libc
- One child process per connection (no threading, no event loop)

## Building

Requirement: a C compiler that supports `-fstack-protector-strong`,
`-fstack-clash-protection`, `-fcf-protection=full`, `-fPIE`/`-pie` and
`-Wl,-z,relro,-z,now` (a recent `gcc` or `clang`).

```bash
make
```

This builds `build/service` with full compiler hardening (see
`Makefile` for the exact flags). Verify with:

```bash
checksec --file=build/service
```

## Running

```bash
./build/service
```

Binds to TCP port `4444` on all interfaces and prints
`user_registration_service listening on port 4444` to stdout on
startup. Runs in the foreground; `Ctrl+C` or `kill` the process to
stop it. For background operation: `./build/service &`.

## Protocol

A custom, binary TCP protocol (not HTTP). A client opens a connection
to port `4444`, sends exactly one command (`CMD_REGISTER` or
`CMD_STATUS`), and receives a response; the connection is then closed.
The full, byte-level specification including concrete examples is in
[`PROTOCOL.md`](PROTOCOL.md).

A ready-to-run command-line tool for both commands is provided in
[`tools/legit_client.py`](tools/legit_client.py):

```bash
python3 tools/legit_client.py register alice
python3 tools/legit_client.py status --len 19
```

## Operational model

- A single service process continuously accepts new connections; each
  connection is handled in its own child process.
- No authentication, no encryption (plain-text TCP).
- No log file — all output goes to stdout.

## Project layout

```
src/service.c         Service implementation
src/protocol.h        Protocol constants
tools/legit_client.py Minimal example client
PROTOCOL.md            Full wire protocol specification
Makefile               Build with full compiler hardening
LICENSE                License
```

## License

See [`LICENSE`](LICENSE).
