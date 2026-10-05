# Wire Protocol

This document fully and precisely describes the binary TCP protocol of
`user_registration_service`. For a general introduction, see
[`README.md`](README.md).

## Conventions

- All multi-byte integer fields are **unsigned** and encoded in
  **network byte order** (big-endian).
- A TCP connection carries exactly one request/response exchange. A
  new connection is required for each additional command.
- There is no message terminator; field lengths are always given
  explicitly (either fixed or via a preceding length field).
- Byte offsets are 0-indexed and relative to the start of the
  respective message (not to the overall TCP payload, should multiple
  segments be needed).

## Message framing

Every request starts with a 1-byte command field:

| Offset | Size | Field | Type | Description |
|---|---|---|---|---|
| 0 | 1 | `cmd` | `uint8` | Command identifier, see table below |

The rest of the request depends on the value of `cmd`.

| `cmd` value | Name | Meaning |
|---|---|---|
| `0x01` | `CMD_REGISTER` | Register a user |
| `0x02` | `CMD_STATUS` | Query service status |

Any other value of `cmd` is ignored: the service sends no response
and closes the connection.

---

## `CMD_REGISTER` (`cmd = 0x01`)

Registers a username.

### Request

| Offset | Size | Field | Type | Description |
|---|---|---|---|---|
| 0 | 1 | `cmd` | `uint8` | `0x01` |
| 1 | 4 | `name_len` | `uint32` (BE) | Number of bytes in `name` |
| 5 | `name_len` | `name` | `bytes` | Username |

Documented upper bound for `name_len`: **64 bytes**.

### Response

A single text line, terminated with `\n`, **without** a preceding
length field:

```
Registered user: <name>\n
```

### Full example: registering `alice`

`name = b"alice"` (5 bytes).

**Request, byte by byte:**

| Offset | Byte(s) (hex) | Meaning |
|---|---|---|
| 0 | `01` | `cmd` = `CMD_REGISTER` |
| 1–4 | `00 00 00 05` | `name_len` = 5 |
| 5–9 | `61 6c 69 63 65` | `"alice"` |

As a continuous hex dump (10 bytes total):

```
01 00 00 00 05 61 6c 69 63 65
```

**Response, byte by byte** (23 bytes total):

```
52 65 67 69 73 74 65 72 65 64 20 75 73 65 72 3a 20 61 6c 69 63 65 0a
 R  e  g  i  s  t  e  r  e  d     u  s  e  r  :     a  l  i  c  e \n
```

i.e. `b"Registered user: alice\n"`.

**In Python:**

```python
import socket, struct

s = socket.create_connection(("127.0.0.1", 4444))
name = b"alice"

s.sendall(bytes([0x01]))              # cmd = CMD_REGISTER
s.sendall(struct.pack(">I", len(name)))  # name_len
s.sendall(name)                       # name

print(s.recv(1024))
# -> b"Registered user: alice\n"
```

---

## `CMD_STATUS` (`cmd = 0x02`)

Queries the service status; the client itself specifies how many
bytes the response should contain.

### Request

| Offset | Size | Field | Type | Description |
|---|---|---|---|---|
| 0 | 1 | `cmd` | `uint8` | `0x02` |
| 1 | 4 | `requested_len` | `uint32` (BE) | Desired response length in bytes |

Documented upper bound for `requested_len`: **256 bytes**
(`STATUS_MSG_CAPACITY`). Larger values are capped to this value
server-side.

### Response

Exactly `requested_len` bytes (or the capped value), starting with the
fixed status text `"OK: service healthy"` (19 bytes).

### Full example: status query with `requested_len = 19`

19 is exactly the length of the status text — the smallest
`requested_len` for which the response contains the full text without
truncation.

**Request, byte by byte** (5 bytes total):

| Offset | Byte(s) (hex) | Meaning |
|---|---|---|
| 0 | `02` | `cmd` = `CMD_STATUS` |
| 1–4 | `00 00 00 13` | `requested_len` = 19 (`0x13`) |

```
02 00 00 00 13
```

**Response, byte by byte** (19 bytes total):

```
4f 4b 3a 20 73 65 72 76 69 63 65 20 68 65 61 6c 74 68 79
 O  K  :     s  e  r  v  i  c  e     h  e  a  l  t  h  y
```

i.e. `b"OK: service healthy"` (no trailing `\n`).

**In Python:**

```python
s = socket.create_connection(("127.0.0.1", 4444))

s.sendall(bytes([0x02]))                # cmd = CMD_STATUS
s.sendall(struct.pack(">I", 19))        # requested_len

print(s.recv(19))
# -> b"OK: service healthy"
```

---

## Summary

| `cmd` | Name | Fields after `cmd` | Response |
|---|---|---|---|
| `0x01` | `CMD_REGISTER` | `name_len:uint32(BE)`, `name:bytes[name_len]` | Text line `Registered user: <name>\n` |
| `0x02` | `CMD_STATUS` | `requested_len:uint32(BE)` | `requested_len` bytes, starting with the status text |

A working example for both commands is provided in
[`tools/legit_client.py`](tools/legit_client.py).
