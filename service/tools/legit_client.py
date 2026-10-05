#!/usr/bin/env python3
"""
Minimal client for legitimate use of the service (see the top-level
README.md) - only meant to verify that your own build and environment
work. Strictly respects the documented protocol limits
(MAX_NAME_LEN=64, STATUS_MSG_CAPACITY=256) and is not a tool for the
actual vulnerability analysis.
"""
import argparse
import socket
import struct
import sys

CMD_REGISTER = 1
CMD_STATUS = 2
MAX_NAME_LEN = 64
STATUS_MSG_CAPACITY = 256


def register(host: str, port: int, name: bytes) -> bytes:
    if len(name) > MAX_NAME_LEN:
        raise ValueError(f"name_len {len(name)} exceeds the documented limit ({MAX_NAME_LEN})")
    with socket.create_connection((host, port)) as s:
        s.sendall(bytes([CMD_REGISTER]))
        s.sendall(struct.pack(">I", len(name)))
        s.sendall(name)
        return s.recv(4096)


def status(host: str, port: int, requested_len: int) -> bytes:
    if requested_len > STATUS_MSG_CAPACITY:
        raise ValueError(f"requested_len {requested_len} exceeds the documented limit ({STATUS_MSG_CAPACITY})")
    with socket.create_connection((host, port)) as s:
        s.sendall(bytes([CMD_STATUS]))
        s.sendall(struct.pack(">I", requested_len))
        data = b""
        while len(data) < requested_len:
            chunk = s.recv(requested_len - len(data))
            if not chunk:
                break
            data += chunk
        return data


def main():
    parser = argparse.ArgumentParser(description="Legitimate test client for user_registration_service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4444)
    sub = parser.add_subparsers(dest="command", required=True)

    p_register = sub.add_parser("register", help="Register a user (CMD_REGISTER)")
    p_register.add_argument("name", help=f"Username, max. {MAX_NAME_LEN} bytes")

    p_status = sub.add_parser("status", help="Query service status (CMD_STATUS)")
    p_status.add_argument(
        "--len", type=int, default=19,
        help="desired response length (default: length of the status text)",
    )

    args = parser.parse_args()
    try:
        if args.command == "register":
            response = register(args.host, args.port, args.name.encode())
        else:
            response = status(args.host, args.port, args.len)
    except (ValueError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(1)

    print(response.decode(errors="replace"))


if __name__ == "__main__":
    main()
