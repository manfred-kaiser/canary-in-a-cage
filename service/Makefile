CC      ?= gcc
CFLAGS  = -O2 -g -m64 -fmessage-length=0 -D_FORTIFY_SOURCE=2 \
          -fstack-protector-strong -fstack-clash-protection -fcf-protection=full \
          -fPIE
LDFLAGS = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

.PHONY: all release clean

all: build/service

build/service: src/service.c src/protocol.h
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o build/service src/service.c

# Statically linked variant for distributing a single, portable binary
# (e.g. as a GitHub release asset) that does not depend on the host's
# glibc version. Carries the same hardening flags; only the linking
# mode differs. See the top-level README for details and caveats.
release: src/service.c src/protocol.h
	mkdir -p build
	$(CC) $(CFLAGS) -static-pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
	    -o build/service-static src/service.c

clean:
	rm -f build/service build/service-static
