CC      ?= gcc
CFLAGS  = -O2 -g -m64 -fmessage-length=0 -D_FORTIFY_SOURCE=2 \
          -fstack-protector-strong -fstack-clash-protection -fcf-protection=full \
          -fPIE
LDFLAGS = -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

.PHONY: all clean

all: build/service

build/service: src/service.c src/protocol.h
	mkdir -p build
	$(CC) $(CFLAGS) $(LDFLAGS) -o build/service src/service.c

clean:
	rm -f build/service
