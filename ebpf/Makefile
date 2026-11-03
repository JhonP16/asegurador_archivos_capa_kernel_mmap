# Makefile para el monitor eBPF de mmap()
# Sistemas Operativos - EAFIT 2026-B

CLANG ?= clang
CC ?= gcc
CFLAGS ?= -O2 -g -Wall -Wextra
BPF_CFLAGS ?= -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu

all: mmap_audit.bpf.o mmap_audit_user

mmap_audit.bpf.o: mmap_audit.bpf.c
	$(CLANG) $(BPF_CFLAGS) -O2 -g -c $< -o $@

mmap_audit_user: mmap_audit_user.c
	$(CC) $(CFLAGS) -o $@ $< -lbpf -lelf -lz

clean:
	rm -f mmap_audit.bpf.o mmap_audit_user

.PHONY: all clean

