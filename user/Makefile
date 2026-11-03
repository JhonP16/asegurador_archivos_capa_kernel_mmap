# Makefile para los ejecutables y pruebas de espacio de usuario
# Sistemas Operativos - EAFIT 2026-B

CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -g -pthread
INCLUDES = -I../kernel

TARGETS = test_unauthorized test_race_cow test_crypto_integrity benchmark_perf sec_mmap_demo

all: $(TARGETS)

test_unauthorized: test_unauthorized.c ../kernel/sec_mmap_core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_unauthorized.c

test_race_cow: test_race_cow.c
	$(CC) $(CFLAGS) -o $@ test_race_cow.c

test_crypto_integrity: test_crypto_integrity.c ../kernel/sec_mmap_core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ test_crypto_integrity.c

benchmark_perf: benchmark_perf.c
	$(CC) $(CFLAGS) -o $@ benchmark_perf.c

sec_mmap_demo: sec_mmap_demo.c ../kernel/sec_mmap_core.h
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ sec_mmap_demo.c

clean:
	rm -f $(TARGETS) *.o /tmp/sec_*

test: all
	@echo "===> Ejecutando Suite de Pruebas de Espacio de Usuario..."
	./test_unauthorized
	./test_race_cow
	./test_crypto_integrity
	./benchmark_perf

.PHONY: all clean test

