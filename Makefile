# Master Makefile para el Proyecto de Seguridad de Archivos en Capa Kernel y mmap
# Asignatura: Sistemas Operativos - EAFIT 2026-B

SHELL := /bin/bash

all: modules user-targets ebpf-targets
	@echo "===================================================================="
	@echo " [COMPILACION COMPLETA CON EXITO]"
	@echo "  1. Modulo Kernel (LKM) : kernel/sec_mmap.ko"
	@echo "  2. Pruebas de Usuario  : user/test_unauthorized, test_race_cow,"
	@echo "                           user/test_crypto_integrity, benchmark_perf"
	@echo "  3. Monitor eBPF Ring 0 : ebpf/mmap_audit.bpf.o, ebpf/mmap_audit_user"
	@echo "===================================================================="

modules:
	@echo "===> Compilando modulo de kernel LKM..."
	$(MAKE) -C kernel

user-targets:
	@echo "===> Compilando binarios de espacio de usuario y PoCs..."
	$(MAKE) -C user

ebpf-targets:
	@echo "===> Compilando instrumentacion eBPF..."
	$(MAKE) -C ebpf

clean:
	@echo "===> Limpiando todos los artefactos de compilacion..."
	$(MAKE) -C kernel clean
	$(MAKE) -C user clean
	$(MAKE) -C ebpf clean
	rm -f *.log /tmp/sec_*

test: user-targets
	@echo "===> Ejecutando Suite de Pruebas Automatizadas..."
	./scripts/run_all_tests.sh

benchmark: user-targets
	@echo "===> Ejecutando Benchmark de Rendimiento..."
	./scripts/run_benchmark.sh

load:
	./scripts/load_module.sh

unload:
	./scripts/unload_module.sh

.PHONY: all modules user-targets ebpf-targets clean test benchmark load unload

