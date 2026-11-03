#!/usr/bin/env bash
# Script automatizado para ejecutar la suite completa de pruebas
# Sistemas Operativos - EAFIT 2026-B

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_DIR="${SCRIPT_DIR}/../user"

echo "===================================================================="
echo " EJECUCION DE LA SUITE DE PRUEBAS DE SEGURIDAD MMAP (CAPA KERNEL)"
echo " Fecha: $(date)"
echo " Kernel: $(uname -s -r -m)"
echo "===================================================================="

# Compilar todo si hace falta
echo "[1/5] Compilando modulos y binarios de prueba..."
make -C "${USER_DIR}"

echo -e "\n[2/5] Ejecutando PoC 1: Accesos no autorizados y evasion POSIX..."
"${USER_DIR}/test_unauthorized"

echo -e "\n[3/5] Ejecutando PoC 2: Simulacion de condicion de carrera (COW + madvise)..."
"${USER_DIR}/test_race_cow"

echo -e "\n[4/5] Ejecutando PoC 3: Cifrado transparente e integridad de pagina..."
"${USER_DIR}/test_crypto_integrity"

echo -e "\n[5/5] Ejecutando Benchmark de rendimiento comparativo..."
"${USER_DIR}/benchmark_perf"

if [ -f "/proc/sec_mmap_status" ]; then
    echo -e "\n===================================================================="
    echo " TELEMETRIA FINAL DEL KERNEL (/proc/sec_mmap_status):"
    echo "===================================================================="
    cat /proc/sec_mmap_status
fi

echo -e "\n===================================================================="
echo " ==> TODAS LAS PRUEBAS CONCLUIDAS SATISFACTORIAMENTE."
echo "===================================================================="

