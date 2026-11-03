#!/usr/bin/env bash
# Script para correr benchmarks de rendimiento y registrar resultados
# Sistemas Operativos - EAFIT 2026-B

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
USER_DIR="${SCRIPT_DIR}/../user"
LOG_FILE="${SCRIPT_DIR}/../benchmark_results.log"

echo "===================================================================="
echo " EJECUTANDO BENCHMARK COMPARATIVO DE I/O"
echo " Salida registrada en: ${LOG_FILE}"
echo "===================================================================="

make -C "${USER_DIR}" benchmark_perf

{
    echo "===================================================================="
    echo " REPORTE DE BENCHMARK - $(date)"
    echo " Arquitectura: $(uname -m), Kernel: $(uname -r)"
    echo " CPU: $(grep -m 1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs)"
    echo "===================================================================="
    "${USER_DIR}/benchmark_perf"
} | tee "${LOG_FILE}"

