#!/usr/bin/env bash
# Script para cargar el modulo de kernel sec_mmap
# Sistemas Operativos - EAFIT 2026-B

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_PATH="${SCRIPT_DIR}/../kernel/sec_mmap.ko"
DEV_NODE="/dev/sec_mmap"

echo "===================================================================="
echo " CARGANDO MODULO DE KERNEL: sec_mmap"
echo "===================================================================="

if [ ! -f "${MODULE_PATH}" ]; then
    echo "[!] Modulo no encontrado en ${MODULE_PATH}. Compilando..."
    make -C "${SCRIPT_DIR}/../kernel"
fi

if lsmod | grep -q "sec_mmap"; then
    echo "[*] El modulo sec_mmap ya se encuentra cargado en el kernel."
else
    echo "[+] Insertando ${MODULE_PATH} en Ring 0..."
    sudo insmod "${MODULE_PATH}"
    echo "[+] Modulo insertado correctamente."
fi

# Esperar creacion del nodo udev
sleep 0.5

if [ -e "${DEV_NODE}" ]; then
    echo "[+] Ajustando permisos en ${DEV_NODE} a 0666..."
    sudo chmod 666 "${DEV_NODE}"
    echo "[+] Dispositivo listo para pruebas."
else
    echo "[!] Advertencia: No se encontro el nodo ${DEV_NODE} automaticamente."
    MAJOR=$(grep "sec_mmap" /proc/devices | awk '{print $1}')
    if [ -n "${MAJOR}" ]; then
        echo "[+] Creando nodo manualmente con mknod (Major: ${MAJOR})..."
        sudo mknod "${DEV_NODE}" c "${MAJOR}" 0
        sudo chmod 666 "${DEV_NODE}"
        echo "[+] Nodo creado con exito."
    fi
fi

if [ -f "/proc/sec_mmap_status" ]; then
    echo "[+] Verificando interfaz de telemetria:"
    cat /proc/sec_mmap_status | head -n 12
fi

echo "===================================================================="

