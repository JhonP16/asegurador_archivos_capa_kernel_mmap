#!/usr/bin/env bash
# Script para descargar el modulo de kernel sec_mmap
# Sistemas Operativos - EAFIT 2026-B

DEV_NODE="/dev/sec_mmap"

echo "===================================================================="
echo " DESCARGANDO MODULO DE KERNEL: sec_mmap"
echo "===================================================================="

if lsmod | grep -q "sec_mmap"; then
    echo "[+] Removiendo modulo sec_mmap de Ring 0..."
    sudo rmmod sec_mmap
    echo "[+] Modulo descargado y memoria fisica sanitizada con exito."
else
    echo "[*] El modulo sec_mmap no esta cargado actualmente."
fi

if [ -e "${DEV_NODE}" ]; then
    echo "[+] Eliminando nodo de dispositivo ${DEV_NODE}..."
    sudo rm -f "${DEV_NODE}"
fi

echo "===================================================================="

