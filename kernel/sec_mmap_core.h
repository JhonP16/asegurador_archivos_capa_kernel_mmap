/**
 * @file sec_mmap_core.h
 * @brief Definiciones compartidas, IOCTLs y estructuras de seguridad para sec_mmap
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Este encabezado define la interfaz de control y las estructuras de datos
 * compartidas entre el espacio de kernel (LKM) y el espacio de usuario.
 */

#ifndef _SEC_MMAP_CORE_H_
#define _SEC_MMAP_CORE_H_

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

#define SEC_MMAP_DEVICE_NAME    "sec_mmap"
#define SEC_MMAP_CLASS_NAME     "sec_mmap_class"
#define SEC_MMAP_DEFAULT_PAGES  16
#define SEC_MMAP_PAGE_SIZE      4096
#define SEC_MMAP_BUF_SIZE       (SEC_MMAP_DEFAULT_PAGES * SEC_MMAP_PAGE_SIZE) /* 64 KB */

/* Banderas de política de seguridad */
#define SEC_POLICY_PERM_READ    (1 << 0) /* 0x01: Lectura autorizada */
#define SEC_POLICY_PERM_WRITE   (1 << 1) /* 0x02: Escritura autorizada */
#define SEC_POLICY_ENCRYPTED    (1 << 2) /* 0x04: Cifrado transparente activado */
#define SEC_POLICY_AUDIT_STRICT (1 << 3) /* 0x08: Auditoría detallada por página */
#define SEC_POLICY_COW_TRACK    (1 << 4) /* 0x10: Rastreo estricto de Copy-On-Write */

/* Llave criptográfica por defecto (16 bytes para cifrado de bloque) */
#define SEC_KEY_LEN             16
#define SEC_MAGIC_TOKEN         0x504F5345 /* "SOEP" */

/**
 * struct sec_mmap_policy - Política de acceso y control de integridad
 */
struct sec_mmap_policy {
    uint32_t magic;          /* Token de validación (SEC_MAGIC_TOKEN) */
    uint32_t flags;          /* Banderas de política (SEC_POLICY_*) */
    uint32_t allowed_uid;    /* UID del usuario autorizado */
    uint32_t allowed_gid;    /* GID del grupo autorizado */
    uint8_t  crypto_key[SEC_KEY_LEN]; /* Clave simétrica de cifrado */
};

/**
 * struct sec_mmap_stats - Estadísticas y telemetría de seguridad en Kernel
 */
struct sec_mmap_stats {
    uint64_t total_mmaps;          /* Total de llamadas mmap() atendidas */
    uint64_t read_faults;          /* Fallos de página por lectura (.fault) */
    uint64_t write_faults;         /* Fallos de página por escritura (.page_mkwrite) */
    uint64_t blocked_unauthorized; /* Intentos de acceso denegados */
    uint64_t pages_encrypted;      /* Páginas cifradas/descifradas */
    uint64_t cow_break_events;     /* Eventos de ruptura Copy-On-Write */
    uint64_t integrity_violations; /* Violaciones de integridad detectadas */
};

/**
 * struct sec_audit_event - Registro de evento de auditoría
 */
struct sec_audit_event {
    uint64_t timestamp_ns;
    uint32_t pid;
    uint32_t uid;
    uint32_t event_type;     /* 1: MMAP_OPEN, 2: FAULT_READ, 3: FAULT_WRITE, 4: BLOCKED */
    uint64_t virtual_addr;
    uint32_t page_offset;
    char comm[16];
};

/* Definición de llamadas IOCTL */
#define SEC_MMAP_IOC_MAGIC  'S'

#define SEC_MMAP_IOCTL_SET_POLICY   _IOW(SEC_MMAP_IOC_MAGIC, 1, struct sec_mmap_policy)
#define SEC_MMAP_IOCTL_GET_POLICY   _IOR(SEC_MMAP_IOC_MAGIC, 2, struct sec_mmap_policy)
#define SEC_MMAP_IOCTL_GET_STATS    _IOR(SEC_MMAP_IOC_MAGIC, 3, struct sec_mmap_stats)
#define SEC_MMAP_IOCTL_RESET_STATS  _IO(SEC_MMAP_IOC_MAGIC,  4)
#define SEC_MMAP_IOCTL_SYNC_CIPHER  _IOW(SEC_MMAP_IOC_MAGIC, 5, uint32_t)

#endif /* _SEC_MMAP_CORE_H_ */

