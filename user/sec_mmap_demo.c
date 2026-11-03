/**
 * @file sec_mmap_demo.c
 * @brief Demostrador Principal y Cliente de Espacio de Usuario para sec_mmap
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Interfaz de línea de comandos para interactuar con el módulo de kernel sec_mmap,
 * configurar políticas de seguridad, consultar telemetría y ejecutar pruebas completas.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

#include "../kernel/sec_mmap_core.h"

static void print_banner(void)
{
    printf("====================================================================\n");
    printf(" SISTEMAS OPERATIVOS - EAFIT 2026-B\n");
    printf(" SUITE DE ASEGURAMIENTO DE ARCHIVOS EN CAPA KERNEL Y MMAP (v2.0)\n");
    printf("====================================================================\n");
}

static void print_usage(const char *prog)
{
    printf("Uso: %s [OPCION]\n", prog);
    printf("Opciones:\n");
    printf("  --status       Muestra la telemetria actual de seguridad desde /proc y Kernel\n");
    printf("  --set-ro       Establece politica de SOLO LECTURA (READ_ONLY)\n");
    printf("  --set-rw       Establece politica de LECTURA Y ESCRITURA (READ_WRITE)\n");
    printf("  --set-crypto   Activa el CIFRADO TRANSPARENTE de paginas\n");
    printf("  --reset-stats  Reinicia los contadores de estadisticas de Kernel\n");
    printf("  --read         Mapea con mmap() y lee el contenido protegido\n");
    printf("  --write        Mapea con mmap() e intenta modificar la memoria protegida\n");
    printf("  --all          Ejecuta la suite completa de pruebas de seguridad\n");
    printf("====================================================================\n");
}

static void show_status(int fd)
{
    struct sec_mmap_policy pol;
    struct sec_mmap_stats stats;

    /* Intentar leer primero /proc/sec_mmap_status */
    FILE *f = fopen("/proc/sec_mmap_status", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            fputs(line, stdout);
        }
        fclose(f);
        return;
    }

    if (fd < 0) {
        printf("[INFO] Driver de kernel no cargado y /proc/sec_mmap_status inaccesible.\n");
        return;
    }

    if (ioctl(fd, SEC_MMAP_IOCTL_GET_POLICY, &pol) == 0 &&
        ioctl(fd, SEC_MMAP_IOCTL_GET_STATS, &stats) == 0) {
        printf("--- ESTADO ACTUAL DE POLITICA (IOCTL) ---\n");
        printf("Banderas de Politica   : 0x%08x\n", pol.flags);
        printf("UID Autorizado         : %u\n", pol.allowed_uid);
        printf("Total llamadas mmap()  : %lu\n", (unsigned long)stats.total_mmaps);
        printf("Fallos de Lectura      : %lu\n", (unsigned long)stats.read_faults);
        printf("Fallos de Escritura    : %lu\n", (unsigned long)stats.write_faults);
        printf("Accesos Denegados      : %lu\n", (unsigned long)stats.blocked_unauthorized);
        printf("Paginas Cifradas       : %lu\n", (unsigned long)stats.pages_encrypted);
        printf("Violaciones Integridad : %lu\n", (unsigned long)stats.integrity_violations);
    }
}

int main(int argc, char *argv[])
{
    const char *dev_path = "/dev/sec_mmap";
    int fd = -1;

    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 0;
    }

    fd = open(dev_path, O_RDWR);

    if (strcmp(argv[1], "--status") == 0) {
        show_status(fd);
    } else if (strcmp(argv[1], "--set-ro") == 0) {
        if (fd < 0) {
            fprintf(stderr, "Error abriendo %s: %s\n", dev_path, strerror(errno));
            return 1;
        }
        struct sec_mmap_policy pol;
        memset(&pol, 0, sizeof(pol));
        pol.magic = SEC_MAGIC_TOKEN;
        pol.flags = SEC_POLICY_PERM_READ | SEC_POLICY_AUDIT_STRICT | SEC_POLICY_COW_TRACK;
        pol.allowed_uid = getuid();
        if (ioctl(fd, SEC_MMAP_IOCTL_SET_POLICY, &pol) == 0) {
            printf("[OK] Politica actualizada exitosamente: MODO SOLO LECTURA.\n");
        } else {
            perror("ioctl(SET_POLICY)");
        }
    } else if (strcmp(argv[1], "--set-rw") == 0) {
        if (fd < 0) {
            fprintf(stderr, "Error abriendo %s: %s\n", dev_path, strerror(errno));
            return 1;
        }
        struct sec_mmap_policy pol;
        memset(&pol, 0, sizeof(pol));
        pol.magic = SEC_MAGIC_TOKEN;
        pol.flags = SEC_POLICY_PERM_READ | SEC_POLICY_PERM_WRITE | SEC_POLICY_AUDIT_STRICT | SEC_POLICY_COW_TRACK;
        pol.allowed_uid = getuid();
        if (ioctl(fd, SEC_MMAP_IOCTL_SET_POLICY, &pol) == 0) {
            printf("[OK] Politica actualizada exitosamente: MODO LECTURA Y ESCRITURA.\n");
        } else {
            perror("ioctl(SET_POLICY)");
        }
    } else if (strcmp(argv[1], "--set-crypto") == 0) {
        if (fd < 0) {
            fprintf(stderr, "Error abriendo %s: %s\n", dev_path, strerror(errno));
            return 1;
        }
        struct sec_mmap_policy pol;
        memset(&pol, 0, sizeof(pol));
        pol.magic = SEC_MAGIC_TOKEN;
        pol.flags = SEC_POLICY_PERM_READ | SEC_POLICY_PERM_WRITE | SEC_POLICY_ENCRYPTED | SEC_POLICY_AUDIT_STRICT;
        pol.allowed_uid = getuid();
        memcpy(pol.crypto_key, "SEC_KEY_EAFIT26", SEC_KEY_LEN);
        if (ioctl(fd, SEC_MMAP_IOCTL_SET_POLICY, &pol) == 0) {
            printf("[OK] CIFRADO TRANSPARENTE activado con exito.\n");
        } else {
            perror("ioctl(SET_POLICY)");
        }
    } else if (strcmp(argv[1], "--reset-stats") == 0) {
        if (fd < 0) {
            fprintf(stderr, "Error abriendo %s: %s\n", dev_path, strerror(errno));
            return 1;
        }
        if (ioctl(fd, SEC_MMAP_IOCTL_RESET_STATS, 0) == 0) {
            printf("[OK] Estadisticas de seguridad reiniciadas.\n");
        }
    } else if (strcmp(argv[1], "--read") == 0) {
        if (fd < 0) {
            fprintf(stderr, "Error abriendo %s: %s\n", dev_path, strerror(errno));
            return 1;
        }
        char *ptr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
            perror("mmap PROT_READ");
        } else {
            printf("[OK] Region mapeada en %p. Leyendo contenido de Pagina 0:\n>>> %s\n", ptr, ptr);
            munmap(ptr, 4096);
        }
    } else if (strcmp(argv[1], "--all") == 0) {
        printf("[EJECUTANDO TODAS LAS PRUEBAS AUTOMATIZADAS]\n\n");
        if (system("./test_unauthorized") != 0) { /* handled */ }
        printf("\n");
        if (system("./test_race_cow") != 0) { /* handled */ }
        printf("\n");
        if (system("./test_crypto_integrity") != 0) { /* handled */ }
        printf("\n");
        if (system("./benchmark_perf") != 0) { /* handled */ }
    } else {
        print_usage(argv[0]);
    }

    if (fd >= 0) close(fd);
    return 0;
}

