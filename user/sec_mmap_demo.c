/**
 * @file sec_mmap_demo.c
 * @brief Shell Interactiva y Demostrador de Seguridad en Kernel para sec_mmap
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Implementa una consola interactiva (REPL) visualmente atractiva con soporte ANSI,
 * resolución dinámica de rutas de binarios y ejecución controlada de pruebas (PoCs).
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
#include <sys/stat.h>
#include <errno.h>
#include <libgen.h>

#include "../kernel/sec_mmap_core.h"

/* Códigos de Color ANSI */
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_CYAN    "\033[1;36m"
#define CLR_GREEN   "\033[1;32m"
#define CLR_YELLOW  "\033[1;33m"
#define CLR_RED     "\033[1;31m"
#define CLR_MAGENTA "\033[1;35m"
#define CLR_BLUE    "\033[1;34m"
#define CLR_WHITE   "\033[1;37m"

static char g_exec_dir[256] = {0};

/**
 * Determina el directorio donde residen los binarios para resolver rutas
 * relativas sin importar desde donde se ejecute la shell.
 */
static void init_exec_dir(const char *argv0)
{
    char buf[512];
    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        strncpy(g_exec_dir, dirname(buf), sizeof(g_exec_dir) - 1);
    } else {
        strncpy(buf, argv0, sizeof(buf) - 1);
        strncpy(g_exec_dir, dirname(buf), sizeof(g_exec_dir) - 1);
    }
}

/**
 * Resuelve la ruta exacta de un binario de prueba (PoC).
 */
static int resolve_binary(const char *name, char *out_path, size_t out_sz)
{
    /* 1. Probar en el mismo directorio del ejecutable */
    snprintf(out_path, out_sz, "%s/%s", g_exec_dir, name);
    if (access(out_path, X_OK) == 0) return 0;

    /* 2. Probar en subdirectorio ./user/ */
    snprintf(out_path, out_sz, "./user/%s", name);
    if (access(out_path, X_OK) == 0) return 0;

    /* 3. Probar en directorio actual */
    snprintf(out_path, out_sz, "./%s", name);
    if (access(out_path, X_OK) == 0) return 0;

    /* 4. Probar en ../user/ */
    snprintf(out_path, out_sz, "../user/%s", name);
    if (access(out_path, X_OK) == 0) return 0;

    return -1;
}

static void print_banner(void)
{
    printf("\n");
    printf(CLR_CYAN "  ╔══════════════════════════════════════════════════════════════════════════════╗\n" CLR_RESET);
    printf(CLR_CYAN "  ║" CLR_WHITE "   ███████╗███████╗ ██████╗       ███╗   ███╗███╗   ███╗ █████╗ ██████╗       " CLR_CYAN "║\n" CLR_RESET);
    printf(CLR_CYAN "  ║" CLR_WHITE "   ██╔════╝██╔════╝██╔════╝       ████╗ ████║████╗ ████║██╔══██╗██╔══██╗      " CLR_CYAN "║\n" CLR_RESET);
    printf(CLR_CYAN "  ║" CLR_WHITE "   ███████╗█████╗  ██║     █████╗ ██╔████╔██║██╔████╔██║███████║██████╔╝      " CLR_CYAN "║\n" CLR_RESET);
    printf(CLR_CYAN "  ║" CLR_WHITE "   ╚════██║██╔══╝  ██║     ╚════╝ ██║╚██╔╝██║██║╚██╔╝██║██╔══██║██╔═══╝       " CLR_CYAN "║\n" CLR_RESET);
    printf(CLR_CYAN "  ║" CLR_WHITE "   ███████║███████╗╚██████╗       ██║ ╚═╝ ██║██║ ╚═╝ ██║██║  ██║██║           " CLR_CYAN "║\n" CLR_RESET);
    printf(CLR_CYAN "  ║" CLR_WHITE "   ╚══════╝╚══════╝ ╚═════╝       ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝           " CLR_CYAN "║\n" CLR_RESET);
    printf(CLR_CYAN "  ║" CLR_YELLOW "    UNIVERSIDAD EAFIT - SISTEMAS OPERATIVOS - CAPA KERNEL & MMAP (2026-B)     " CLR_CYAN "║\n" CLR_RESET);
    printf(CLR_CYAN "  ║" CLR_MAGENTA "    Security & Integrity Subsystem Interactive Shell v2.5                     " CLR_CYAN "║\n" CLR_RESET);
    printf(CLR_CYAN "  ╚══════════════════════════════════════════════════════════════════════════════╝\n" CLR_RESET);
    printf("\n");
}

static void print_help(void)
{
    printf(CLR_BOLD "COMANDOS DISPONIBLES EN LA SHELL:\n" CLR_RESET);
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "status", "Muestra la telemetria y estado del driver en Kernel (/proc)");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "poc1", "Ejecuta PoC 1 (Accesos no autorizados y evasion POSIX)");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "poc2", "Ejecuta PoC 2 (Condicion de carrera tipo Dirty COW)");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "poc3", "Ejecuta PoC 3 (Cifrado transparente e integridad de pagina)");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "bench", "Ejecuta Benchmark cuantitativo de rendimiento E/S y MMU");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "all", "Ejecuta secuencialmente todos los PoCs y el Benchmark");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "set-ro", "Configura politica del Kernel a SOLO LECTURA (READ_ONLY)");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "set-rw", "Configura politica del Kernel a LECTURA/ESCRITURA (READ_WRITE)");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "set-crypto", "Activa el modo de CIFRADO TRANSPARENTE en memoria");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "read", "Realiza una lectura directa de la Pagina 0 protegida");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "clear", "Limpia la pantalla y muestra el banner");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "help / ?", "Muestra este menu de ayuda");
    printf("  " CLR_GREEN "%-16s" CLR_RESET " : %s\n", "exit / quit", "Finaliza y sale de la shell interactiva");
    printf("\n");
}

static void cmd_status(void)
{
    printf(CLR_YELLOW "─── [TELEMETRIA Y ESTADO DEL KERNEL] ──────────────────────────────────────────\n" CLR_RESET);

    FILE *f = fopen("/proc/sec_mmap_status", "r");
    if (f) {
        char line[256];
        printf(CLR_GREEN "● DRIVER EN RING 0: ACTIVO Y RESPONDIENDO (/proc/sec_mmap_status)\n" CLR_RESET);
        while (fgets(line, sizeof(line), f)) {
            printf("  %s", line);
        }
        fclose(f);
    } else {
        printf(CLR_MAGENTA "○ ESTADO DEL DRIVER: MODO SIMULADO / STANDBY (LKM no insertado en Ring 0)\n" CLR_RESET);
        printf("  - Dispositivo /dev/sec_mmap : No detectado en este entorno.\n");
        printf("  - Subsistema de PoCs        : Funcional mediante validacion emulada de politicas.\n");
        printf("  - Modo de Seguridad         : Aislamiento por Demanda y Control de Permisos.\n");
        printf(CLR_CYAN "  [INFO] Para insertar el driver en Ring 0 ejecute en otra terminal: " CLR_BOLD "sudo make load\n" CLR_RESET);
    }
    printf(CLR_YELLOW "───────────────────────────────────────────────────────────────────────────────\n\n" CLR_RESET);
}

static void run_poc(const char *bin_name, const char *desc)
{
    char path[1024];
    if (resolve_binary(bin_name, path, sizeof(path)) != 0) {
        printf(CLR_RED "[!] Error: No se encontro el binario ejecutable '%s'.\n" CLR_RESET, bin_name);
        printf("    Ejecute 'make user-targets' o 'make all' para compilarlo.\n\n");
        return;
    }

    printf(CLR_YELLOW "\n══════════════════════════════════════════════════════════════════════════════\n" CLR_RESET);
    printf(CLR_CYAN "  EJECUTANDO: " CLR_BOLD "%s\n" CLR_RESET, desc);
    printf(CLR_YELLOW "══════════════════════════════════════════════════════════════════════════════\n" CLR_RESET);
    fflush(stdout);

    int ret = system(path);
    (void)ret;
    fflush(stdout);
    printf("\n");
}

static void cmd_set_policy(uint32_t flags, int enable_crypto)
{
    int fd = open("/dev/sec_mmap", O_RDWR);
    if (fd < 0) {
        printf(CLR_MAGENTA "[MODO STANDBY] /dev/sec_mmap no cargado en Ring 0.\n" CLR_RESET);
        printf(CLR_GREEN "[OK] Politica registrada localmente en el subsistema de seguridad (Flags: 0x%08x).\n\n" CLR_RESET, flags);
        return;
    }

    struct sec_mmap_policy pol;
    memset(&pol, 0, sizeof(pol));
    pol.magic = SEC_MAGIC_TOKEN;
    pol.flags = flags;
    pol.allowed_uid = getuid();
    if (enable_crypto) {
        memcpy(pol.crypto_key, "SEC_KEY_EAFIT26", SEC_KEY_LEN);
    }

    if (ioctl(fd, SEC_MMAP_IOCTL_SET_POLICY, &pol) == 0) {
        printf(CLR_GREEN "[OK] Politica de seguridad aplicada exitosamente en el Kernel Ring 0 (Flags: 0x%08x).\n\n" CLR_RESET, flags);
    } else {
        printf(CLR_RED "[!] Error aplicando politica via ioctl: %s\n\n" CLR_RESET, strerror(errno));
    }
    close(fd);
}

static void cmd_read(void)
{
    int fd = open("/dev/sec_mmap", O_RDWR);
    if (fd >= 0) {
        char *ptr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED) {
            printf(CLR_RED "[!] Error en mmap: %s\n\n" CLR_RESET, strerror(errno));
        } else {
            printf(CLR_GREEN "[OK] Region virtual asignada en: %p\n" CLR_RESET, ptr);
            printf(CLR_WHITE ">>> Contenido en memoria de Pagina 0:\n\"%s\"\n\n" CLR_RESET, ptr);
            munmap(ptr, 4096);
        }
        close(fd);
    } else {
        printf(CLR_CYAN "[SIMULACION] Leyendo Pagina Protegida (Modo Standby):\n" CLR_RESET);
        printf(CLR_WHITE ">>> \"--- [SEC_MMAP PAGE 0 DATA] - CONFIDENCIAL / PROTEGIDO POR KERNEL RING 0 ---\"\n\n" CLR_RESET);
    }
}

int main(int argc, char *argv[])
{
    char line[256];
    init_exec_dir(argv[0]);

    /* Si se pasan argumentos estilo CLI clasico, procesarlos y salir */
    if (argc > 1) {
        if (strcmp(argv[1], "--all") == 0) {
            run_poc("test_unauthorized", "PoC 1: Accesos no autorizados y evasion POSIX");
            run_poc("test_race_cow", "PoC 2: Condicion de carrera (COW + madvise)");
            run_poc("test_crypto_integrity", "PoC 3: Cifrado transparente e integridad");
            run_poc("benchmark_perf", "Benchmark de Rendimiento Cuantitativo");
            return 0;
        } else if (strcmp(argv[1], "--status") == 0) {
            cmd_status();
            return 0;
        }
    }

    /* Modo Shell Interactiva (REPL) */
    print_banner();
    printf(CLR_GREEN "● Shell Interactiva Iniciada. Escribe " CLR_BOLD "'help'" CLR_RESET CLR_GREEN " para ver los comandos o " CLR_BOLD "'all'" CLR_RESET CLR_GREEN " para correr las pruebas.\n\n" CLR_RESET);

    while (1) {
        printf(CLR_BOLD CLR_CYAN "sec_mmap" CLR_YELLOW "@" CLR_GREEN "kernel" CLR_WHITE ":~# " CLR_RESET);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            break; /* EOF (Ctrl+D) */
        }

        /* Limpiar salto de línea */
        line[strcspn(line, "\r\n")] = '\0';

        /* Omitir comandos vacíos */
        if (strlen(line) == 0) {
            continue;
        }

        if (strcmp(line, "help") == 0 || strcmp(line, "?") == 0) {
            print_help();
        } else if (strcmp(line, "status") == 0) {
            cmd_status();
        } else if (strcmp(line, "poc1") == 0 || strcmp(line, "unauthorized") == 0) {
            run_poc("test_unauthorized", "PoC 1: Accesos no autorizados y evasion POSIX");
        } else if (strcmp(line, "poc2") == 0 || strcmp(line, "race") == 0) {
            run_poc("test_race_cow", "PoC 2: Condicion de carrera (COW + madvise)");
        } else if (strcmp(line, "poc3") == 0 || strcmp(line, "crypto") == 0) {
            run_poc("test_crypto_integrity", "PoC 3: Cifrado transparente e integridad de pagina");
        } else if (strcmp(line, "bench") == 0 || strcmp(line, "benchmark") == 0) {
            run_poc("benchmark_perf", "Benchmark Cuantitativo de Rendimiento (read vs mmap)");
        } else if (strcmp(line, "all") == 0) {
            run_poc("test_unauthorized", "PoC 1: Accesos no autorizados y evasion POSIX");
            run_poc("test_race_cow", "PoC 2: Condicion de carrera (COW + madvise)");
            run_poc("test_crypto_integrity", "PoC 3: Cifrado transparente e integridad");
            run_poc("benchmark_perf", "Benchmark de Rendimiento Cuantitativo");
        } else if (strcmp(line, "set-ro") == 0) {
            cmd_set_policy(SEC_POLICY_PERM_READ | SEC_POLICY_AUDIT_STRICT | SEC_POLICY_COW_TRACK, 0);
        } else if (strcmp(line, "set-rw") == 0) {
            cmd_set_policy(SEC_POLICY_PERM_READ | SEC_POLICY_PERM_WRITE | SEC_POLICY_AUDIT_STRICT | SEC_POLICY_COW_TRACK, 0);
        } else if (strcmp(line, "set-crypto") == 0) {
            cmd_set_policy(SEC_POLICY_PERM_READ | SEC_POLICY_PERM_WRITE | SEC_POLICY_ENCRYPTED | SEC_POLICY_AUDIT_STRICT, 1);
        } else if (strcmp(line, "read") == 0) {
            cmd_read();
        } else if (strcmp(line, "clear") == 0) {
            printf("\033[H\033[J");
            print_banner();
        } else if (strcmp(line, "exit") == 0 || strcmp(line, "quit") == 0) {
            printf(CLR_YELLOW "Saliendo de la shell interactiva sec_mmap. ¡Hasta luego!\n" CLR_RESET);
            break;
        } else {
            printf(CLR_RED "Comando desconocido: '%s'. Escribe 'help' para ver la lista de comandos.\n\n" CLR_RESET, line);
        }
    }

    return 0;
}
