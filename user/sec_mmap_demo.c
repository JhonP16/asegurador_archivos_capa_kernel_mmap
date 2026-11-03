/**
 * @file sec_mmap_demo.c
 * @brief Shell Interactiva y Demostrador de Seguridad en Kernel para sec_mmap (v3.0)
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Implementa una consola interactiva real (REPL) donde el control de acceso
 * y la protección de memoria se validan en tiempo real sobre la MMU mediante:
 * - mmap() y mprotect() reales modificando bits PTE (_PAGE_RW)
 * - Captura de excepciones de hardware (#PF / SIGSEGV / SEGV_ACCERR)
 * - Comandos interactivos read, write <texto>, set-ro, set-rw, set-crypto
 * - Resolución dinámica de binarios para PoC 1, 2, 3 y Benchmark
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
#include <signal.h>
#include <setjmp.h>
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

/* Búfer de memoria virtual real mapeado con la MMU */
static char *g_mapped_page = NULL;
static int g_current_policy = 1; /* 1: READ_ONLY, 2: READ_WRITE */
static int g_is_encrypted = 0;
static const char g_crypto_key[16] = "KEY_EAFIT_2026B";

/* Contexto para captura de fallos de protección de hardware */
static sigjmp_buf g_jump_env;
static volatile sig_atomic_t g_caught_signal = 0;
static volatile sig_atomic_t g_signal_code = 0;
static volatile void *g_fault_address = NULL;

/**
 * Manejador de señales de hardware: Captura SIGSEGV / SIGBUS cuando la CPU
 * intenta escribir en una página con bit de hardware R/W = 0.
 */
static void sig_mmu_handler(int sig, siginfo_t *info, void *ctx)
{
    (void)ctx;
    g_caught_signal = sig;
    g_signal_code = info->si_code;
    g_fault_address = info->si_addr;
    siglongjmp(g_jump_env, 1);
}

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

static int resolve_binary(const char *name, char *out_path, size_t out_sz)
{
    snprintf(out_path, out_sz, "%s/%s", g_exec_dir, name);
    if (access(out_path, X_OK) == 0) return 0;

    snprintf(out_path, out_sz, "./user/%s", name);
    if (access(out_path, X_OK) == 0) return 0;

    snprintf(out_path, out_sz, "./%s", name);
    if (access(out_path, X_OK) == 0) return 0;

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
    printf(CLR_CYAN "  ║" CLR_MAGENTA "    Security & Integrity Subsystem Interactive Shell v3.0                     " CLR_CYAN "║\n" CLR_RESET);
    printf(CLR_CYAN "  ╚══════════════════════════════════════════════════════════════════════════════╝\n" CLR_RESET);
    printf("\n");
}

static void print_help(void)
{
    printf(CLR_BOLD "COMANDOS DISPONIBLES EN LA SHELL:\n" CLR_RESET);
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "status", "Muestra estado de políticas, memoria virtual y telemetría");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "set-ro", "Aplica política SOLO LECTURA (mprotect PROT_READ en la MMU)");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "set-rw", "Aplica política LECTURA/ESCRITURA (mprotect PROT_WRITE)");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "read", "Lee e inspecciona el contenido real de la página en RAM");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "write <texto>", "Intenta modificar en caliente la memoria protegida");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "set-crypto", "Cifra en caliente los datos de la página física en RAM");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "decrypt", "Descifra en caliente los datos protegidos");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "poc1", "Ejecuta PoC 1: Accesos no autorizados y evasión POSIX");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "poc2", "Ejecuta PoC 2: Condición de carrera tipo Dirty COW");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "poc3", "Ejecuta PoC 3: Cifrado transparente e integridad de página");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "bench", "Ejecuta Benchmark cuantitativo de rendimiento E/S y MMU");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "all", "Ejecuta secuencialmente todos los PoCs y el Benchmark");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "clear", "Limpia la pantalla y muestra el banner principal");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "help / ?", "Muestra este menú de ayuda");
    printf("  " CLR_GREEN "%-18s" CLR_RESET " : %s\n", "exit / quit", "Finaliza y sale de la shell interactiva");
    printf("\n");
}

static void cmd_status(void)
{
    printf(CLR_YELLOW "─── [ESTADO ACTUAL DEL SUBSISTEMA DE MEMORIA Y KERNEL] ────────────────────────\n" CLR_RESET);

    FILE *f = fopen("/proc/sec_mmap_status", "r");
    if (f) {
        char line[256];
        printf(CLR_GREEN "● MÓDULO LKM RING 0 : ACTIVO (/proc/sec_mmap_status detectado)\n" CLR_RESET);
        while (fgets(line, sizeof(line), f)) {
            printf("  %s", line);
        }
        fclose(f);
    } else {
        printf(CLR_MAGENTA "○ MÓDULO LKM RING 0 : MODO STANDBY / EMULADO EN HARDWARE MMU\n" CLR_RESET);
        printf("  - Dispositivo Kernel  : /dev/sec_mmap en espera.\n");
        printf("  - Protección MMU      : Activa en espacio de direcciones del proceso.\n");
    }

    printf(CLR_CYAN "--- CONFIGURACIÓN DE POLÍTICA EN VIVO ---\n" CLR_RESET);
    printf("  - Dirección Virtual   : %p (Página de 4096 bytes)\n", (void *)g_mapped_page);
    printf("  - Permiso Actual MMU  : %s\n",
           (g_current_policy == 1) ? CLR_RED "SOLO LECTURA (PROT_READ / R/W=0)" CLR_RESET :
                                     CLR_GREEN "LECTURA Y ESCRITURA (PROT_READ|PROT_WRITE / R/W=1)" CLR_RESET);
    printf("  - Estado Criptográfico: %s\n",
           g_is_encrypted ? CLR_YELLOW "CIFRADO ACTIVO (Datos ofuscados en RAM)" CLR_RESET :
                            CLR_WHITE "TEXTO PLANO (Descifrado)" CLR_RESET);
    printf(CLR_YELLOW "───────────────────────────────────────────────────────────────────────────────\n\n" CLR_RESET);
}

/**
 * Establece la política de solo lectura aplicando mprotect() en el kernel.
 */
static void cmd_set_ro(void)
{
    if (mprotect(g_mapped_page, 4096, PROT_READ) != 0) {
        printf(CLR_RED "[!] Error llamando a mprotect(PROT_READ): %s\n\n" CLR_RESET, strerror(errno));
        return;
    }
    g_current_policy = 1;

    /* Sincronizar con el driver si existe */
    int fd = open("/dev/sec_mmap", O_RDWR);
    if (fd >= 0) {
        struct sec_mmap_policy pol;
        memset(&pol, 0, sizeof(pol));
        pol.magic = SEC_MAGIC_TOKEN;
        pol.flags = SEC_POLICY_PERM_READ | SEC_POLICY_AUDIT_STRICT | SEC_POLICY_COW_TRACK;
        pol.allowed_uid = getuid();
        ioctl(fd, SEC_MMAP_IOCTL_SET_POLICY, &pol);
        close(fd);
    }

    printf(CLR_GREEN "✔ POLÍTICA APLICADA: MODO SOLO LECTURA (READ_ONLY)\n" CLR_RESET);
    printf("  - La llamada mprotect() forzó la entrada PTE en la MMU a: " CLR_RED "R/W = 0 (Solo Lectura)" CLR_RESET ".\n");
    printf("  - Ahora cualquier intento de escribir disparará una " CLR_BOLD "Excepción de Protección de CPU (#PF)" CLR_RESET ".\n");
    printf("  - Prueba escribir ahora con: " CLR_YELLOW "write HACK_TEST\n\n" CLR_RESET);
}

/**
 * Establece la política de lectura y escritura aplicando mprotect().
 */
static void cmd_set_rw(void)
{
    if (mprotect(g_mapped_page, 4096, PROT_READ | PROT_WRITE) != 0) {
        printf(CLR_RED "[!] Error llamando a mprotect(PROT_READ|PROT_WRITE): %s\n\n" CLR_RESET, strerror(errno));
        return;
    }
    g_current_policy = 2;

    /* Sincronizar con el driver si existe */
    int fd = open("/dev/sec_mmap", O_RDWR);
    if (fd >= 0) {
        struct sec_mmap_policy pol;
        memset(&pol, 0, sizeof(pol));
        pol.magic = SEC_MAGIC_TOKEN;
        pol.flags = SEC_POLICY_PERM_READ | SEC_POLICY_PERM_WRITE | SEC_POLICY_AUDIT_STRICT | SEC_POLICY_COW_TRACK;
        pol.allowed_uid = getuid();
        ioctl(fd, SEC_MMAP_IOCTL_SET_POLICY, &pol);
        close(fd);
    }

    printf(CLR_GREEN "✔ POLÍTICA APLICADA: MODO LECTURA Y ESCRITURA (READ_WRITE)\n" CLR_RESET);
    printf("  - La llamada mprotect() activó el bit en la MMU a: " CLR_GREEN "R/W = 1 (Escritura Habilitada)" CLR_RESET ".\n");
    printf("  - Las escrituras en memoria están ahora autorizadas.\n");
    printf("  - Prueba escribir con: " CLR_YELLOW "write DATOS_NUEVOS_AUTORIZADOS\n\n" CLR_RESET);
}

/**
 * Lee el contenido real de la página física y muestra un volcado hexadecimal.
 */
static void cmd_read(void)
{
    printf(CLR_CYAN "─── [LECTURA DIRECTA DE MEMORIA EN %p] ──────────────────────────\n" CLR_RESET, (void *)g_mapped_page);
    printf(CLR_BOLD "Contenido en Texto: " CLR_RESET);
    if (g_is_encrypted) {
        printf(CLR_YELLOW "[DATOS CIFRADOS EN RAM - ILEGIBLES]" CLR_RESET "\n");
    } else {
        printf(CLR_WHITE "\"%s\"" CLR_RESET "\n", g_mapped_page);
    }

    printf(CLR_BOLD "\nVolcado Hexadecimal (Primeros 48 bytes):\n" CLR_RESET);
    for (int i = 0; i < 48; i++) {
        printf("%02x ", (uint8_t)g_mapped_page[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf(CLR_CYAN "───────────────────────────────────────────────────────────────────────────────\n\n" CLR_RESET);
}

/**
 * Intenta escribir en la página mapeada. Si la política es READ_ONLY,
 * la CPU disparará un fallo de hardware que atrapamos con siglongjmp.
 */
static void cmd_write(const char *text)
{
    if (!text || strlen(text) == 0) {
        printf(CLR_RED "Uso: write <texto_a_escribir>\nEjemplo: write MI_NUEVO_DATO_2026\n\n" CLR_RESET);
        return;
    }

    printf("[INTENTO] Intentando escribir \"%s\" en direccion virtual %p...\n", text, (void *)g_mapped_page);

    /* Punto de retorno ante excepción de hardware (#PF / SIGSEGV) */
    g_caught_signal = 0;
    if (sigsetjmp(g_jump_env, 1) == 0) {
        /* Intento real de modificación mediante instrucción CPU directa */
        strncpy(g_mapped_page, text, 4095);
        g_mapped_page[4095] = '\0';
        g_is_encrypted = 0;

        printf(CLR_GREEN "✔ [OPERACIÓN AUTORIZADA]: La escritura se ejecutó con ÉXITO!\n" CLR_RESET);
        printf("  - La política actual (READ_WRITE) permitió modificar la memoria.\n");
        printf("  - Comprueba el nuevo valor escribiendo el comando: " CLR_YELLOW "read\n\n" CLR_RESET);
    } else {
        /* Excepción capturada desde la MMU */
        printf("\n" CLR_RED "╔══════════════════════════════════════════════════════════════════════════════╗\n" CLR_RESET);
        printf(CLR_RED "║  ¡VIOLACIÓN DE PROTECCIÓN DE MEMORIA INTERCEPTADA POR EL SISTEMA!            ║\n" CLR_RESET);
        printf(CLR_RED "╚══════════════════════════════════════════════════════════════════════════════╝\n" CLR_RESET);
        printf(CLR_YELLOW "  ● Excepción de CPU Disparada: Señal %d (%s)\n" CLR_RESET,
               g_caught_signal, (g_caught_signal == SIGSEGV) ? "SIGSEGV (Fallo de Segmentación)" : "SIGBUS");
        printf(CLR_YELLOW "  ● Código de Causa           : SEGV_ACCERR (Permisos de acceso inválidos en la MMU)\n" CLR_RESET);
        printf(CLR_YELLOW "  ● Dirección Bloqueada       : %p\n" CLR_RESET, g_fault_address);
        printf(CLR_WHITE "  ● Explicación Técnica       : La entrada PTE tenía el bit de hardware R/W = 0.\n"
                         "                                La instrucción de escritura fue ABORTADA por el procesador.\n" CLR_RESET);
        printf(CLR_GREEN "✔ DEFENSA DEMOSTRADA: La memoria permanece INTACTA y protegida contra escritura.\n" CLR_RESET);
        printf("  - Escribe " CLR_YELLOW "read" CLR_RESET " para comprobar que los datos originales siguen intactos.\n");
        printf("  - Escribe " CLR_YELLOW "set-rw" CLR_RESET " si deseas autorizar la escritura y volver a probar.\n\n");
    }
}

/**
 * Cifra la página en caliente para demostrar confidencialidad en RAM.
 */
static void cmd_set_crypto(void)
{
    /* Si estaba en modo solo lectura, desbloquear temporalmente para cifrar */
    int prev_policy = g_current_policy;
    if (g_current_policy == 1) {
        mprotect(g_mapped_page, 4096, PROT_READ | PROT_WRITE);
    }

    if (!g_is_encrypted) {
        for (int i = 0; i < 4096; i++) {
            g_mapped_page[i] ^= g_crypto_key[i % sizeof(g_crypto_key)];
        }
        g_is_encrypted = 1;
        printf(CLR_YELLOW "✔ CIFRADO EN CALIENTE APLICADO A LA PÁGINA FÍSICA EN RAM.\n" CLR_RESET);
        printf("  - Todos los bytes en memoria ahora residen como " CLR_BOLD "Ciphertext (Texto Cifrado)" CLR_RESET ".\n");
        printf("  - Escribe " CLR_YELLOW "read" CLR_RESET " para ver cómo se ve la memoria cifrada.\n");
        printf("  - Escribe " CLR_YELLOW "decrypt" CLR_RESET " para descifrarla nuevamente.\n\n");
    } else {
        printf(CLR_MAGENTA "[INFO] La memoria ya se encuentra en estado cifrado.\n\n" CLR_RESET);
    }

    /* Restaurar permiso original */
    if (prev_policy == 1) {
        mprotect(g_mapped_page, 4096, PROT_READ);
    }
}

/**
 * Descifra la página en caliente.
 */
static void cmd_decrypt(void)
{
    if (g_is_encrypted) {
        int prev_policy = g_current_policy;
        if (g_current_policy == 1) {
            mprotect(g_mapped_page, 4096, PROT_READ | PROT_WRITE);
        }

        for (int i = 0; i < 4096; i++) {
            g_mapped_page[i] ^= g_crypto_key[i % sizeof(g_crypto_key)];
        }
        g_is_encrypted = 0;
        printf(CLR_GREEN "✔ DESCIFRADO EXITOSO: La página ha vuelto a su estado original legible.\n" CLR_RESET);
        printf("  - Escribe " CLR_YELLOW "read" CLR_RESET " para verificar el texto recuperado.\n\n");

        if (prev_policy == 1) {
            mprotect(g_mapped_page, 4096, PROT_READ);
        }
    } else {
        printf(CLR_WHITE "[INFO] La memoria ya está en texto plano descifrado.\n\n" CLR_RESET);
    }
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

int main(int argc, char *argv[])
{
    char line[512];
    init_exec_dir(argv[0]);

    /* 1. Configurar manejador de señales para excepciones de la MMU */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sig_mmu_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    /* 2. Asignar página de memoria virtual real con la MMU */
    g_mapped_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (g_mapped_page == MAP_FAILED) {
        perror("mmap inicial");
        return 1;
    }

    /* Inicializar con contenido de prueba */
    strncpy(g_mapped_page, "--- [PAGINA PROTEGIDA EN KERNEL: CONFIDENCIAL EAFIT 2026-B] ---", 4095);

    /* Configurar inicialmente en SOLO LECTURA */
    mprotect(g_mapped_page, 4096, PROT_READ);
    g_current_policy = 1;

    /* Modo CLI batch si se pasan argumentos */
    if (argc > 1) {
        if (strcmp(argv[1], "--all") == 0) {
            run_poc("test_unauthorized", "PoC 1: Accesos no autorizados y evasion POSIX");
            run_poc("test_race_cow", "PoC 2: Condicion de carrera (COW + madvise)");
            run_poc("test_crypto_integrity", "PoC 3: Cifrado transparente e integridad");
            run_poc("benchmark_perf", "Benchmark de Rendimiento Cuantitativo");
            munmap(g_mapped_page, 4096);
            return 0;
        } else if (strcmp(argv[1], "--status") == 0) {
            cmd_status();
            munmap(g_mapped_page, 4096);
            return 0;
        }
    }

    /* Modo Shell Interactiva */
    print_banner();
    printf(CLR_GREEN "● Shell Interactiva v3.0 Iniciada con Protección MMU en vivo.\n" CLR_RESET);
    printf("  Página mapeada en " CLR_BOLD "%p" CLR_RESET ". Política inicial: " CLR_RED "SOLO LECTURA\n\n" CLR_RESET, (void *)g_mapped_page);

    while (1) {
        printf(CLR_BOLD CLR_CYAN "sec_mmap" CLR_YELLOW "@" CLR_GREEN "kernel" CLR_WHITE ":~# " CLR_RESET);
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            break; /* EOF (Ctrl+D) */
        }

        line[strcspn(line, "\r\n")] = '\0';
        if (strlen(line) == 0) continue;

        if (strcmp(line, "help") == 0 || strcmp(line, "?") == 0) {
            print_help();
        } else if (strcmp(line, "status") == 0) {
            cmd_status();
        } else if (strcmp(line, "set-ro") == 0) {
            cmd_set_ro();
        } else if (strcmp(line, "set-rw") == 0) {
            cmd_set_rw();
        } else if (strcmp(line, "read") == 0) {
            cmd_read();
        } else if (strncmp(line, "write ", 6) == 0) {
            cmd_write(line + 6);
        } else if (strcmp(line, "write") == 0) {
            printf(CLR_RED "Uso: write <texto>\nEjemplo: write HACK_INTENTO_1\n\n" CLR_RESET);
        } else if (strcmp(line, "set-crypto") == 0) {
            cmd_set_crypto();
        } else if (strcmp(line, "decrypt") == 0) {
            cmd_decrypt();
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

    munmap(g_mapped_page, 4096);
    return 0;
}
