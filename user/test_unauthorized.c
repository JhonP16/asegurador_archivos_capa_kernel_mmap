/**
 * @file test_unauthorized.c
 * @brief PoC: Prueba de Acceso No Autorizado y Evasión de Permisos POSIX
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Esta prueba evalúa dos vectores de ataque comunes en mmap():
 * 1. Intento de mapeo con PROT_WRITE sobre un archivo configurado como READ_ONLY
 *    en la política de seguridad del Kernel.
 * 2. Evasión de permisos POSIX (abrir con O_RDONLY y solicitar PROT_WRITE con MAP_PRIVATE).
 * 
 * Demuestra cómo la capa de Kernel intercepta la solicitud en Ring 0 (mmap hook)
 * o en el primer intento de escritura (page_mkwrite), denegando la acción con -EACCES
 * o disparando SIGBUS/SIGSEGV sin comprometer los datos subyacentes.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#include <setjmp.h>

#include "../kernel/sec_mmap_core.h"

static sigjmp_buf jump_env;
static volatile sig_atomic_t caught_signal = 0;

static void sigbus_handler(int sig, siginfo_t *info, void *ctx)
{
    (void)info;
    (void)ctx;
    caught_signal = sig;
    siglongjmp(jump_env, 1);
}

int main(int argc, char *argv[])
{
    int fd;
    const char *dev_path = (argc > 1) ? argv[1] : "/dev/sec_mmap";
    struct sec_mmap_policy pol;
    struct sec_mmap_stats stats;
    char *addr;
    struct sigaction sa;

    printf("====================================================================\n");
    printf("[PoC 1] VALIDACION DE ACCESOS NO AUTORIZADOS Y EVASION POSIX\n");
    printf("====================================================================\n");

    /* Configurar manejador de SIGBUS / SIGSEGV */
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigbus_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);

    fd = open(dev_path, O_RDWR);
    if (fd < 0) {
        printf("[INFO] Dispositivo de kernel '%s' no disponible (%s).\n", dev_path, strerror(errno));
        printf("[INFO] Ejecutando validacion teorica y simulacion controlada de evasion...\n");

        /* Simulacion de archivo real en disco con permisos de solo lectura */
        char tmpfile[] = "/tmp/sec_test_ro_XXXXXX";
        int tfd = mkstemp(tmpfile);
        if (tfd < 0) {
            perror("mkstemp");
            return 1;
        }
        if (write(tfd, "DATOS_CONFIDENCIALES_KERNEL_READ_ONLY\n", 38) < 0) {
            perror("write");
        }
        close(tfd);
        chmod(tmpfile, 0400); /* Solo lectura para todos */

        /* Prueba de evasion POSIX */
        int ro_fd = open(tmpfile, O_RDONLY);
        printf("[TEST 1.1] Abriendo archivo sensible con O_RDONLY (fd=%d)...\n", ro_fd);

        printf("[TEST 1.2] Intentando mmap(PROT_READ | PROT_WRITE, MAP_SHARED)...\n");
        addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, ro_fd, 0);
        if (addr == MAP_FAILED) {
            printf("  ===> RESULTADO: Kernel BLOQUEO el mapeo exitosamente (%s). [OK]\n", strerror(errno));
        } else {
            printf("  ===> ALERTA: Kernel permitio MAP_SHARED con PROT_WRITE sobre O_RDONLY!\n");
            munmap(addr, 4096);
        }

        printf("[TEST 1.3] Evaluando vector de evasion mmap(PROT_READ | PROT_WRITE, MAP_PRIVATE)...\n");
        addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, ro_fd, 0);
        if (addr != MAP_FAILED) {
            printf("  ===> OBSERVACION ARQUITECTONICA: POSIX permite mmap privado con PROT_WRITE\n");
            printf("       sobre descriptores O_RDONLY. Esto crea una copia privada en RAM (COW).\n");
            printf("       Escribiendo sobre la region virtual mapeada privada...\n");

            if (sigsetjmp(jump_env, 1) == 0) {
                addr[0] = 'X';
                printf("  ===> Modificacion en espacio de usuario completada (direccion: %p).\n", addr);
            }

            /* Verificar si el archivo en disco fue afectado */
            char check_buf[40] = {0};
            lseek(ro_fd, 0, SEEK_SET);
            if (read(ro_fd, check_buf, 38) < 0) {
                perror("read");
            }
            printf("  ===> Contenido real del archivo en disco: '%s'", check_buf);
            if (check_buf[0] != 'X') {
                printf("  ===> DEFENSA EFECTIVA: El archivo base en disco permaneceu INTACTO!\n");
                printf("       La modificacion solo afecto la copia COW privada local.\n");
            } else {
                printf("  ===> FALLA CRITICA: El archivo base en disco fue SOBRESCRITO!\n");
            }
            munmap(addr, 4096);
        }
        close(ro_fd);
        unlink(tmpfile);
        return 0;
    }

    /* Caso con Modulo de Kernel /dev/sec_mmap activo */
    printf("[INFO] Dispositivo /dev/sec_mmap detectado en Ring 0. Verificando politicas...\n");

    /* 1. Configurar politica estricta de SOLO LECTURA para UID 1000 */
    memset(&pol, 0, sizeof(pol));
    pol.magic = SEC_MAGIC_TOKEN;
    pol.flags = SEC_POLICY_PERM_READ | SEC_POLICY_AUDIT_STRICT;
    pol.allowed_uid = getuid();
    if (ioctl(fd, SEC_MMAP_IOCTL_SET_POLICY, &pol) < 0) {
        perror("ioctl(SET_POLICY)");
    } else {
        printf("[CONFIG] Politica fijada: READ_ONLY para UID %u.\n", pol.allowed_uid);
    }

    /* 2. Intentar mmap con PROT_WRITE (Debe ser rechazado por el driver en mmap) */
    printf("[TEST 2.1] Solicitando mmap(PROT_READ | PROT_WRITE, MAP_SHARED)...\n");
    addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        printf("  ===> RESULTADO: Intercepcion de Kernel exitosa: %s. [BLOQUEADO]\n", strerror(errno));
    } else {
        printf("  ===> ADVERTENCIA: mmap write no fue bloqueado en alta de VMA.\n");
        munmap(addr, 4096);
    }

    /* 3. Mapear en modo lectura legitima */
    printf("[TEST 2.2] Solicitando mmap legitimo con PROT_READ...\n");
    addr = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap PROT_READ");
        close(fd);
        return 1;
    }
    printf("  ===> Region mapeada en: %p. Leyendo primer byte: '%c'\n", addr, addr[0]);

    /* 4. Intentar forzar escritura sobre pagina protegida */
    printf("[TEST 2.3] Intentando violar proteccion con mprotect(PROT_WRITE) y escribir...\n");
    if (mprotect(addr, 4096, PROT_READ | PROT_WRITE) == 0) {
        if (sigsetjmp(jump_env, 1) == 0) {
            addr[0] = 'H'; /* Debe disparar page_mkwrite en kernel y generar SIGBUS */
            printf("  ===> Escritura permitida sin intervencion.\n");
        } else {
            printf("  ===> EXCEPCION DE HARDWARE CAPTURADA: Senal %d (%s) disparada por el Kernel!\n",
                   caught_signal, (caught_signal == SIGBUS) ? "SIGBUS" : "SIGSEGV");
            printf("  ===> DEFENSA EXITOSA: El controlador page_mkwrite del LKM bloqueo la escritura.\n");
        }
    } else {
        printf("  ===> mprotect denegado por el Kernel: %s\n", strerror(errno));
    }

    munmap(addr, 4096);

    /* Consultar estadisticas de violaciones en el driver */
    if (ioctl(fd, SEC_MMAP_IOCTL_GET_STATS, &stats) == 0) {
        printf("--------------------------------------------------------------------\n");
        printf("[TELEMETRIA KERNEL] Intentos Bloqueados : %lu\n", (unsigned long)stats.blocked_unauthorized);
        printf("[TELEMETRIA KERNEL] Fallos de Lectura   : %lu\n", (unsigned long)stats.read_faults);
        printf("[TELEMETRIA KERNEL] Fallos de Escritura : %lu\n", (unsigned long)stats.write_faults);
        printf("[TELEMETRIA KERNEL] Violaciones Total   : %lu\n", (unsigned long)stats.integrity_violations);
        printf("--------------------------------------------------------------------\n");
    }

    close(fd);
    printf("[PoC 1] Prueba de seguridad finalizada satisfactoriamente.\n");
    return 0;
}

