/**
 * @file mmap_audit_user.c
 * @brief Cargador y Consumidor de Eventos eBPF en Espacio de Usuario
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Carga el programa mmap_audit.bpf.o en el núcleo de Linux, se engancha
 * al tracepoint sys_enter_mmap y consume registros en tiempo real del Ring Buffer.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define TASK_COMM_LEN 16

struct mmap_event {
    uint32_t pid;
    uint32_t uid;
    uint64_t addr;
    uint64_t len;
    uint32_t prot;
    uint32_t flags;
    char comm[TASK_COMM_LEN];
};

static volatile sig_atomic_t stop = 0;

static void sig_handler(int sig)
{
    (void)sig;
    stop = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct mmap_event *e = data;
    (void)ctx;
    (void)data_sz;

    printf("[eBPF AUDIT] PID: %-6u | UID: %-4u | Comm: %-14s | Addr: 0x%012lx | Len: %-8lu | Prot: 0x%x | Flags: 0x%x\n",
           e->pid, e->uid, e->comm, (unsigned long)e->addr, (unsigned long)e->len, e->prot, e->flags);
    return 0;
}

int main(int argc, char *argv[])
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct ring_buffer *rb = NULL;
    int map_fd;
    const char *bpf_file = "mmap_audit.bpf.o";

    (void)argc;
    (void)argv;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("====================================================================\n");
    printf(" MONITOR DE SEGURIDAD Y AUDITORIA eBPF PARA MMAP() (Ring 0)\n");
    printf("====================================================================\n");

    /* 1. Abrir y cargar el objeto BPF */
    obj = bpf_object__open_file(bpf_file, NULL);
    if (!obj) {
        fprintf(stderr, "[ERROR] No se pudo abrir objeto BPF '%s': %s\n", bpf_file, strerror(errno));
        printf("[INFO] Verifique si mmap_audit.bpf.o fue compilado con clang.\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "[ERROR] Fallo al cargar objeto BPF en el kernel: %s\n", strerror(errno));
        printf("[INFO] Nota: Requiere capacidades CAP_BPF / CAP_SYS_ADMIN (sudo).\n");
        bpf_object__close(obj);
        return 1;
    }

    /* 2. Enganchar al tracepoint */
    prog = bpf_object__find_program_by_name(obj, "trace_sys_enter_mmap");
    if (!prog) {
        fprintf(stderr, "[ERROR] No se encontro el programa BPF trace_sys_enter_mmap\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "[ERROR] Fallo al enganchar BPF link: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

    /* 3. Configurar Ring Buffer */
    map_fd = bpf_object__find_map_fd_by_name(obj, "audit_ringbuf");
    if (map_fd < 0) {
        fprintf(stderr, "[ERROR] No se encontro el mapa audit_ringbuf\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[ERROR] Fallo al inicializar BPF ring buffer\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    printf("[INFO] eBPF cargado y monitoreando syscalls mmap en tiempo real.\n");
    printf("[INFO] Presione Ctrl+C para finalizar la captura...\n\n");

    while (!stop) {
        int err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error leyendo ring buffer: %d\n", err);
            break;
        }
    }

    printf("\n[INFO] Cerrando monitor eBPF...\n");
    ring_buffer__free(rb);
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}

