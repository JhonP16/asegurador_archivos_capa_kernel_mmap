/**
 * @file mmap_audit.bpf.c
 * @brief Programa eBPF para Auditoria de Alta Velocidad sobre mmap() en Ring 0
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Intercepta la llamada al sistema sys_enter_mmap mediante tracepoints
 * del kernel, extrayendo argumentos criticos (direccion virtual, tamano,
 * proteccion PROT_*, banderas MAP_*, PID, UID y nombre del binario).
 * Emite telemetria estructurada hacia un Ring Buffer sin modificar el kernel.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16

struct mmap_event {
    __u32 pid;
    __u32 uid;
    __u64 addr;
    __u64 len;
    __u32 prot;
    __u32 flags;
    char comm[TASK_COMM_LEN];
};

/* BPF Ring Buffer para comunicacion de ultra-baja latencia con espacio de usuario */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); /* 256 KB */
} audit_ringbuf SEC(".maps");

/* Estructura del tracepoint sys_enter_mmap */
struct sys_enter_mmap_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    long syscall_nr;
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long off;
};

SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_sys_enter_mmap(struct sys_enter_mmap_args *ctx)
{
    struct mmap_event *e;
    __u64 id = bpf_get_current_pid_tgid();
    __u32 pid = id >> 32;
    __u32 uid = bpf_get_current_uid_gid();

    e = bpf_ringbuf_reserve(&audit_ringbuf, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = pid;
    e->uid = uid;
    e->addr = ctx->addr;
    e->len = ctx->len;
    e->prot = (__u32)ctx->prot;
    e->flags = (__u32)ctx->flags;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

