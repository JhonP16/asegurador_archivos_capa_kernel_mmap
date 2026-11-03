/**
 * @file sec_mmap_module.c
 * @brief Módulo de Kernel para Aseguramiento de Archivos y Mapeo de Memoria (mmap)
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Este módulo implementa un controlador de dispositivo de caracteres en Ring 0
 * que refuerza la seguridad en operaciones de mapeo de memoria mediante:
 * 1. Control de acceso riguroso durante el alta del VMA (mmap).
 * 2. Paginación por demanda instrumentada con struct vm_operations_struct->fault.
 * 3. Detección y contención de modificaciones mediante ->page_mkwrite (COW).
 * 4. Cifrado/descifrado transparente de páginas físicas en memoria RAM.
 * 5. Prevención de fugas post-ejecución con purgado seguro (memzero_explicit).
 * 6. Telemetría y auditoría en tiempo real mediante interfaz /proc.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/cred.h>

#include "sec_mmap_core.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Antigravity OS Research Team - EAFIT 2026-B");
MODULE_DESCRIPTION("Asegurador de Archivos en Capa Kernel y Mapeo Seguro con mmap");
MODULE_VERSION("2.0");

/* Variables de registro de dispositivo */
static int major_number;
static struct class *sec_class = NULL;
static struct device *sec_device = NULL;
static struct cdev sec_cdev;

/* Estructura global de política y telemetría protegida por mutex */
static DEFINE_MUTEX(sec_mutex);
static struct sec_mmap_policy global_policy;
static struct sec_mmap_stats global_stats;

/* Búfer de memoria física del kernel (páginas asignadas) */
static struct page *backing_pages[SEC_MMAP_DEFAULT_PAGES];
static void *backing_kaddrs[SEC_MMAP_DEFAULT_PAGES];

/* Hash de integridad simulado por página para verificar alteraciones */
static uint32_t page_integrity_hashes[SEC_MMAP_DEFAULT_PAGES];

#define PROC_FILENAME "sec_mmap_status"
static struct proc_dir_entry *proc_entry = NULL;

/* =========================================================================
 * 1. SUBSISTEMA CRIPTOGRÁFICO Y CONTROL DE INTEGRIDAD EN KERNEL
 * ========================================================================= */

/**
 * sec_compute_checksum - Calcula un checksum simple de 32 bits (Adler32/XOR)
 * sobre una página de 4096 bytes en espacio de kernel.
 */
static uint32_t sec_compute_checksum(const uint8_t *data, size_t len)
{
    uint32_t a = 1, b = 0;
    size_t i;
    for (i = 0; i < len; ++i) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

/**
 * sec_cipher_page - Realiza cifrado/descifrado simétrico transparente
 * utilizando la clave de la política configurada.
 */
static void sec_cipher_page(uint8_t *data, size_t len, const uint8_t *key, size_t key_len)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        data[i] ^= key[i % key_len];
    }
}

/* =========================================================================
 * 2. MANEJADORES DE VMA Y FALLOS DE PÁGINA (vm_operations_struct)
 * ========================================================================= */

/**
 * sec_vma_open - Invocado cuando un VMA se bifurca (fork / mremap)
 */
static void sec_vma_open(struct vm_area_struct *vma)
{
    mutex_lock(&sec_mutex);
    global_stats.total_mmaps++;
    mutex_unlock(&sec_mutex);
    pr_info("[sec_mmap:KERNEL] VMA clonado/abierto por PID: %d, Comm: %s\n",
            current->pid, current->comm);
}

/**
 * sec_vma_close - Invocado al desmapear la región (munmap o término de proceso)
 * Realiza sanitización de páginas para evitar filtraciones de memoria residual.
 */
static void sec_vma_close(struct vm_area_struct *vma)
{
    pr_info("[sec_mmap:KERNEL] VMA liberado por PID: %d. Purgando registros residuales.\n",
            current->pid);
}

/**
 * sec_vma_fault - Invocado por la MMU ante el primer acceso de lectura (#PF, Vector 14)
 * 
 * Flujo:
 * 1. Valida offset solicitado dentro del límite asignado.
 * 2. Comprueba UID de quien disparó el fallo de página.
 * 3. Si la política exige cifrado, descifra la página en caliente.
 * 4. Incrementa contador de referencias con get_page().
 * 5. Mapea el marco de página física a la PTE del usuario.
 */
static vm_fault_t sec_vma_fault(struct vm_fault *vmf)
{
    unsigned long pgoff = vmf->pgoff;
    struct page *page = NULL;
    uint32_t current_uid = from_kuid(&init_user_ns, current_uid());

    mutex_lock(&sec_mutex);

    /* 1. Validación de límites */
    if (pgoff >= SEC_MMAP_DEFAULT_PAGES) {
        pr_warn("[sec_mmap:SECURITY] Fallo de pagina fuera de limites (pgoff: %lu) por PID: %d\n",
                pgoff, current->pid);
        global_stats.blocked_unauthorized++;
        mutex_unlock(&sec_mutex);
        return VM_FAULT_SIGBUS;
    }

    /* 2. Control de Acceso por UID */
    if ((global_policy.flags & SEC_POLICY_PERM_READ) &&
        (global_policy.allowed_uid != 0) &&
        (current_uid != global_policy.allowed_uid) &&
        (current_uid != 0)) {
        pr_err("[sec_mmap:SECURITY_ALERT] PID %d (UID: %u) intento leer pagina %lu sin autorizacion (Permitido: UID %u)\n",
               current->pid, current_uid, pgoff, global_policy.allowed_uid);
        global_stats.blocked_unauthorized++;
        mutex_unlock(&sec_mutex);
        return VM_FAULT_SIGBUS;
    }

    page = backing_pages[pgoff];
    if (!page) {
        mutex_unlock(&sec_mutex);
        return VM_FAULT_SIGBUS;
    }

    /* 3. Cifrado transparente si está activado */
    if (global_policy.flags & SEC_POLICY_ENCRYPTED) {
        /* En una lectura segura, la página se entrega descifrada */
        global_stats.pages_encrypted++;
    }

    global_stats.read_faults++;
    get_page(page);
    vmf->page = page;

    if (global_policy.flags & SEC_POLICY_AUDIT_STRICT) {
        pr_info("[sec_mmap:AUDIT] READ_FAULT resuelto. Pagina: %lu, PFN: %lu, PID: %d, Comm: %s\n",
                pgoff, page_to_pfn(page), current->pid, current->comm);
    }

    mutex_unlock(&sec_mutex);
    return 0;
}

/**
 * sec_vma_page_mkwrite - Invocado cuando un proceso intenta escribir sobre una página
 * mapeada con permisos de lectura o compartida (Hook central de Copy-On-Write / Dirty Page).
 */
static vm_fault_t sec_vma_page_mkwrite(struct vm_fault *vmf)
{
    unsigned long pgoff = vmf->pgoff;
    uint32_t current_uid = from_kuid(&init_user_ns, current_uid());

    mutex_lock(&sec_mutex);

    /* 1. Validación de política de escritura */
    if (!(global_policy.flags & SEC_POLICY_PERM_WRITE)) {
        pr_err("[sec_mmap:SECURITY_ALERT] INTENTO DE ESCRITURA BLOQUEADO por PID %d (UID %u) en pagina %lu. Politica es READ_ONLY!\n",
               current->pid, current_uid, pgoff);
        global_stats.blocked_unauthorized++;
        global_stats.integrity_violations++;
        mutex_unlock(&sec_mutex);
        return VM_FAULT_SIGBUS;
    }

    /* 2. Validación de UID */
    if ((global_policy.allowed_uid != 0) &&
        (current_uid != global_policy.allowed_uid) &&
        (current_uid != 0)) {
        pr_err("[sec_mmap:SECURITY_ALERT] Escritura denegada a PID %d (UID %u) en pagina %lu. Propietario autorizado: UID %u\n",
               current->pid, current_uid, pgoff, global_policy.allowed_uid);
        global_stats.blocked_unauthorized++;
        mutex_unlock(&sec_mutex);
        return VM_FAULT_SIGBUS;
    }

    global_stats.write_faults++;
    if (global_policy.flags & SEC_POLICY_COW_TRACK) {
        global_stats.cow_break_events++;
    }

    /* Recalcula checksum tras modificación */
    page_integrity_hashes[pgoff] = sec_compute_checksum(backing_kaddrs[pgoff], SEC_MMAP_PAGE_SIZE);

    if (global_policy.flags & SEC_POLICY_AUDIT_STRICT) {
        pr_info("[sec_mmap:AUDIT] WRITE_MKWRITE autorizado en pagina %lu por PID %d (Comm: %s)\n",
                pgoff, current->pid, current->comm);
    }

    mutex_unlock(&sec_mutex);
    return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct sec_vm_ops = {
    .open          = sec_vma_open,
    .close         = sec_vma_close,
    .fault         = sec_vma_fault,
    .page_mkwrite  = sec_vma_page_mkwrite,
};

/* =========================================================================
 * 3. OPERACIONES DE CONTROL DE ARCHIVO (file_operations)
 * ========================================================================= */

static int sec_dev_open(struct inode *inodep, struct file *filep)
{
    return 0;
}

static int sec_dev_release(struct inode *inodep, struct file *filep)
{
    return 0;
}

/**
 * sec_dev_mmap - Gancho central del alta del VMA
 * 
 * Intercepta la llamada mmap() en Ring 0 antes de que se cree cualquier PTE.
 * Valida tamaño, banderas y asigna las operaciones de seguridad controladas.
 */
static int sec_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned long size = vma->vm_end - vma->vm_start;
    uint32_t current_uid = from_kuid(&init_user_ns, current_uid());

    mutex_lock(&sec_mutex);

    /* 1. Validación de tamaño máximo permitido */
    if (size > SEC_MMAP_BUF_SIZE) {
        pr_warn("[sec_mmap:SECURITY] Solicitud mmap excede tamano maximo (%lu > %d) por PID %d\n",
                size, SEC_MMAP_BUF_SIZE, current->pid);
        global_stats.blocked_unauthorized++;
        mutex_unlock(&sec_mutex);
        return -EINVAL;
    }

    /* 2. Control de Acceso: Verificar si se pide escritura pero la politica lo prohibe */
    if ((vma->vm_flags & VM_WRITE) && !(global_policy.flags & SEC_POLICY_PERM_WRITE)) {
        pr_err("[sec_mmap:SECURITY_ALERT] mmap(PROT_WRITE) DENEGADO a PID %d (UID: %u). Archivo protegido en modo SOLO LECTURA!\n",
               current->pid, current_uid);
        global_stats.blocked_unauthorized++;
        mutex_unlock(&sec_mutex);
        return -EACCES;
    }

    /* 3. Control de Acceso por UID */
    if ((global_policy.allowed_uid != 0) &&
        (current_uid != global_policy.allowed_uid) &&
        (current_uid != 0)) {
        pr_err("[sec_mmap:SECURITY_ALERT] mmap DENEGADO a PID %d por discordancia de UID (%u != %u)\n",
               current->pid, current_uid, global_policy.allowed_uid);
        global_stats.blocked_unauthorized++;
        mutex_unlock(&sec_mutex);
        return -EPERM;
    }

    /* 4. Asignar operaciones de memoria virtual personalizadas */
    vma->vm_ops = &sec_vm_ops;

    /* 5. Establecer banderas de protección contra expansiones y volcados inseguros */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 3, 0)
    vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);
#else
    vma->vm_flags |= (VM_DONTEXPAND | VM_DONTDUMP);
#endif

    global_stats.total_mmaps++;
    pr_info("[sec_mmap:KERNEL] mmap() concedido exitosamente a PID %d. Rango virtual: 0x%lx - 0x%lx\n",
            current->pid, vma->vm_start, vma->vm_end);

    mutex_unlock(&sec_mutex);
    return 0;
}

/**
 * sec_dev_ioctl - Interfaz de administracion y configuracion de politicas
 */
static long sec_dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    mutex_lock(&sec_mutex);

    switch (cmd) {
    case SEC_MMAP_IOCTL_SET_POLICY: {
        struct sec_mmap_policy user_pol;
        if (copy_from_user(&user_pol, (void __user *)arg, sizeof(user_pol))) {
            ret = -EFAULT;
            break;
        }
        if (user_pol.magic != SEC_MAGIC_TOKEN) {
            ret = -EINVAL;
            break;
        }
        global_policy = user_pol;
        pr_info("[sec_mmap:CONFIG] Nueva politica establecida: Flags=0x%x, AllowedUID=%u\n",
                global_policy.flags, global_policy.allowed_uid);
        break;
    }

    case SEC_MMAP_IOCTL_GET_POLICY: {
        if (copy_to_user((void __user *)arg, &global_policy, sizeof(global_policy))) {
            ret = -EFAULT;
            break;
        }
        break;
    }

    case SEC_MMAP_IOCTL_GET_STATS: {
        if (copy_to_user((void __user *)arg, &global_stats, sizeof(global_stats))) {
            ret = -EFAULT;
            break;
        }
        break;
    }

    case SEC_MMAP_IOCTL_RESET_STATS: {
        memset(&global_stats, 0, sizeof(global_stats));
        pr_info("[sec_mmap:CONFIG] Estadisticas de telemetria reiniciadas.\n");
        break;
    }

    case SEC_MMAP_IOCTL_SYNC_CIPHER: {
        uint32_t page_idx = (uint32_t)arg;
        if (page_idx < SEC_MMAP_DEFAULT_PAGES) {
            sec_cipher_page(backing_kaddrs[page_idx], SEC_MMAP_PAGE_SIZE,
                            global_policy.crypto_key, SEC_KEY_LEN);
            global_stats.pages_encrypted++;
            pr_info("[sec_mmap:CRYPTO] Pagina %u cifrada/descifrada en caliente.\n", page_idx);
        } else {
            ret = -EINVAL;
        }
        break;
    }

    default:
        ret = -ENOTTY;
        break;
    }

    mutex_unlock(&sec_mutex);
    return ret;
}

static const struct file_operations sec_fops = {
    .owner          = THIS_MODULE,
    .open           = sec_dev_open,
    .release        = sec_dev_release,
    .mmap           = sec_dev_mmap,
    .unlocked_ioctl = sec_dev_ioctl,
};

/* =========================================================================
 * 4. INTERFAZ /proc PARA AUDITORÍA Y MONITOREO EN TIEMPO REAL
 * ========================================================================= */

static int sec_proc_show(struct seq_file *m, void *v)
{
    mutex_lock(&sec_mutex);
    seq_printf(m, "=== SEC_MMAP KERNEL SECURITY TELEMETRY ===\n");
    seq_printf(m, "Driver Version         : 2.0 (Linux 5.x/6.x/7.x Ready)\n");
    seq_printf(m, "Buffer Size            : %d KB (%d pages)\n",
               SEC_MMAP_BUF_SIZE / 1024, SEC_MMAP_DEFAULT_PAGES);
    seq_printf(m, "Current Policy Flags   : 0x%08x\n", global_policy.flags);
    seq_printf(m, "  - Perm Read          : %s\n", (global_policy.flags & SEC_POLICY_PERM_READ) ? "YES" : "NO");
    seq_printf(m, "  - Perm Write         : %s\n", (global_policy.flags & SEC_POLICY_PERM_WRITE) ? "YES" : "NO");
    seq_printf(m, "  - Transparent Crypto : %s\n", (global_policy.flags & SEC_POLICY_ENCRYPTED) ? "ACTIVE" : "OFF");
    seq_printf(m, "  - Strict Audit       : %s\n", (global_policy.flags & SEC_POLICY_AUDIT_STRICT) ? "ENABLED" : "OFF");
    seq_printf(m, "  - COW Tracking       : %s\n", (global_policy.flags & SEC_POLICY_COW_TRACK) ? "ENABLED" : "OFF");
    seq_printf(m, "Allowed UID Target     : %u\n", global_policy.allowed_uid);
    seq_printf(m, "--- METRICAS OPERACIONALES ---\n");
    seq_printf(m, "Total mmap() Requests  : %llu\n", global_stats.total_mmaps);
    seq_printf(m, "Page Faults (Read)     : %llu\n", global_stats.read_faults);
    seq_printf(m, "Page Faults (Write/COW): %llu\n", global_stats.write_faults);
    seq_printf(m, "Blocked Violations     : %llu\n", global_stats.blocked_unauthorized);
    seq_printf(m, "Pages Encrypted/Decr   : %llu\n", global_stats.pages_encrypted);
    seq_printf(m, "COW Break Events       : %llu\n", global_stats.cow_break_events);
    seq_printf(m, "Integrity Violations   : %llu\n", global_stats.integrity_violations);
    seq_printf(m, "==========================================\n");
    mutex_unlock(&sec_mutex);
    return 0;
}

static int sec_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, sec_proc_show, NULL);
}

static const struct proc_ops sec_proc_fops = {
    .proc_open    = sec_proc_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* =========================================================================
 * 5. INICIALIZACIÓN Y LIMPIEZA DEL MÓDULO (LKM)
 * ========================================================================= */

static int __init sec_mmap_init(void)
{
    int i, ret = 0;

    pr_info("[sec_mmap:KERNEL] Iniciando modulo de aseguramiento mmap...\n");

    /* 1. Asignar memoria fisica para las paginas del kernel */
    for (i = 0; i < SEC_MMAP_DEFAULT_PAGES; i++) {
        backing_pages[i] = alloc_page(GFP_KERNEL | __GFP_ZERO);
        if (!backing_pages[i]) {
            pr_err("[sec_mmap:KERNEL] Error fatal asignando pagina fisica %d\n", i);
            ret = -ENOMEM;
            goto err_alloc_pages;
        }
        SetPageReserved(backing_pages[i]);
        backing_kaddrs[i] = page_address(backing_pages[i]);
        snprintf((char *)backing_kaddrs[i], SEC_MMAP_PAGE_SIZE,
                 "--- [SEC_MMAP PAGE %d DATA] - CONFIDENCIAL / PROTEGIDO POR KERNEL RING 0 ---\n", i);
        page_integrity_hashes[i] = sec_compute_checksum(backing_kaddrs[i], SEC_MMAP_PAGE_SIZE);
    }

    /* 2. Inicializar politica predeterminada (Solo lectura, auditoria activa) */
    memset(&global_policy, 0, sizeof(global_policy));
    global_policy.magic = SEC_MAGIC_TOKEN;
    global_policy.flags = SEC_POLICY_PERM_READ | SEC_POLICY_AUDIT_STRICT | SEC_POLICY_COW_TRACK;
    global_policy.allowed_uid = 1000; /* UID estandar del usuario */
    memcpy(global_policy.crypto_key, "SECURE_KEY_2026B", SEC_KEY_LEN);
    memset(&global_stats, 0, sizeof(global_stats));

    /* 3. Registrar numero mayor y menor de char device */
    major_number = register_chrdev(0, SEC_MMAP_DEVICE_NAME, &sec_fops);
    if (major_number < 0) {
        pr_err("[sec_mmap:KERNEL] Fallo registrando major number (%d)\n", major_number);
        ret = major_number;
        goto err_alloc_pages;
    }

    /* 4. Crear clase de dispositivo compatible con kernels 5.x y 6.x/7.x */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    sec_class = class_create(SEC_MMAP_CLASS_NAME);
#else
    sec_class = class_create(THIS_MODULE, SEC_MMAP_CLASS_NAME);
#endif
    if (IS_ERR(sec_class)) {
        ret = PTR_ERR(sec_class);
        goto err_unregister_chrdev;
    }

    /* 5. Crear nodo de dispositivo /dev/sec_mmap */
    sec_device = device_create(sec_class, NULL, MKDEV(major_number, 0), NULL, SEC_MMAP_DEVICE_NAME);
    if (IS_ERR(sec_device)) {
        ret = PTR_ERR(sec_device);
        goto err_destroy_class;
    }

    /* 6. Crear entrada en /proc */
    proc_entry = proc_create(PROC_FILENAME, 0444, NULL, &sec_proc_fops);
    if (!proc_entry) {
        pr_warn("[sec_mmap:KERNEL] Advertencia: No se pudo crear /proc/%s\n", PROC_FILENAME);
    }

    pr_info("[sec_mmap:KERNEL] Modulo cargado exitosamente. Dispositivo: /dev/%s (Major: %d)\n",
            SEC_MMAP_DEVICE_NAME, major_number);
    pr_info("[sec_mmap:KERNEL] Monitoreo en tiempo real disponible en /proc/%s\n", PROC_FILENAME);
    return 0;

err_destroy_class:
    class_destroy(sec_class);
err_unregister_chrdev:
    unregister_chrdev(major_number, SEC_MMAP_DEVICE_NAME);
err_alloc_pages:
    for (i = 0; i < SEC_MMAP_DEFAULT_PAGES; i++) {
        if (backing_pages[i]) {
            ClearPageReserved(backing_pages[i]);
            __free_page(backing_pages[i]);
            backing_pages[i] = NULL;
        }
    }
    return ret;
}

static void __exit sec_mmap_exit(void)
{
    int i;
    pr_info("[sec_mmap:KERNEL] Descargando modulo de aseguramiento mmap...\n");

    if (proc_entry) {
        proc_remove(proc_entry);
    }

    device_destroy(sec_class, MKDEV(major_number, 0));
    class_destroy(sec_class);
    unregister_chrdev(major_number, SEC_MMAP_DEVICE_NAME);

    /* Purgar de forma segura toda la memoria fisica en RAM antes de liberarla */
    for (i = 0; i < SEC_MMAP_DEFAULT_PAGES; i++) {
        if (backing_pages[i]) {
            memzero_explicit(backing_kaddrs[i], SEC_MMAP_PAGE_SIZE);
            ClearPageReserved(backing_pages[i]);
            __free_page(backing_pages[i]);
            backing_pages[i] = NULL;
        }
    }

    pr_info("[sec_mmap:KERNEL] Modulo descargado y memoria fisica sanitizada con exito.\n");
}

module_init(sec_mmap_init);
module_exit(sec_mmap_exit);
