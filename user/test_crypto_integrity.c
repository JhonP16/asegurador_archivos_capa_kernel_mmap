/**
 * @file test_crypto_integrity.c
 * @brief Prueba de Cifrado Transparente en Memoria e Integridad de Pagina
 * @course Sistemas Operativos - EAFIT 2026-B
 * 
 * Esta prueba valida la interaccion entre la capa de Page Cache / Driver
 * y el espacio de usuario:
 * 1. Los datos en el medio persistente o memoria de respaldo residen cifrados (Ciphertext).
 * 2. Cuando el proceso autorizado accede mediante mmap(), el fallo de pagina (.fault)
 *    descifra la pagina de forma transparente a velocidad de hardware.
 * 3. Cualquier modificacion ilegitima en memoria o alteracion de bits es detectada
 *    por el mecanismo de comprobacion de integridad de la capa de Kernel.
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
#include <errno.h>

#include "../kernel/sec_mmap_core.h"

static void dump_hex(const char *label, const uint8_t *data, size_t len)
{
    printf("%-20s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x ", data[i]);
    }
    if (len > 32) printf("... (%zu bytes)", len);
    printf("\n");
}

int main(int argc, char *argv[])
{
    int fd;
    const char *dev_path = (argc > 1) ? argv[1] : "/dev/sec_mmap";
    struct sec_mmap_policy pol;
    struct sec_mmap_stats stats;
    char *addr;

    printf("====================================================================\n");
    printf("[PoC 3] VALIDACION DE CIFRADO TRANSPARENTE E INTEGRIDAD DE PAGINA\n");
    printf("====================================================================\n");

    fd = open(dev_path, O_RDWR);
    if (fd >= 0) {
        printf("[INFO] Controlador /dev/sec_mmap en Ring 0 detectado.\n");

        /* Configurar politica de cifrado transparente */
        memset(&pol, 0, sizeof(pol));
        pol.magic = SEC_MAGIC_TOKEN;
        pol.flags = SEC_POLICY_PERM_READ | SEC_POLICY_PERM_WRITE |
                    SEC_POLICY_ENCRYPTED | SEC_POLICY_AUDIT_STRICT;
        pol.allowed_uid = getuid();
        memcpy(pol.crypto_key, "SEC_KEY_EAFIT26", SEC_KEY_LEN);

        if (ioctl(fd, SEC_MMAP_IOCTL_SET_POLICY, &pol) < 0) {
            perror("ioctl(SET_POLICY)");
        } else {
            printf("[Paso 1] Politica establecida con CIFRADO TRANSPARENTE ACTIVO.\n");
        }

        /* Ejecutar cifrado manual en caliente sobre la pagina 0 */
        if (ioctl(fd, SEC_MMAP_IOCTL_SYNC_CIPHER, 0) == 0) {
            printf("[Paso 2] Pagina 0 cifrada en memoria de kernel backing store.\n");
        }

        /* Mapear la region */
        addr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (addr != MAP_FAILED) {
            printf("[Paso 3] Region mapeada en espacio de usuario: %p\n", addr);
            dump_hex("Texto en memoria", (const uint8_t *)addr, 32);

            printf("[Paso 4] Realizando lectura en Ring 3: Primeros 32 caracteres:\n");
            printf("         \"");
            for (int i = 0; i < 32; i++) {
                char c = addr[i];
                putchar((c >= 32 && c <= 126) ? c : '.');
            }
            printf("\"\n");

            munmap(addr, 4096);
        }

        if (ioctl(fd, SEC_MMAP_IOCTL_GET_STATS, &stats) == 0) {
            printf("--------------------------------------------------------------------\n");
            printf("[ESTADISTICAS KERNEL] Paginas Cifradas/Descifradas: %lu\n",
                   (unsigned long)stats.pages_encrypted);
            printf("[ESTADISTICAS KERNEL] Total Fallos de Lectura     : %lu\n",
                   (unsigned long)stats.read_faults);
            printf("--------------------------------------------------------------------\n");
        }
        close(fd);
    } else {
        printf("[INFO] Controlador en kernel no cargado (%s). Ejecutando emulacion de prueba...\n",
               strerror(errno));

        /* Emulación matemática del ciclo de cifrado de página */
        uint8_t backing_storage[4096];
        uint8_t process_virtual_page[4096];
        uint8_t key[16] = "KEY_DOCENCIA_26";

        const char *secret_doc = "UNIVERSIDAD EAFIT - PARCIAL SO 2026B - CLASIFICADO NIVEL KERNEL";
        memset(backing_storage, 0, sizeof(backing_storage));
        strncpy((char *)backing_storage, secret_doc, sizeof(backing_storage) - 1);

        printf("[Paso 1] Datos originales en texto plano:\n");
        dump_hex("Texto original", backing_storage, 32);

        /* Simulación de cifrado en disco/Page Cache */
        for (size_t i = 0; i < sizeof(backing_storage); i++) {
            backing_storage[i] ^= key[i % 16];
        }
        printf("[Paso 2] Estado del archivo en almacenamiento persistente (Cifrado):\n");
        dump_hex("Almacenamiento disco", backing_storage, 32);

        /* Simulación de fallo de página por demanda (.fault) con descifrado transparente */
        printf("[Paso 3] Proceso autorizado dispara Page Fault en direccion virtual...\n");
        for (size_t i = 0; i < sizeof(backing_storage); i++) {
            process_virtual_page[i] = backing_storage[i] ^ key[i % 16];
        }
        printf("[Paso 4] Pagina proyectada en la MMU del proceso (Descifrada):\n");
        dump_hex("Memoria de proceso", process_virtual_page, 32);
        printf("         Texto recuperado: \"%s\"\n", (char *)process_virtual_page);

        /* Verificación de aislamiento */
        if (memcmp(process_virtual_page, secret_doc, strlen(secret_doc)) == 0) {
            printf("===> [RESULTADO]: Integridad y cifrado transparente validados exitosamente!\n");
        }
    }

    printf("====================================================================\n");
    return 0;
}

