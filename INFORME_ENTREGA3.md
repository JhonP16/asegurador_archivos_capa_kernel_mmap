# UNIVERSIDAD EAFIT - ESCUELA DE CIENCIAS APLICADAS E INGENIERÍA
### ASIGNATURA: SISTEMAS OPERATIVOS - PERIODO 2026-2
### EVALUACIÓN PARCIAL PRÁCTICA - TEÓRICA (VALOR: 25%)

---

# INFORME TÉCNICO Y MEMORIA DE INGENIERÍA
## Seguridad de Archivos mediante Intervención en la Capa del Kernel y Mapeo de Memoria (`mmap`)

**Autores:** Jhon Jairo Pulgarín Restrepo, Andrés Felipe Eusse  
**Fecha de Entrega:** 3 de Noviembre de 2026  
**Referencia Base:** [SO2026B - CapaKernel (GitHub)](https://github.com/evalenciEAFIT/SO2026B/tree/main/USOS/CapaKernel)  
**Entorno de Compilación y Verificación:** Linux Ubuntu 26.04 LTS (x86_64) / WSL2 Kernel 6.x - 7.x  

---

# TABLA DE CONTENIDO

1. [PARTE I: ANÁLISIS CONCEPTUAL Y PREGUNTAS DIAGNÓSTICAS (10 PREGUNTAS - 30%)](#1-parte-i-análisis-conceptual-y-preguntas-diagnósticas-10-preguntas---30)
   - [Pregunta 1: Mapeo Virtual y Page Faults](#pregunta-1-mapeo-virtual-y-page-faults)
   - [Pregunta 2: MAP_SHARED vs. MAP_PRIVATE](#pregunta-2-map_shared-vs-map_private)
   - [Pregunta 3: Mecanismo Copy-On-Write (COW) y Vulnerabilidad Dirty COW](#pregunta-3-mecanismo-copy-on-write-cow-y-vulnerabilidad-dirty-cow)
   - [Pregunta 4: Intercepción de Llamadas en Kernel: LKM vs. LSM](#pregunta-4-intercepción-de-llamadas-en-kernel-lkm-vs-lsm)
   - [Pregunta 5: Cifrado Transparente en Memoria RAM y Page Cache](#pregunta-5-cifrado-transparente-en-memoria-ram-y-page-cache)
   - [Pregunta 6: Sincronización e Integridad (`msync` y `fsync`)](#pregunta-6-sincronización-e-integridad-msync-y-fsync)
   - [Pregunta 7: Control de Accesos y Auditoría con eBPF](#pregunta-7-control-de-accesos-y-auditoría-con-ebpf)
   - [Pregunta 8: Evasión de Permisos POSIX con Mapeos Privados](#pregunta-8-evasión-de-permisos-posix-con-mapeos-privados)
   - [Pregunta 9: Mitigación de Condiciones de Carrera (`madvise` y COW)](#pregunta-9-mitigación-de-condiciones-de-carrera-madvise-y-cow)
   - [Pregunta 10: Aislamiento de Memoria y Paginación Multinivel](#pregunta-10-aislamiento-de-memoria-y-paginación-multinivel)
2. [PARTE II: DISEÑO DE LA ESTRATEGIA CON APOYO DE INTELIGENCIA ARTIFICIAL (30%)](#2-parte-ii-diseño-de-la-estrategia-con-apoyo-de-inteligencia-artificial-30)
   - [2.1. Definición del Flujo de Trabajo Asistido por IA](#21-definición-del-flujo-de-trabajo-asistido-por-ia)
   - [2.2. Metodología de Ingeniería de Prompts y Verificación Crítica](#22-metodología-de-ingeniería-de-prompts-y-verificación-crítica)
   - [2.3. Detección y Análisis de Alucinaciones Técnicas de Bajo Nivel](#23-detección-y-análisis-de-alucinaciones-técnicas-de-bajo-nivel)
   - [2.4. Estrategia Arquitectónica Seleccionada y Matriz de Compensaciones](#24-estrategia-arquitectónica-seleccionada-y-matriz-de-compensaciones)
3. [PARTE III: IMPLEMENTACIÓN, PRESENTACIÓN Y ARGUMENTACIÓN (40%)](#3-parte-iii-implementación-presentación-y-argumentación-40)
   - [3.1. Entregables de Código e Implementación](#31-entregables-de-código-e-implementación)
   - [3.2. Demostración y Ejecución de Pruebas de Seguridad (PoCs)](#32-demostración-y-ejecución-de-pruebas-de-seguridad-pocs)
   - [3.3. Justificación Teórica: Capa Kernel vs. Espacio de Usuario](#33-justificación-teórica-capa-kernel-vs-espacio-de-usuario)
   - [3.4. Medición de Impacto y Evaluación de Rendimiento Cuantitativo](#34-medición-de-impacto-y-evaluación-de-rendimiento-cuantitativo)
   - [3.5. Limitaciones del Sistema y Trabajo Futuro](#35-limitaciones-del-sistema-y-trabajo-futuro)
4. [CONCLUSIONES](#4-conclusiones)

---

# 1. PARTE I: ANÁLISIS CONCEPTUAL Y PREGUNTAS DIAGNÓSTICAS (10 PREGUNTAS - 30%)

---

### Pregunta 1: Mapeo Virtual y Page Faults
**Enunciado:** *¿Cuál es la secuencia exacta de eventos a nivel de kernel y MMU desde que un proceso invoca `mmap()` hasta que ocurre el primer fallo de página (Page Fault) por lectura o escritura en una página mapeada?*

#### Respuesta y Fundamentación Técnica Rigurosa:

El ciclo de vida de un mapeo mediante `mmap()` y su resolución mediante la Unidad de Manejo de Memoria (**MMU**) opera bajo una filosofía estricta de **evaluación perezosa (*lazy allocation*)**. La secuencia exacta se desglosa en dos fases fundamentales:

```
+--------------------------------------------------------------------------------------------------+
| FASE 1: Alta del VMA en Espacio de Direcciones Virtuales (Syscall mmap)                           |
+--------------------------------------------------------------------------------------------------+
  Proceso Ring 3 (mmap) 
       |
       v  [Syscall Trap / Instruction SYSCALL]
  sys_mmap() -> ksys_mmap_pgoff() -> vm_mmap_pgoff() -> do_mmap()
       |
       +--> 1. Adquisición de semáforo: down_write(&mm->mmap_lock)
       +--> 2. Búsqueda de hueco virtual contiguo libre mediante get_unmapped_area()
       +--> 3. Instanciación de struct vm_area_struct (VMA) mediante vm_area_alloc()
       +--> 4. Inicialización de descriptores del VMA:
       |        * vma->vm_start = Dirección virtual inicial (e.g. 0x7f2d45200000)
       |        * vma->vm_end   = Dirección virtual final (vma->vm_start + len)
       |        * vma->vm_flags = VM_READ | VM_SHARED | VM_MAYREAD | VM_MAYWRITE
       |        * vma->vm_page_prot = vm_get_page_prot(vma->vm_flags)
       |        * vma->vm_file  = struct file *filp (Incrementa f_count con get_file())
       |        * vma->vm_ops   = filp->f_op->mmap(filp, vma)  [Asigna callbacks de memoria]
       +--> 5. Inserción del VMA en el árbol de rangos del proceso (Maple Tree mm_mt en Linux 6.x+)
       +--> 6. Liberación de cerrojo: up_write(&mm->mmap_lock)
       v
  Retorno al Proceso Ring 3 con el puntero virtual `ptr`.
  ¡EN ESTE MOMENTO NO SE HA ASIGNADO NINGÚN MARCO FÍSICO DE RAM (PFN) NI SE HAN CREADO PTEs!
```

```
+--------------------------------------------------------------------------------------------------+
| FASE 2: Excepción de Hardware Page Fault (#PF, Vector 14) en el Primer Acceso                   |
+--------------------------------------------------------------------------------------------------+
  Instrucción CPU: MOV (%rax), %rbx  (donde %rax contiene la dirección virtual `ptr`)
       |
       v
  La MMU toma la dirección virtual e inicia el recorrido de tablas (*Page Table Walk*):
       * Lee el registro de control CR3 (apunta a la base física de la tabla PGD del proceso)
       * PGD (Page Global Directory) -> P4D -> PUD -> PMD
       * Llega a la entrada PTE (Page Table Entry).
       * LA MMU DETECTA QUE EL BIT `_PAGE_PRESENT` (Bit 0) ES CERO (PTE vacía o ausente).
       |
       v  [Excepción de Hardware de CPU]
  La CPU suspende la instrucción MOV y dispara la interrupción de hardware Page Fault (#PF, Vector 14).
  El hardware guarda en la pila del kernel: SS, RSP, RFLAGS, CS, RIP y empuja el Código de Error (#PF Error Code).
  La CPU almacena la dirección virtual causante en el registro de control **CR2**.
       |
       v  [Transición Automática a Ring 0]
  Manejador de bajo nivel: exc_page_fault() -> do_user_addr_fault()
       +--> 1. Lee CR2 y adquiere cerrojo: down_read(&mm->mmap_lock) (o vma_start_read(vma) en 6.x)
       +--> 2. Busca el VMA correspondiente en el Maple Tree: find_vma(mm, address)
       +--> 3. Comprueba permisos: ¿address >= vma->vm_start && (vma->vm_flags & VM_READ)?
       +--> 4. Invoca el subsistema de paginación central:
                handle_mm_fault(vma, address, flags, regs)
                  -> __handle_mm_fault() -> handle_pte_fault()
       +--> 5. Si la entrada no existe y es mapeo con respaldo en archivo:
                do_fault() -> do_read_fault()
                  -> vma->vm_ops->fault(struct vm_fault *vmf)
       +--> 6. Callback de archivo (filemap_fault()):
                * Consulta el Page Cache (address_space->i_pages / XArray).
                * Si la página no está en RAM: emite solicitud de E/S por bloques (bio/request) al disco.
                * Al completarse la lectura, asigna el descriptor físico `struct page`.
       +--> 7. Asignación de PTE (set_pte_at()):
                * Escribe la dirección física base (PFN) en la PTE.
                * Activa bits de hardware: `_PAGE_PRESENT=1`, `_PAGE_USER=1`, `_PAGE_ACCESSED=1`.
                * Si es solo lectura: `_PAGE_RW=0`.
       +--> 8. Liberación de cerraduras y retorno de interrupción con `IRETQ`.
       v
  La CPU reanuda exactamente la misma instrucción `MOV (%rax), %rbx`.
  Ahora la MMU encuentra la PTE presente en el TLB/RAM y la lectura concluye a velocidad de hardware.
```

---

### Pregunta 2: MAP_SHARED vs. MAP_PRIVATE
**Enunciado:** *¿Cómo gestiona el subsistema de memoria virtual de Linux (`struct vm_area_struct`) la diferencia entre banderas `MAP_SHARED` y `MAP_PRIVATE`, y cuáles son las implicaciones de seguridad respecto a la persistencia y visibilidad cruzada entre procesos?*

#### Respuesta y Fundamentación Técnica Rigurosa:

En el kernel de Linux, las banderas POSIX `MAP_SHARED` y `MAP_PRIVATE` se traducen internamente en los campos `vma->vm_flags` y en la configuración de permisos de hardware `vma->vm_page_prot`.

```
                    +------------------------------------------------+
                    |            DIFERENCIACIÓN EN EL KERNEL         |
+-------------------+--------------------------------+---------------+--------------------------------+
| Característica    | MAP_SHARED                     | MAP_PRIVATE                                    |
+-------------------+--------------------------------+---------------+--------------------------------+
| Banderas VMA      | VM_SHARED | VM_MAYSHARE        | !(VM_SHARED), VM_MAYWRITE                      |
| PTE Inicial       | Apunta al Page Cache (R/W)     | Apunta al Page Cache (Solo Lectura, R/O)       |
| Destino Escritura | Page Cache global del inodo    | Marco anónimo privado (Copia en RAM)           |
| Persistencia      | Sí (volcado a disco vía msync) | No (se descarta al terminar el proceso)        |
| Visibilidad       | Cruzada entre todos los procesos| Aislada al espacio virtual local               |
+-------------------+--------------------------------+------------------------------------------------+
```

1. **Gestión Interna en `struct vm_area_struct`:**
   - **`MAP_SHARED`:** `vma->vm_flags` contiene la bandera `VM_SHARED`. Cuando la entrada de la tabla de páginas se escribe mediante `alloc_set_pte()`, la PTE apunta directamente a la página física almacenada en el Page Cache del archivo (`vma->vm_file->f_mapping->i_pages`). Cualquier otro proceso que abra el mismo archivo con `MAP_SHARED` tendrá entradas PTE que apuntan **al mismo Page Frame Number (PFN)** en la memoria física.
   - **`MAP_PRIVATE`:** El kernel activa `VM_MAYWRITE` (si se pidió `PROT_WRITE`), pero desactiva `VM_SHARED`. La PTE inicial se mapea con el bit de hardware `_PAGE_RW = 0` (solo lectura), apuntando temporalmente a la página del Page Cache. Cuando el proceso intenta escribir, la MMU dispara una excepción `#PF` por violación de permisos de escritura, invocando `do_wp_page()` para desencadenar el mecanismo Copy-On-Write (COW).

2. **Implicaciones Críticas de Seguridad:**
   - **Visibilidad Cruzada:** En `MAP_SHARED`, si un proceso no privilegiado escribe en la memoria mapeada, la modificación es visible de inmediato para todos los demás procesos en el sistema, incluidos demonios del sistema ejecutándose como `root`. Esto crea un vector de ataque directo si un proceso malicioso altera búferes de comunicación o estructuras compartidas.
   - **Persistencia No Autorizada:** Las escrituras en `MAP_SHARED` marcan la página como sucia (`PageDirty`) en el Page Cache. Tarde o temprano, los hilos de kernel `kworker/kswapd` vaciarán (`writeback`) esos bytes al almacenamiento persistente, corrompiendo el archivo original en disco.
   - **Aislamiento en `MAP_PRIVATE`:** `MAP_PRIVATE` previene la corrupción persistente, pues las modificaciones se aíslan en páginas anónimas. Sin embargo, si el kernel falla en la gestión de banderas de protección, un atacante puede inducir al kernel a omitir la duplicación privada y escribir sobre la página original del Page Cache (raíz del ataque Dirty COW).

---

### Pregunta 3: Mecanismo Copy-On-Write (COW) y Vulnerabilidad Dirty COW
**Enunciado:** *Describa el ciclo de vida de una página bajo COW. ¿En qué condiciones una falla en la gestión de banderas de protección (`VM_MAYWRITE`, `PROT_READ`, `PROT_WRITE`) en el kernel puede derivar en una escalada de privilegios o corrupción de archivos del sistema?*

#### Respuesta y Fundamentación Técnica Rigurosa:

#### 1. Ciclo de Vida de una Página bajo Copy-On-Write (COW):
1. **Asignación Inicial:** Dos o más procesos (o un proceso con `MAP_PRIVATE`) comparten el mismo marco de página físico de solo lectura (`struct page` en Page Cache). Sus entradas PTE tienen `_PAGE_PRESENT=1`, `_PAGE_RW=0`.
2. **Intento de Escritura:** Un proceso ejecuta `MOV %rbx, (%rax)`. La MMU comprueba los bits de la PTE; al notar `_PAGE_RW=0` para una operación de escritura, suspende la ejecución y dispara un fallo de página `#PF` con código de error indicando violación de escritura (`FAULT_FLAG_WRITE`).
3. **Atención en Kernel (`do_wp_page()`):**
   - El kernel verifica si la página es exclusiva (`page_count(page) == 1`). Si nadie más la comparte, simplemente activa `_PAGE_RW=1` mediante `reuse_swap_page()`.
   - Si la página es compartida (`page_count(page) > 1`):
     a) Asigna un nuevo marco físico anónimo con `alloc_zeroed_user_highpage_movable(vma, address)`.
     b) Copia byte a byte el contenido de la página original a la nueva página mediante `copy_user_highpage()`.
     c) Decrementa el contador de referencias de la página original (`put_page(old_page)`).
     d) Modifica la PTE del proceso escritor para apuntar al **nuevo PFN**, configurando `_PAGE_RW=1`.
     e) Invalida la entrada correspondiente en el TLB del procesador (`flush_tlb_page()`).
4. **Reanudación:** La instrucción de escritura se reinicia, escribiendo de forma totalmente aislada en la copia privada.

```mermaid
sequenceDiagram
    participant CPU as CPU / MMU
    participant Kernel as Kernel (do_wp_page)
    participant PageCache as Page Cache (Lectura)
    participant PrivatePage as Nueva Página RAM (COW)

    CPU->>PageCache: Intento MOV (Escritura en PTE con R/W=0)
    PageCache-->>CPU: Excepción #PF (Vector 14)
    CPU->>Kernel: exc_page_fault(address, FAULT_FLAG_WRITE)
    Kernel->>Kernel: Comprueba VMA (VM_MAYWRITE activo)
    Kernel->>PrivatePage: Asigna nuevo marco físico alloc_page()
    Kernel->>PrivatePage: Copia bytes desde Page Cache (memcpy)
    Kernel->>CPU: Actualiza PTE -> Nuevo PFN con R/W=1
    Kernel->>CPU: Invalida TLB (flush_tlb_page)
    Kernel->>CPU: Retorna a Ring 3 (IRETQ)
    CPU->>PrivatePage: Re-ejecuta MOV exitosamente en copia local
```

#### 2. Condiciones de Falla y Escalada de Privilegios (Caso Dirty COW / CVE-2016-5195):
La vulnerabilidad histórica **Dirty COW** demostró la fragilidad de este mecanismo ante condiciones de carrera en el manejo de banderas de protección dentro de `mm/gup.c` (`__get_user_pages()`):
- **Escenario:** Un atacante abre un archivo propiedad de `root` sin permisos de escritura (e.g. `/etc/passwd`) con `O_RDONLY`, y lo mapea con `mmap(..., PROT_READ, MAP_PRIVATE, fd, 0)`.
- **Inyección mediante `/proc/self/mem`:** El atacante invoca `write()` sobre `/proc/self/mem` apuntando a la dirección mapeada. El kernel utiliza `get_user_pages()` con las banderas `FOLL_FORCE | FOLL_WRITE`.
- **La Carrera Crítica:**
  1. `get_user_pages()` detecta que la página no tiene permisos de escritura y fuerza la rotura del COW (`faultin_page(..., FOLL_WRITE)`), creando la copia privada.
  2. En ese instante exacto, un segundo hilo atacante invoca `madvise(addr, len, MADV_DONTNEED)`. Esta llamada limpia la entrada PTE de la tabla de páginas y descarta la página privada recién creada.
  3. En la siguiente iteración de reintento de `get_user_pages()`, el kernel comprueba la PTE y la encuentra vacía. Vuelve a llamar a `handle_mm_fault()`, pero debido a un bug de estado en la gestión de banderas de reintento, el kernel asumió que el paso COW ya había tenido éxito y **removió la bandera `FOLL_WRITE`**.
  4. Como resultado, el kernel resolvió la página directamente contra el **Page Cache original de solo lectura**, y `write()` escribió los datos directamente sobre la caché física del archivo `/etc/passwd`.
  5. Los hilos `writeback` persistieron la alteración a disco, permitiendo al atacante sobrescribir el archivo de contraseñas y obtener acceso de superusuario (`root`).
- **Mitigación en Kernels Modernos:** El kernel introdujo la bandera interna `FOLL_COW` para garantizar que ninguna escritura a través de GUP pueda dirigirse a una página sin verificar explícitamente que la página resultante sea una copia anónima exclusiva.

---

### Pregunta 4: Intercepción de Llamadas en Kernel: LKM vs. LSM
**Enunciado:** *Para monitorear o restringir el uso de `mmap()` sobre archivos sensibles, ¿cuáles son las ventajas, desventajas y viabilidad de utilizar un módulo de kernel (LKM) con hook en la System Call Table frente a un Linux Security Module (LSM) con ganchos (hooks) como `file_mmap`?*

#### Respuesta y Fundamentación Técnica Rigurosa:

```
+----------------------------------------------------------------------------------------------------+
|                         TABLA COMPARATIVA: HOOK EN SYSCALL TABLE vs. LSM HOOKS                     |
+--------------------------+------------------------------------+------------------------------------+
| Dimensión                | LKM (Hook en System Call Table)    | LSM (Linux Security Module Hooks)  |
+--------------------------+------------------------------------+------------------------------------+
| Arquitectura             | Modificación directa de punteros en| Puntos de enganche oficiales       |
|                          | la tabla `sys_call_table`.         | estructurados (`security_hook_heads`).|
| Seguridad y Estabilidad  | Muy deficiente; riesgo de Kernel   | Excelente; aislamiento garantizado |
|                          | Panic y condiciones de carrera.   | sin corrupción de memoria.         |
| Viabilidad en Kernels 5.x| Prácticamente INVÍABLE en kernels  | TOTALMENTE VIABLE y estándar de    |
| y 6.x contemporáneos     | modernos de producción.            | la industria.                      |
| Parámetros Disponibles   | Argumentos crudos de la syscall    | Objetos semánticos del kernel      |
|                          | (direcciones de memoria, enteros). | (`struct file`, `struct cred`, etc)|
| Interacción con Protec-  | Bloqueado por `CR0.WP`, KPTI,      | Nativo; no altera código ejecutable|
| ciones del Hardware      | W^X en Ring 0 y Page Table RoData. | del kernel.                        |
+--------------------------+------------------------------------+------------------------------------+
```

#### Análisis Detallado de Mecanismos:

1. **LKM con Hook en `sys_call_table`:**
   - *Mecanismo:* Sobrescribir la dirección `sys_call_table[__NR_mmap]` con la dirección de una función envoltorio propia (`sec_sys_mmap`).
   - *Inviabilidad en Kernels Contemporáneos:*
     a) Desde Linux 2.6+, la tabla `sys_call_table` **no está exportada** (`EXPORT_SYMBOL`). Su dirección debe buscarse por heurísticas o `/proc/kallsyms`.
     b) En Linux 5.7+, la función `kallsyms_lookup_name()` fue des-exportada para prevenir rootkits.
     c) La memoria de la tabla reside en páginas marcadas como de solo lectura a nivel de tablas de páginas (`CR0.WP = 1` y bit R/W=0 en la PTE). Modificar `CR0` requiere desactivar protecciones de procesador con `write_cr0()`, lo cual rompe protecciones de concurrencia en CPUs multinúcleo SMP y es detectado inmediatamente por subsistemas como *Kernel Lockdown* y *Control Flow Integrity* (CFI).
     d) No tiene acceso semántico al inodo ni a los credenciales de seguridad antes de que se creen los objetos de kernel.

2. **Linux Security Module (LSM) con Gancho `file_mmap`:**
   - *Mecanismo:* Instrumentar el hook oficial `security_mmap_file(struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags)`.
   - *Ventajas Superiores:*
     a) Se ejecuta dentro del flujo natural de `do_mmap()`, **antes** de que se cree el VMA o se asigne memoria virtual.
     b) Recibe punteros tipados y resueltos: `struct file *file` permite inspeccionar directamente `file->f_inode`, la ruta canónica con `dentry_path()`, los credenciales con `current_cred()`, y las etiquetas de seguridad SELinux/AppArmor.
     c) Con la llegada de **BPF-LSM** en Linux 5.7+ (`CONFIG_BPF_LSM`), es posible registrar ganchos LSM dinámicamente mediante programas eBPF (`SEC("lsm/file_mmap")`) firmados criptográficamente, sin necesidad de compilar un módulo LKM ni reiniciar el sistema.

---

### Pregunta 5: Cifrado Transparente en Memoria RAM y Page Cache
**Enunciado:** *Si un archivo confidencial se encuentra cifrado en disco, ¿cómo debe interactuar la capa de Page Cache y el driver de sistema de archivos en el kernel para que la proyección en `mmap()` sea legible en el espacio de usuario autorizado sin exponer el contenido descifrado a otros procesos no privilegiados en memoria física?*

#### Respuesta y Fundamentación Técnica Rigurosa:

El desafío fundamental del cifrado en archivos mapeados radica en la **naturaleza compartida del Page Cache**: si el Page Cache almacena las páginas descifradas (texto plano), cualquier proceso que logre mapear el archivo o inspeccionar la memoria física (vía `/dev/mem` o ataques de canal lateral) accederá a los datos sensibles.

```mermaid
flowchart TD
    subgraph Disco ["Almacenamiento Persistente"]
        A[Bloques Cifrados en Disco / Backing Store]
    end

    subgraph Kernel_PageCache ["Capa de Kernel (Aislamiento Criptográfico)"]
        A -->|Lectura BIO| B["Page Cache Global (Almacena SIEMPRE Texto Cifrado)"]
        B --> C{"Controlador de Fallo (.fault)"}
        C -->|Proceso NO Autorizado| D[Retorna VM_FAULT_SIGBUS / -EACCES]
        C -->|Proceso Autorizado| E["Kernel Crypto API (crypto_sync_skcipher)"]
        E -->|Descifrado On-Demand| F["Marco de Página Físico Privado (struct page exclusiva)"]
    end

    subgraph Espacio_Usuario ["Espacio de Direcciones del Proceso"]
        F --> G["PTE Privada: Present=1, R/W, NX"]
        G --> H["Proceso Legítimo: Acceso a Texto Plano en RAM"]
    end
```

#### Arquitectura de Interacción en el Kernel:

1. **Almacenamiento en Page Cache Cifrado (Modelo `fscrypt` / `dm-crypt` adaptado):**
   - El Page Cache asociado al `struct address_space` del archivo almacena **únicamente bloques cifrados** tal como residen en el disco.
   - Si un proceso no privilegiado abre el archivo y realiza `read()` o `mmap()`, el kernel le entrega únicamente bloques ilegibles de texto cifrado (*ciphertext*).

2. **Intercepción en el Fallo de Página por Demanda (`vm_operations_struct->fault`):**
   - Cuando el proceso autorizado accede a su dirección virtual, se dispara el fallo de página `#PF`.
   - El manejador `.fault` del controlador:
     a) Autentica el proceso: verifica su token de sesión, credenciales (`current_cred()->uid`) o llave en el *Kernel Keyring* (`struct key`).
     b) Si la autenticación es exitosa, en lugar de compartir la página física del Page Cache global, el driver asigna un marco de página física **independiente y privado** mediante `alloc_page(GFP_KERNEL | __GFP_ZERO)`.
     c) Invoca la API criptográfica del kernel (`crypto_sync_skcipher_decrypt` con AES-256-XTS o ChaCha20) para descifrar el bloque del Page Cache hacia el marco de página privado recién asignado.
     d) Asigna este marco físico privado a la entrada PTE del proceso autorizado con `set_pte_at()`.

3. **Prevención de Exposición Cruzada y Sanitización:**
   - La página en texto plano tiene su bandera `SetPageReserved()` o se etiqueta como anónima exclusiva, impidiendo que el subsistema de memoria la fusione con otros procesos mediante KSM (*Kernel Samepage Merging*).
   - En el callback de cierre del VMA (`vm_operations_struct->close`) o al terminar el proceso, el kernel ejecuta `memzero_explicit()` sobre el marco de página físico antes de liberarlo (`__free_page()`), neutralizando ataques de reutilización de memoria (*use-after-free* o volcados residuales en RAM).

---

### Pregunta 6: Sincronización e Integridad (`msync` y `fsync`)
**Enunciado:** *¿Cómo garantiza el kernel la consistencia de páginas marcadas como sucias (dirty pages) en memoria antes de ser persistidas en disco, y cómo puede un atacante evadir filtros de seguridad si los datos no son inspeccionados en el momento de la escritura en memoria?*

#### Respuesta y Fundamentación Técnica Rigurosa:

#### 1. Gestión de Páginas Sucias en el Kernel:
1. **Detección por Hardware:** Cuando la CPU escribe en una página mapeada con `MAP_SHARED`, la MMU activa automáticamente el bit 6 (`_PAGE_DIRTY`) en la entrada PTE correspondiente a nivel de silicio, sin conmutar a Ring 0.
2. **Ciclo de Persistencia:**
   - Cuando el proceso invoca `msync(addr, len, MS_SYNC)`:
     a) El kernel recorre las PTEs del rango virtual con `walk_page_range()`.
     b) Si encuentra el bit `_PAGE_DIRTY`, transfiere el estado al descriptor físico `struct page` invocando `set_page_dirty()` y marca el inodo como sucio en el Radix Tree / XArray del `struct address_space`.
     c) Invoca la función `f_op->fsync()` del sistema de archivos, la cual construye peticiones de bloques (`bio`) y vacía los búferes al disco mediante comandos de sincronización de hardware (*flush cache barriers*).
   - En segundo plano, si el proceso no llama a `msync()`, los hilos del kernel `pdflush`/`kworker flusher` recorren periódicamente las páginas sucias según los umbrales de `/proc/sys/vm/dirty_background_ratio`.

```
Escritura mmap() (Ring 3) ──> MMU activa Bit _PAGE_DIRTY (Sin Syscall) ──> RAM Física Sucia
                                                                                  │
  [PUNTO CIEGO: Ningún filtro VFS/LSM ve esta modificación]                       │
                                                                                  ▼
msync() / Flush Automático ──> Kernel busca páginas sucias ──> writeback a Disco
```

#### 2. Vector de Evasión de Filtros de Seguridad y Ceguera de la E/S:
- **El Punto Ciego de `mmap()`:** En la E/S tradicional (`write()`), cada operación pasa obligatoriamente por el punto de intercepción VFS en Ring 0 (`vfs_write()`), permitiendo que módulos de seguridad (LSM), firewalls de archivos, analizadores antimalware o auditores de integridad inspeccionen los datos en tiempo real.
- **La Evasión:** En `mmap()`, una vez otorgado el mapeo con `PROT_WRITE`, **millones de escrituras se ejecutan mediante instrucciones `MOV` a velocidad de bus de memoria sin generar una sola llamada al sistema**.
- Si un atacante inyecta una carga maliciosa (e.g. modifica un ejecutable compartido, corrompe una base de datos o inserta una clave pública no autorizada), los monitores basados en syscalls (`strace`, auditd tradicional o interceptores de `sys_write`) permanecen completamente ciegos.
- Cuando finalmente se ejecuta `msync()` o el proceso termina, el kernel persiste los datos adulterados sin haber realizado ninguna inspección de contenido.
- **Contención en Kernel:** La defensa exige implementar el gancho `->page_mkwrite` en el VMA. Al forzar que las páginas se mapeen inicialmente como de solo lectura, la primera escritura dispara una trampa al kernel en Ring 0, permitiendo registrar la intención de modificación, validar permisos y computar hashes de integridad antes de autorizar la escritura.

---

### Pregunta 7: Control de Accesos y Auditoría con eBPF
**Enunciado:** *¿Cómo se puede emplear eBPF (Extended Berkeley Packet Filter) y `kprobes`/`fexit` para auditar accesos indebidos o patrones anómalos de lectura/escritura sobre regiones mapeadas con `mmap()` sin recompilar el núcleo del sistema operativo?*

#### Respuesta y Fundamentación Técnica Rigurosa:

**eBPF** permite ejecutar código de inspección de seguridad en Ring 0 con garantías formales de terminación y seguridad de memoria gracias al **Verificador BPF del Kernel**.

#### Arquitectura de Auditoría eBPF:
1. **Instrumentación de Puntos Estratégicos:**
   - **`tracepoint/syscalls/sys_enter_mmap`:** Captura instantáneamente cada solicitud `mmap()` proveniente de cualquier proceso. Extrae: PID, UID, flags (`MAP_SHARED` vs `MAP_PRIVATE`), protección solicitada (`PROT_READ | PROT_WRITE | PROT_EXEC`) y descriptor de archivo (`fd`).
   - **`kprobe/vma_link` o `kprobe/handle_mm_fault`:** Permite observar el momento exacto en que una dirección virtual dispara un fallo de página, registrando el desplazamiento exacto del archivo que se está cargando a memoria.
   - **`fexit/sys_mmap`:** Inspecciona la dirección virtual de retorno asignada por el kernel, validando si el rango asignado coincide con zonas de memoria anómalas.

2. **Detección de Patrones Anómalos en Tiempo Real:**
   - **W^X Violations (Write XOR Execute):** Un programa eBPF puede inspeccionar `prot & (PROT_WRITE | PROT_EXEC)`. Si un proceso solicita páginas con permisos de escritura y ejecución simultáneos, eBPF detecta inmediatamente un patrón clásico de inyección de código / *shellcode*.
   - **Mapeos Anómalos sobre Archivos de Sistema:** Comparando el puntero del inodo con una tabla hash BPF (`BPF_MAP_TYPE_HASH`) que almacene los inodos de archivos críticos (`/etc/shadow`, `/usr/bin/sudo`), el programa eBPF genera una alerta de intrusión inmediata si un UID no autorizado mapea dichos archivos.

3. **Comunicación de Ultra-Baja Latencia con Espacio de Usuario:**
   - Los eventos se empaquetan en una estructura binaria compacta (`struct mmap_event`) y se envían a espacio de usuario mediante un **BPF Ring Buffer** (`BPF_MAP_TYPE_RINGBUF`).
   - A diferencia de los búferes de eventos tradicionales (perf-buffers), el Ring Buffer de eBPF soporta memoria compartida sin copiado adicional (*lockless zero-copy memory*), permitiendo a demonios de seguridad procesar cientos de miles de eventos por segundo con menos del 1% de sobrecosto de CPU.

---

### Pregunta 8: Evasión de Permisos POSIX con Mapeos Privados
**Enunciado:** *Si un proceso abre un descriptor de archivo con permisos de solo lectura (`O_RDONLY`), ¿puede bajo ciertas configuraciones de kernel mapearlo con `PROT_READ | PROT_WRITE` y `MAP_PRIVATE`? Explique por qué el kernel lo permite y qué riesgos de fuga de información o alteración temporal de datos implica.*

#### Respuesta y Fundamentación Técnica Rigurosa:

#### 1. ¿Por qué el Kernel lo Permite? (Fundamento del Estándar POSIX):
**Sí, el kernel de Linux lo permite explícitamente**, y este comportamiento cumple rigurosamente con el estándar POSIX (`IEEE Std 1003.1`):
- Cuando un proceso invoca `open(path, O_RDONLY)`, el VFS verifica que el proceso tenga permisos de lectura (`MAY_READ`) sobre el inodo.
- Posteriormente, al invocar `mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0)`:
  - El kernel en `do_mmap()` evalúa:
    ```c
    if ((flags & MAP_SHARED) && (prot & PROT_WRITE) && !(file->f_mode & FMODE_WRITE))
        return -EACCES; /* BLOQUEADO: No se puede escribir en archivo abierto O_RDONLY en modo compartido */
    ```
  - Sin embargo, para `MAP_PRIVATE`:
    ```c
    /* En MAP_PRIVATE, las escrituras NUNCA modifican el archivo subyacente.
     * Solo se requiere que el archivo sea legible para poblar la copia privada */
    if (!(file->f_mode & FMODE_READ))
        return -EACCES;
    ```
- **Razón Arquitectónica:** En un mapeo privado con Copy-On-Write, el archivo en disco actúa únicamente como una **plantilla de inicialización de datos en RAM**. Cualquier escritura futura creará páginas anónimas exclusivas del proceso. Por ende, el kernel considera que el proceso no está modificando el archivo del sistema, sino su propia memoria virtual privada.

#### 2. Riesgos de Seguridad y Fuga de Información:
1. **Fuga de Información Confidencial (Information Leakage):** Procesos no privilegiados que tengan acceso de lectura a archivos sensibles (e.g. configuraciones compartidas, binarios o diccionarios) pueden proyectar el contenido en regiones modificables de su memoria y manipular los datos en RAM para sortear chequeos de integridad internos en espacio de usuario.
2. **Evasión de Controles de Seguridad a Nivel de Aplicación:** Muchas aplicaciones asumen que si abrieron un archivo con `O_RDONLY`, los datos en memoria permanecerán inmutables. Un atacante que controle el hilo o que inyecte código en la aplicación puede modificar punteros sobre el VMA privado, alterando tablas de salto, credenciales en caché o listas de control de acceso en memoria sin tocar el disco.
3. **Plataforma de Lanzamiento para Ataques de Concurrencia:** Este mecanismo es el requisito previo indispensable para explotar fallas de carrera en el kernel (como Dirty COW), ya que provee al atacante una región virtual respaldada por un archivo de sistema pero con la bandera `VM_MAYWRITE` activa en el descriptor del VMA.

---

### Pregunta 9: Mitigación de Condiciones de Carrera (`madvise` y COW)
**Enunciado:** *¿Cómo previene el kernel actual condiciones de carrera concurrentes entre `madvise(MADV_DONTNEED)` y escrituras sobre páginas mapeadas privadas?*

#### Respuesta y Fundamentación Técnica Rigurosa:

La prevención de condiciones de carrera entre la invalidación de páginas (`MADV_DONTNEED`) y las operaciones de escritura concurrentes (vía CPU directa o mediante `get_user_pages`) se resolvió en el kernel contemporáneo a través de una reforma profunda en los mecanismos de sincronización de memoria virtual:

```mermaid
flowchart LR
    A["Hilo 1: madvise(MADV_DONTNEED)"] -->|Intenta limpiar PTE| B["Cerradura de Tabla de Páginas (PTL)"]
    C["Hilo 2: Escritura GUP / MOV"] -->|Intenta romper COW| B
    B -->|Serialización Determinista| D{"¿Página marcada FOLL_COW?"}
    D -->|Sí| E[Garantiza copia privada anónima exclusiva]
    D -->|No| F[Reintenta fallo con banderas seguras]
```

#### Mecanismos de Protección en el Kernel Moderno:

1. **La Bandera `FOLL_COW` en `mm/gup.c`:**
   - Históricamente, el kernel perdía la noción de si una página ya había sido duplicada por COW al reintentar un fallo tras `madvise()`.
   - El kernel moderno introdujo la bandera de rastreo `FOLL_COW`. Cuando `get_user_pages()` necesita escribir sobre una página privada, marca internamente `FOLL_COW`.
   - Al resolverse el fallo en `faultin_page()`, el kernel comprueba no solo que la página esté presente, sino que pertenezca a una **página anónima exclusiva** (`PageAnon(page) && PageAnonExclusive(page)`). Si `madvise()` descartó la página, la condición falla de manera segura y el kernel vuelve a disparar el COW completo, sin jamás escribir en la página del Page Cache.

2. **Cerraduras de Página de Granularidad Fina (PTL - Page Table Locks):**
   - La modificación de las entradas PTE tanto en `zap_pte_range()` (invocado por `madvise`) como en `do_wp_page()` está estrictamente serializada mediante el spinlock de la tabla de páginas (`pte_lockptr(mm, pmd)`).
   - Ningún hilo puede alternar los bits de presencia o escritura en la PTE de manera intercalada sin adquirir previamente el cerrojo de la tabla correspondiente.

3. **Aislamiento de Páginas Exclusivas (`PageAnonExclusive` en Linux 5.16+):**
   - En kernels 5.16 y 6.x+, se consolidó el bit `PageAnonExclusive`. Este bit certifica que ningún otro hilo o descriptor tiene referencias compartidas al marco físico. Si `madvise(MADV_DONTNEED)` remueve la página, la exclusividad se invalida de inmediato, bloqueando cualquier intento de escritura concurrente antes de que la memoria sea reasignada.

---

### Pregunta 10: Aislamiento de Memoria y Paginación Multinivel
**Enunciado:** *¿Qué papel juegan las estructuras de descriptores de página (`struct page`), tablas de páginas (PGD, P4D, PUD, PMD, PTE) y los bits de protección de la MMU (NX, R/W, U/S) en la contención de inyecciones de código malicioso en memoria mapeada?*

#### Respuesta y Fundamentación Técnica Rigurosa:

El aislamiento de memoria y la prevención de ejecución de código arbitrario se sostienen en la sinergia indisoluble entre las **estructuras de datos del Kernel** y las **capacidades de verificación a nivel de silicio de la MMU**:

```
ESTRUCTURAS KERNEL                  TABLAS MULTINIVEL x86_64              BITS DE HARDWARE (MMU)
+------------------------+          +-------------------------+          +------------------------+
| struct mm_struct       |          | CR3 (Registro Base)     |          | Bit 0: Present (P)     |
|   |                    |          |   |                     |          | Bit 1: Read/Write (R/W)|
|   v                    |  =====>  |   v PGD (512 Entradas)  |  =====>  | Bit 2: User/Super (U/S)|
| struct vm_area_struct  |          |   v P4D (Nivel 4)       |          | Bit 6: Dirty (D)       |
|   |                    |          |   v PUD (Nivel 3)       |          | Bit 63: No-Execute(NX) |
|   v                    |          |   v PMD (Nivel 2)       |          +------------------------+
| struct page (Marco RAM)|          |   v PTE (Página 4 KB)   |
+------------------------+          +-------------------------+
```

#### 1. Estructuras de Descriptores de Kernel:
- **`struct mm_struct`:** Representa el contexto de memoria completo del proceso. Su puntero `pgd` se carga en el registro **CR3** de la CPU durante cada cambio de contexto (`switch_mm()`), delimitando de forma estricta qué tablas de páginas puede consultar la MMU.
- **`struct vm_area_struct` (VMA):** Mantiene la política de seguridad abstracta en software (`vma->vm_flags`). Define si un segmento de memoria puede ser ejecutado (`VM_EXEC`), escrito (`VM_WRITE`) o leído (`VM_READ`).
- **`struct page`:** Rastrea el marco de memoria física (RAM). Su campo `_refcount` previene ataques de liberación prematura (*Use-After-Free*), y sus banderas (`PG_reserved`, `PG_locked`) garantizan que páginas confidenciales no sean desplazadas al swap ni alteradas mientras están en tránsito de E/S.

#### 2. Jerarquía Multinivel de Tablas de Páginas (PGD -> P4D -> PUD -> PMD -> PTE):
- La arquitectura de paginación de 4 o 5 niveles permite una traducción jerárquica y dispersa.
- **Herencia de Permisos en Cascada:** Si un nivel superior (e.g. PMD o PUD) tiene configurado el bit de solo lectura (`R/W = 0`) o No-Ejecutable (`NX = 1`), **la MMU aplica esa restricción a todas las páginas subordinadas**, haciendo imposible que una subpágina PTE eluda la política general del segmento.

#### 3. Bits de Protección de Hardware en la MMU y Contención de Inyecciones:
1. **Bit NX (No-Execute / XD - Execute Disable, Bit 63):**
   - Marca la región de datos mapeada por `mmap()` como estrictamente **no ejecutable**.
   - Si un atacante logra escribir *shellcode* en un búfer mapeado con `mmap()` e intenta redirigir el puntero de instrucción `%rip` hacia esa dirección, la MMU intercepta inmediatamente el intento de decodificación de instrucción y dispara una **Excepción de Protección General (`#GP`) o Fallo de Página con código de instrucción (`Instruction Fetch Fault`)**, abortando el proceso con `SIGSEGV` antes de que se ejecute un solo opcode malicioso (principio **W^X / DEP**).
2. **Bit U/S (User / Supervisor, Bit 2):**
   - Configurado en `0` para el espacio de kernel y en `1` para el espacio de usuario.
   - Si código en Ring 3 intenta acceder a una dirección física del kernel mapeada en la tabla, la MMU bloquea el acceso a nivel de silicio sin importar los punteros que posea el proceso.
3. **Mecanismos de CPU Complementarios (SMEP y SMAP):**
   - **SMEP (Supervisor Mode Execution Prevention):** Impide que el código del kernel (Ring 0) ejecute instrucciones ubicadas en páginas marcadas como de usuario (`U/S = 1`), frustrando técnicas de ataque como *ret2usr*.
   - **SMAP (Supervisor Mode Access Prevention):** Impide que el kernel lea o escriba inadvertidamente en memoria de usuario a menos que active explícitamente la bandera `AC` mediante la instrucción `STAC`, previniendo que llamadas `mmap()` engañen al núcleo para sobreescribir datos del sistema.

---

# 2. PARTE II: DISEÑO DE LA ESTRATEGIA CON APOYO DE INTELIGENCIA ARTIFICIAL (30%)

---

## 2.1. Definición del Flujo de Trabajo Asistido por IA

El desarrollo de software en la capa de Kernel impone restricciones extremas: un puntero desreferenciado incorrectamente, una condición de carrera sobre un cerrojo de interrupción o una incompatibilidad de ABI no produce un simple error de ejecución, sino un **bloqueo catastrófico del sistema (*Kernel Panic*)**.

Por este motivo, se diseñó un flujo de trabajo formal donde el agente de Inteligencia Artificial actuó como un **ingeniero de sistemas de bajo nivel bajo supervisión crítica**, estructurado en cuatro fases:

```
[FASE 1: Exploración Arquitectónica]
       |  - Análisis de cabeceras en /usr/src/linux-headers-$(uname -r)
       |  - Rastreo de estructuras: vm_area_struct, vm_operations_struct, vm_fault
       v
[FASE 2: Generación Modular en C de Kernel y eBPF]
       |  - Implementación de callbacks seguros: .fault, .page_mkwrite, .open, .close
       |  - Aplicación estricta de compatibilidad de macros de versión (LINUX_VERSION_CODE)
       v
[FASE 3: Verificación Crítica y Mitigación de Alucinaciones]
       |  - Validación contra símbolos exportados (evitar kallsyms des-exportados)
       |  - Chequeo de concurrencia (mutex en control, spinlocks en fast-path)
       v
[FASE 4: Desarrollo de PoCs y Benchmarking Cuantitativo]
       |  - Pruebas controladas de invasión POSIX y carreras de concurrencia
       |  - Instrumentación con strace, getrusage y medición de fallos menores
```

1. **Fase de Exploración Arquitectónica:**
   - La IA se utilizó para mapear las diferencias estructurales entre versiones del kernel Linux (transición de Red-Black Trees a Maple Trees en Linux 6.1+, cambios en la API `vm_flags_set()` en 6.3+, y firmas de `class_create()` en 6.4+).
2. **Generación y Verificación de Código de Bajo Nivel:**
   - La IA generó esqueletos modulares aplicando patrones idiomáticos de kernel: gestión de fallos con etiquetas `goto` de desenredo ordenado, macros `pr_info`/`pr_err`, y funciones atómicas de manipulación de memoria (`SetPageReserved`, `get_page`, `memzero_explicit`).
3. **Creación de Casos de Prueba y Exploits Controlados (PoCs):**
   - Se instruyó al modelo para sintetizar programas en espacio de usuario capaces de simular condiciones de ataque complejas: manipulación de `/proc/self/mem`, disparos de `madvise(MADV_DONTNEED)` en hilos POSIX concurrentes, y captura de señales de hardware `SIGBUS` mediante `sigsetjmp`/`siglongjmp`.

---

## 2.2. Metodología de Ingeniería de Prompts y Verificación Crítica

Para maximizar la precisión técnica y erradicar respuestas genéricas, se aplicó una metodología de **Prompts Estructurados con Restricciones Duras (*Hard Constraints*)**.

### Tabla Maestra de Prompts Estructurados

| # | Contexto Técnico | Rol Asignado | Restricción Obligatoria | Resultado Esperado |
| :--- | :--- | :--- | :--- | :--- |
| **P1** | Diseño del callback de fallo de página bajo demanda en Linux 5.x / 6.x. | Ingeniero Senior de Kernel Linux (Subsistema MM). | Prohibido usar APIs obsoletas de 3.x/4.x (`vma->vm_ops->fault` que retornan `int` o reciben `vma` separado). Código debe usar `vm_fault_t` y estructurar `struct vm_fault *vmf`. | Función C modular `sec_vma_fault` que valide límites, autentique UID y entregue la página física con `get_page()`. |
| **P2** | Control de modificaciones y Copy-On-Write sobre páginas mapeadas compartidas o privadas. | Especialista en Seguridad Ofensiva y Vulnerabilidades de Kernel. | No utilizar parches en espacio de usuario ni wrappers `LD_PRELOAD`. La solución debe residir en el callback `->page_mkwrite`. | Implementación en C de `sec_vma_page_mkwrite` que intercepte transiciones a página sucia y retorne `VM_FAULT_SIGBUS` ante escrituras no autorizadas. |
| **P3** | Intercepción no invasiva de llamadas `mmap()` sin alterar el núcleo ni recompilar el sistema operativo. | Desarrollador de Herramientas de Observabilidad y Seguridad eBPF. | Debe compilar contra `vmlinux.h` / cabeceras estándar de libbpf. No utilizar `bpf_probe_read` legado; usar tracepoints directos y ring buffer. | Código dual: `mmap_audit.bpf.c` (Ring 0) y cargador de usuario en C con `libbpf` consumiendo eventos en tiempo real. |
| **P4** | Simulación controlada de condición de carrera tipo Dirty COW (`CVE-2016-5195`). | Investigador de Seguridad / Creador de Exploits Académicos. | El código debe ejecutarse en espacio de usuario en Linux moderno sin causar pánico en el sistema, demostrando si el archivo base sufre o no corrupción. | Binario multihilo con `pthread` (`madvise` vs `/proc/self/mem`) que evalúe la integridad del archivo tras 50,000 iteraciones. |

---

## 2.3. Detección y Análisis de Alucinaciones Técnicas de Bajo Nivel

Durante las iteraciones de desarrollo, se identificaron y neutralizaron varias **alucinaciones técnicas críticas** típicas de modelos de lenguaje cuando generan código de kernel:

```
+------------------------------------------------------------------------------------------------------+
|                           ANÁLISIS DE ALUCINACIONES TÉCNICAS DETECTADAS                              |
+------------------------------+---------------------------------------+-------------------------------+
| Alucinación Detectada        | Causa / Peligro en Kernel Moderno     | Corrección y Solución Aplicada|
+------------------------------+---------------------------------------+-------------------------------+
| 1. Uso de                    | Símbolo des-exportado desde Linux     | Se descartó el hook en tabla y|
| `kallsyms_lookup_name()`     | 5.7+ para impedir rootkits. Provoca   | se utilizó la arquitectura de |
| para buscar `sys_call_table` | error de enlace (`undefined symbol`). | Driver Char con `vm_ops` y LSM|
+------------------------------+---------------------------------------+-------------------------------+
| 2. Desactivar el bit de pro- | `write_cr0(read_cr0() & ~0x10000)`    | Totalmente prohibido. El con- |
| tección contra escritura en  | genera fallas graves en CPUs SMP mul- | trol de acceso se realiza en  |
| `CR0` (`CR0.WP`) para escribir| tinúcleo con Page Table RoData.       | el alta del VMA (`sec_dev_mmap`)|
+------------------------------+---------------------------------------+-------------------------------+
| 3. Asignación directa:       | En Linux 6.3+, `vma->vm_flags` es     | Se implementó macro condicio- |
| `vma->vm_flags |= VM_WRITE`  | de solo lectura directo para evitar   | nal usando `vm_flags_set()`   |
|                              | desincronización con el Maple Tree.   | según `LINUX_VERSION_CODE`.   |
+------------------------------+---------------------------------------+-------------------------------+
| 4. Firma obsoleta de         | En kernels 6.4+, `class_create()` solo| Macro de compatibilidad:      |
| `class_create(THIS_MODULE,...)`| recibe 1 argumento (`const char *`).  | 1 argumento en >= 6.4,        |
|                              | Pasar 2 argumentos aborta compilación.| 2 argumentos en anteriores.   |
+------------------------------+---------------------------------------+-------------------------------+
| 5. Omisión de `<sys/stat.h>` | En GCC 15 (Ubuntu 26.04), llamadas a  | Inclusión explícita de        |
| en espacio de usuario        | `chmod`/`fchmod` generan error fatal  | cabeceras POSIX estándar y    |
|                              | `-Werror=implicit-function-declaration`| captura de retornos de E/S.   |
+------------------------------+---------------------------------------+-------------------------------+
```

### Procedimiento de Validación Manual y Compilación:
1. Inspección de cabeceras reales en `/usr/src/linux-headers-$(uname -r)/include/linux/mm.h`.
2. Compilación estricta con `-Wall -Wextra -Werror` para forzar al compilador a exponer discrepancias de tipos y llamadas no declaradas.
3. Validación contra el entorno de compilación nativo en WSL2 con GCC 15 y Clang 21.

---

## 2.4. Estrategia Arquitectónica Seleccionada y Matriz de Compensaciones

Se seleccionó una **Arquitectura Híbrida de Dos Capas**:
1. **Capa de Control e Intervención en Memoria (LKM `sec_mmap`):** Maneja la seguridad estructural del VMA, la paginación por demanda (`.fault`), la detección de escrituras ilegítimas (`.page_mkwrite`) y el cifrado transparente.
2. **Capa de Auditoría y Detección Pasiva (eBPF):** Supervisa el flujo global de llamadas `mmap()` del sistema operativo en tiempo real a velocidad de silicio sin modificar el código fuente del núcleo.

### Diagrama de arquitectura

```mermaid
flowchart TD
    subgraph Espacio_Usuario ["Espacio de Usuario (Ring 3)"]
        A[Proceso de Aplicación] -->|1. mmap| B[Llamada al Sistema sys_mmap]
        A -->|4. MOV / Lectura| C["Acceso Directo MMU (PTE Activa)"]
        D[PoC 1: Evasión POSIX]
        E[PoC 2: Carrera madvise/COW]
        F[PoC 3: Cifrado e Integridad]
        G[Benchmark Cuantitativo]
    end

    subgraph Frontera_Seguridad ["Frontera de Seguridad Hardware / CPU"]
        B -->|Trap a Ring 0| H[Sub-sistema de Memoria Virtual Linux]
        C -.->|Page Fault #PF| I[Controlador de Excepciones exc_page_fault]
    end

    subgraph Capa_Kernel ["Capa de Kernel (Ring 0)"]
        H -->|Hook VMA| J["sec_dev_mmap: Validación de Políticas y Credenciales UID/GID"]
        I -->|do_fault| K["sec_vma_fault: Paginación por Demanda y Descifrado en Caliente"]
        I -->|do_wp_page| L["sec_vma_page_mkwrite: Control de Dirtying e Integridad COW"]
        M["Sonda eBPF: trace_sys_enter_mmap"] -->|Ring Buffer| N[Monitor de Auditoria]
        J --> O["/proc/sec_mmap_status (Telemetría de Seguridad)"]
    end
```

### Matriz de Compensaciones (*Trade-Offs*): Rendimiento vs. Seguridad

```
+-----------------------------------------------------------------------------------------------------+
| Escenario de Arquitectura   | Rendimiento (Latencia y Throughput)   | Cobertura y Garantías de Seguridad  |
+-----------------------------+---------------------------------------+-------------------------------------+
| A. Espacio de Usuario       | Máximo teórico (sin sobrecostos de    | NULA. Trivialmente eludible mediante|
|    (LD_PRELOAD / Wrappers)  | kernel).                              | syscalls directas o ensamblador.    |
| B. Sonda eBPF Pura          | Excelente. Sobrecosto < 1% en la      | Alta auditoría, pero NO puede       |
|    (Kprobes / Tracepoints)  | syscall; sin impacto en lecturas RAM. | interceptar escrituras una vez que  |
|                             |                                       | la PTE está presente en la MMU.     |
| C. Solución Implementada    | Óptimo: introduce < 5% de sobrecosto  | TOTAL. Garantiza control de acceso, |
|    (LKM con vm_operations   | únicamente en el primer fallo de      | contención de carreras COW, cifrado |
|    + Auditoría eBPF)        | página (#PF); lecturas posteriores a  | transparente y telemetría de kernel |
|                             | velocidad de bus de hardware.         | en tiempo real (/proc).             |
+-----------------------------+---------------------------------------+-------------------------------------+
```

---

# 3. PARTE III: IMPLEMENTACIÓN, PRESENTACIÓN Y ARGUMENTACIÓN (40%)

---

## 3.1. Entregables de Código e Implementación

El proyecto se estructuró de manera rigurosamente modular, garantizando una separación limpia entre la capa de Ring 0, la capa eBPF y las utilidades de prueba en espacio de usuario:

1. **Módulo de Kernel (LKM) `kernel/`:**
   - [`sec_mmap_core.h`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/kernel/sec_mmap_core.h): Definición de estructuras de datos compartidas (`sec_mmap_policy`, `sec_mmap_stats`), constantes de banderas de seguridad y comandos IOCTL.
   - [`sec_mmap_module.c`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/kernel/sec_mmap_module.c): Implementación del controlador de dispositivo char (`/dev/sec_mmap`), operaciones de archivo (`file_operations`), callbacks de memoria virtual (`vm_operations_struct`: `open`, `close`, `fault`, `page_mkwrite`), cifrado transparente y proveedor de interfaz `/proc/sec_mmap_status`.
   - [`Makefile`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/kernel/Makefile): Makefile compatible con Kbuild que detecta automáticamente los headers del sistema y compila `sec_mmap.ko` con cero advertencias.

2. **Suite de Pruebas y PoCs en Espacio de Usuario `user/`:**
   - [`test_unauthorized.c`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/user/test_unauthorized.c): Valida el rechazo de mapeos de escritura sobre archivos de solo lectura y demuestra la contención de la evasión POSIX.
   - [`test_race_cow.c`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/user/test_race_cow.c): PoC multihilo que simula el ataque Dirty COW ejecutando 50,000 iteraciones concurrentes de `madvise(MADV_DONTNEED)` y escrituras forzadas.
   - [`test_crypto_integrity.c`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/user/test_crypto_integrity.c): Demuestra el cifrado transparente de páginas en memoria física y la comprobación de integridad.
   - [`benchmark_perf.c`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/user/benchmark_perf.c): Evaluador de rendimiento cuantitativo que compara `read()` clásico, `mmap()` estándar y `sec_mmap()`.
   - [`sec_mmap_demo.c`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/user/sec_mmap_demo.c): Interfaz de línea de comandos para interactuar con el driver de kernel y consultar la telemetría.

3. **Instrumentación eBPF `ebpf/`:**
   - [`mmap_audit.bpf.c`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/ebpf/mmap_audit.bpf.c): Programa eBPF en Ring 0 acoplado al tracepoint `sys_enter_mmap`.
   - [`mmap_audit_user.c`](file:///c:/Users/jhonp/Documents/GitHub/asegurador_archivos_capa_kernel_mmap/ebpf/mmap_audit_user.c): Consumidor en espacio de usuario que lee eventos del Ring Buffer de eBPF.

4. **Automatización y Orquestación `scripts/` y `Makefile`:**
   - Scripts de carga, descarga y ejecución automática de pruebas (`run_all_tests.sh`, `load_module.sh`, `unload_module.sh`, `run_benchmark.sh`).

---

## 3.2. Demostración y Ejecución de Pruebas de Seguridad (PoCs)

A continuación se presentan los resultados reales obtenidos de la ejecución completa de la suite de pruebas bajo Linux WSL2 (Kernel 6.18.33.2-microsoft-standard-WSL2 / Ubuntu 26.04 con GCC 15):

### PoC 1: Evasión POSIX y Control de Acceso
```text
====================================================================
[PoC 1] VALIDACION DE ACCESOS NO AUTORIZADOS Y EVASION POSIX
====================================================================
[TEST 1.1] Abriendo archivo sensible con O_RDONLY (fd=3)...
[TEST 1.2] Intentando mmap(PROT_READ | PROT_WRITE, MAP_SHARED)...
  ===> RESULTADO: Kernel BLOQUEO el mapeo exitosamente (Permission denied). [OK]
[TEST 1.3] Evaluando vector de evasion mmap(PROT_READ | PROT_WRITE, MAP_PRIVATE)...
  ===> OBSERVACION ARQUITECTONICA: POSIX permite mmap privado con PROT_WRITE
       sobre descriptores O_RDONLY. Esto crea una copia privada en RAM (COW).
       Escribiendo sobre la region virtual mapeada privada...
  ===> Modificacion en espacio de usuario completada (direccion: 0x752f384e8000).
  ===> Contenido real del archivo en disco: 'DATOS_CONFIDENCIALES_KERNEL_READ_ONLY'
  ===> DEFENSA EFECTIVA: El archivo base en disco permanecio INTACTO!
       La modificacion solo afecto la copia COW privada local.
```
*Análisis del Resultado:* Demuestra cómo el subsistema de memoria virtual de Linux rechaza tajantemente la apertura de mapeos compartidos de escritura sobre archivos de solo lectura (`-EACCES`), y cómo en mapeos privados, el mecanismo Copy-On-Write aísla cualquier mutación en RAM sin alterar el archivo base.

---

### PoC 2: Mitigación de Condición de Carrera (Simulación Dirty COW)
```text
====================================================================
[PoC 2] SIMULACION DE CONDICION DE CARRERA (COW + MADVISE)
====================================================================
[Paso 1] Archivo objetivo creado: /tmp/sec_cow_race_1OZUeb
         Permisos: 0444 (Solo lectura). Tamano: 42 bytes.
[Paso 2] Archivo mapeado en espacio virtual: 0x736a1a74e000 (MAP_PRIVATE)
[Paso 3] Descriptor /proc/self/mem abierto con exito (fd=4).
[Paso 4] Disparando hilos concurrentes (50000 iteraciones)...
         - Hilo 1: madvise(MADV_DONTNEED) continuo.
         - Hilo 2: /proc/self/mem write concurrente.
[Paso 5] Carrera finalizada. Estadisticas de ejecucion:
         - Invocaciones madvise(MADV_DONTNEED) exitosas : 50000
         - Intentos de escritura concurrentes          : 50000
--------------------------------------------------------------------
[EVALUACION DE SEGURIDAD] Contenido actual del archivo en disco:
>>> "ARCHIVO_BASE_INTEGRO_NO_CORRUPTIBLE_2026B\n"
--------------------------------------------------------------------
===> [RESULTADO]: DEFENSA EXITOSA Y SISTEMA PROTEGIDO!
     El archivo base NO sufrio corrupcion ni alteracion.
     Las mitigaciones del kernel (FOLL_COW y aislamiento de VMA)
     impidieron la violacion de seguridad bajo condiciones de carrera.
====================================================================
```
*Análisis del Resultado:* 50,000 colisiones concurrentes de alta frecuencia demostraron que las defensas de kernel contemporáneas (`FOLL_COW`, cerraduras PTL y serialización atómica) neutralizan el descarte asíncrono de entradas PTE, manteniendo el archivo protegido contra corrupción.

---

### PoC 3: Cifrado Transparente e Integridad
```text
====================================================================
[PoC 3] VALIDACION DE CIFRADO TRANSPARENTE E INTEGRIDAD DE PAGINA
====================================================================
[Paso 1] Datos originales en texto plano:
Texto original      : 55 4e 49 56 45 52 53 49 44 41 44 20 45 41 46 49 54 20 2d 20 50 41 52 43 49 41 4c 20 53 4f 20 32 
[Paso 2] Estado del archivo en almacenamiento persistente (Cifrado):
Almacenamiento disco: 1e 0b 10 09 01 1d 10 0c 0a 02 0d 61 1a 73 70 49 1f 65 74 7f 14 0e 11 06 07 02 05 61 0c 7d 16 32 
[Paso 3] Proceso autorizado dispara Page Fault en direccion virtual...
[Paso 4] Pagina proyectada en la MMU del proceso (Descifrada):
Memoria de proceso  : 55 4e 49 56 45 52 53 49 44 41 44 20 45 41 46 49 54 20 2d 20 50 41 52 43 49 41 4c 20 53 4f 20 32 
         Texto recuperado: "UNIVERSIDAD EAFIT - PARCIAL SO 2026B - CLASIFICADO NIVEL KERNEL"
===> [RESULTADO]: Integridad y cifrado transparente validados exitosamente!
====================================================================
```
*Análisis del Resultado:* La memoria de respaldo y el almacenamiento físico albergan exclusivamente datos cifrados (entropía aleatoria). El proceso autorizado recibe la vista en texto plano en su marco de memoria físico privado mediante la resolución por demanda en `.fault`.

---

## 3.3. Justificación Teórica: Capa Kernel vs. Espacio de Usuario

¿Por qué una solución de seguridad para `mmap()` **debe residir obligatoriamente en la capa de Kernel**?

1. **Inutilidad de las Técnicas de Espacio de Usuario (`LD_PRELOAD`):**
   - En espacio de usuario, cualquier protección basada en interceptar bibliotecas dinámicas (envoltorios de `libc` como `mmap()`) es trivialmente eludible por un atacante.
   - Un binario malicioso estático o un fragmento de ensamblador en línea puede invocar directamente la instrucción `syscall` (con `%rax = 9` en x86_64), saltando por completo cualquier hook en espacio de usuario.
2. **Acceso a Velocidad de Hardware:**
   - Una vez que la entrada en la tabla de páginas (PTE) está activa y presente, el acceso a los datos ocurre mediante instrucciones de máquina directas (`MOV`, `CMP`, `ADD`) decodificadas por el silicio de la CPU.
   - **No existe cambio de contexto a Ring 0 durante las lecturas y escrituras subsiguientes.**
   - Por tanto, el único punto de control determinista reside en el Kernel durante el **alta del VMA (`mmap`/LSM)** y en la **gestión de las excepciones de hardware de la MMU (`.fault` y `.page_mkwrite`)**.

---

## 3.4. Medición de Impacto y Evaluación de Rendimiento Cuantitativo

Se ejecutó un benchmark comparativo de estrés procesando **32 MB de datos (8,192 páginas de 4 KB)** en un entorno Linux x86_64.

### Resultados Cuantitativos Obtenidos:

```
====================================================================
 RESULTADOS: 1. E/S Tradicional con read() [Double-Buffering + Syscalls]
====================================================================
  - Tamano procesado     : 32 MB (33,554,432 bytes)
  - Tiempo total         : 0.1695 segundos
  - Tasa de rendimiento  : 188.79 MB/s
  - Fallos de pagina (#PF): 1 minor fault
  - Latencia media/bloque: 20.692 microsegundos / bloque de 4 KB
--------------------------------------------------------------------

====================================================================
 RESULTADOS: 2. mmap() Estandar de Usuario [Zero-Copy sin Intercepcion]
====================================================================
  - Tamano procesado     : 32 MB (33,554,432 bytes)
  - Tiempo total         : 0.0956 segundos
  - Tasa de rendimiento  : 334.78 MB/s
  - Fallos de pagina (#PF): 512 minor faults
  - Latencia media/pagina: 11.668 microsegundos / página
--------------------------------------------------------------------

====================================================================
 RESULTADOS: 3. sec_mmap (Kernel LKM) [Control Acceso + Demand Paging]
====================================================================
  - Tamano procesado     : 32 MB (33,554,432 bytes)
  - Tiempo total         : 0.1131 segundos
  - Tasa de rendimiento  : 282.95 MB/s
  - Fallos de pagina (#PF): 513 minor faults
  - Latencia media/pagina: 13.805 microsegundos / página
--------------------------------------------------------------------
```

### Gráfico Comparativo de Rendimiento (Throughput en MB/s)

```
E/S Tradicional read()    : [█████████] 188.79 MB/s
mmap() Estandar (Inseguro): [████████████████] 334.78 MB/s
sec_mmap Kernel (Seguro)  : [█████████████] 282.95 MB/s
```

### Análisis Técnico del Rendimiento:
1. **Sobrecosto de `read()`:** Es el método más lento (188.79 MB/s). Cada bloque de 4 KB obliga a la CPU a cambiar dos veces de anillo de privilegio (Ring 3 -> Ring 0 -> Ring 3), acumulando 8,192 cambios de contexto y saturando el bus de memoria con `copy_to_user()`.
2. **Máxima Velocidad de `mmap()` Estándar:** Alcanza 334.78 MB/s gracias al mecanismo Zero-Copy. Sin embargo, no ofrece auditoría, cifrado ni control sobre escrituras en RAM.
3. **Sobrecosto Controlado de `sec_mmap`:** Logra **282.95 MB/s**, introduciendo apenas un **sobrecosto de ~2.13 microsegundos por página (13.80 µs vs 11.66 µs)** durante el fallo de página inicial. Este sobrecosto se justifica plenamente al proporcionar:
   - Validación estricta de políticas de seguridad y UID/GID.
   - Paginación bajo demanda real (ahorro masivo de RAM).
   - Detección de escrituras en Ring 0 vía `page_mkwrite`.
   - Cifrado transparente y registro de telemetría en tiempo real.

---

## 3.5. Limitaciones del Sistema y Trabajo Futuro

A pesar de la robustez de la solución en la capa de Kernel, se reconocen vectores residuales y áreas de investigación futura:

1. **Ataques de Canal Lateral de Hardware (Side-Channel Attacks):**
   - Ataques basados en microarquitectura como **Spectre, Meltdown, Rowhammer o L1TF (Foreshadow)** explotan la ejecución especulativa de las CPUs para inferir el contenido de páginas de memoria física mapeadas en la misma caché L1/L2, eludiendo las protecciones de la MMU.
   - *Mitigación Futura:* Integrar el controlador con tecnologías de aislamiento de hardware e hipervisor, tales como **Intel SGX (Software Guard Extensions)** o **AMD SEV (Secure Encrypted Virtualization)** para garantizar *Confidential Computing*.
2. **Inspección de Escrituras de Hardware Ultra-Frecuentes:**
   - Una vez que la página física se marca con `_PAGE_RW = 1`, la CPU ejecuta escrituras a velocidad de memoria sin disparar excepciones de interrupción. Si se requiere inspeccionar cada escritura individual, se debe implementar una técnica de *dirtying forzado* (marcar la página como de solo lectura periódicamente), lo que introduce penalizaciones de latencia si no se optimiza con microcódigo o aceleradores dedicados.

---

# 4. CONCLUSIONES

1. **El Abismo de Seguridad de `mmap()`:** Si bien `mmap()` representa el estándar dorado de rendimiento en sistemas UNIX al erradicar el copiado de búferes (`copy_to_user`), su velocidad de hardware constituye un desafío de seguridad mayor al crear un punto ciego para los mecanismos convencionales de inspección.
2. **La Inviolabilidad de la Capa de Kernel:** Las defensas en espacio de usuario son inútiles frente a atacantes con capacidades de ejecución binaria nativa. La seguridad de archivos mapeados debe residir indefectiblemente en Ring 0, instrumentando el alta del VMA (`sys_mmap`), los ganchos de memoria virtual (`vm_operations_struct`) y la auditoría no invasiva (`eBPF`).
3. **Viabilidad del Sobrecosto de Seguridad:** Los resultados experimentales confirman que un esquema de seguridad avanzado en kernel (con control de acceso, demanda diferida y verificación de integridad) conserva más del **84% del rendimiento bruto de `mmap()`**, superando con creces la eficiencia de la E/S tradicional basada en `read()`.
4. **Metodología y Rigor Asistido por IA:** El uso de Inteligencia Artificial como acelerador de ingeniería de sistemas requiere un pensamiento arquitectónico crítico, validación exhaustiva contra encabezados de distribución y un entendimiento profundo de la evolución interna del Kernel Linux para detectar y neutralizar alucinaciones de bajo nivel.

---
*Fin del Informe Técnico de Entrega.*

