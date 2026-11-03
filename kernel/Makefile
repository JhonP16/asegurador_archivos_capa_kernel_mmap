# Makefile para el Modulo de Kernel sec_mmap
# Sistemas Operativos - EAFIT 2026-B

obj-m += sec_mmap.o
sec_mmap-objs := sec_mmap_module.o

# Autodeteccion robusta de KDIR: primero el kernel en ejecucion, luego cualquier build disponible en /lib/modules/
KDIR ?= $(shell if [ -d /lib/modules/$$(uname -r)/build ]; then echo /lib/modules/$$(uname -r)/build; else ls -d /lib/modules/*/build 2>/dev/null | head -n 1; fi)
PWD := $(shell pwd)

EXTRA_CFLAGS += -Wall -Wextra -Wno-unused-parameter

all:
	@echo "===> Compilando modulo LKM sec_mmap con KDIR=$(KDIR)"
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f *.o *.ko *.mod.* *.order *.symvers .*.cmd .tmp_versions

load:
	sudo insmod sec_mmap.ko
	sudo chmod 666 /dev/sec_mmap

unload:
	sudo rmmod sec_mmap

.PHONY: all clean load unload

