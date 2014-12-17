obj-m += mcc.o
mcc-y = mcc_linux.o mcc_shm_linux.o mcc_sema4_linux.o mcc_common.o

PWD := $(shell pwd)

EXTRA_CFLAGS += -I$(KERNELDIR)/include -Wno-format

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

install: all
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install INSTALL_MOD_PATH=$(DESTDIR)
	@echo Copying mcc headers to toolchain
	mkdir -p $(DESTDIR)/usr/include/linux
	cp -f {mcc_linux.h,mcc_common.h,mcc_config.h} $(DESTDIR)/usr/include/linux/


clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
