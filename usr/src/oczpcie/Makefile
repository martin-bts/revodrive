
# Configuration options

# If your platform does not support threaded interrupts, uncomment the following line
#DISABLE_THREADED_INTERRUPTS := 1
# If your platform does not support discard alignment, granularit and zeros, uncomment the following line
#DISABLE_DISCARD_TUNING := 1

EXTRA_CFLAGS += -DENABLE_VCA
ifneq ($(KERNELRELEASE),)
EXTRA_CFLAGS += -D__LINUX__
ifeq ($(DISABLE_THREADED_INTERRUPTS), 1)
EXTRA_CFLAGS += -DDISABLE_THREADED_INTERRUPTS
endif
ifeq ($(DISABLE_DISCARD_TUNING), 1)
EXTRA_CFLAGS += -DDISABLE_DISCARD_TUNING
endif
	obj-m := oczpcie.o
	oczpcie-objs := oczpcie_iface.o oczpcie_main.o vca_iface.o chip.o ioctl.o sg_io.o util.o oczpcie_spi.o diag.o
else
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	bash stamp_version || true
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules


clean:
	rm -f *.o
	rm -rf *.ko
	rm -rf *.mod.c
	rm -rf modules.order Module.symvers

endif
