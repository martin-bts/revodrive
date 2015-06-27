# If your platform does not support discard alignment, granularity and zeros, uncomment the following line
#DISABLE_DISCARD_TUNING := 1

ifeq ($(DISABLE_DISCARD_TUNING), 1)
EXTRA_CFLAGS += -DDISABLE_DISCARD_TUNING
endif
obj-m := ../../../../../../usr/src/oczpcie/ oczvca.o
oczvca-objs := vca_ossp.o
EXTRA_LDFLAGS := $(M)/vcalib.ol

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -f vca_ossp.o
	rm -rf *.ko
	rm -rf *.mod.c
	rm -rf modules.order Module.symvers
