obj-m += hook.o
KERNELDIR ?= $(KERNEL_SRC)
PWD := $(shell pwd)
ccflags-y := -std=gnu99 -Wno-declaration-after-statement

all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
