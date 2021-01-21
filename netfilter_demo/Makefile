KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m := hook.o

.PHONY: all clean

all: build

.PHONY:build
build:
	echo $(MAKE)
	echo $(KERNELDIR)
	echo $(PWD)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	echo $(RM)
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

