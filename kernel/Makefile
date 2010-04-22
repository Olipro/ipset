ifneq ($(KERNELRELEASE),)
include Kbuild
else
KERNELDIR := /lib/modules/`uname -r`/build
all::
	$(MAKE) -C $(KERNELDIR) M=`pwd` $@
endif
