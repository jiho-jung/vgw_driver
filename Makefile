CONFIG_MODULE_SIG=n
MODULE_NAME=vgw-driver

ifneq ($(KERNELRELEASE),)

obj-m += $(MODULE_NAME).o
$(MODULE_NAME)-objs := ct_netlink.o tcp_session.o
else

BASEDIR := /lib/modules/$(shell uname -r)
KERNELDIR ?= $(BASEDIR)/build
PWD :=$(shell pwd)

#KERNEL_GCC_VERSION := $(shell cat /proc/version | sed -n 's/.*gcc version \([[:digit:]]\.[[:digit:]]\.[[:digit:]]\).*/\1/p')
#CCVERSION = $(shell $(CC) -dumpversion)
#KVER = $(shell uname -r)
#KMAJ = $(shell echo $(KVER) | \
#sed -e 's/^\([0-9][0-9]*\)\.[0-9][0-9]*\.[0-9][0-9]*.*/\1/')
#KMIN = $(shell echo $(KVER) | \
#sed -e 's/^[0-9][0-9]*\.\([0-9][0-9]*\)\.[0-9][0-9]*.*/\1/')
#KREV = $(shell echo $(KVER) | \
#sed -e 's/^[0-9][0-9]*\.[0-9][0-9]*\.\([0-9][0-9]*\).*/\1/')
#kver_ge = $(shell \
#echo test | awk '{if($(KMAJ) < $(1)) {print 0} else { \
#if($(KMAJ) > $(1)) {print 1} else { \
#if($(KMIN) < $(2)) {print 0} else { \
#if($(KMIN) > $(2)) {print 1} else { \
#if($(KREV) < $(3)) {print 0} else { print 1 } \
#}}}}}' \
#)

VER="1-25-3"
KBUILD_CFLAGS +=

.PHONY:all 
all: clean modules #install

.PHONY:modules
modules:
	 KCPPFLAGS="-DMODULE_VER=\"$(VER)\"" make -C $(KERNELDIR) M=$(PWD) CFLAGS_MODULE="-DMODULE_VER=$(VER)" modules 

.PHONY:install
install:
	make -C $(KERNELDIR) M=$(PWD) modules_install

.PHONY:clean 
clean:
	make -C $(KERNELDIR) M=$(PWD) clean

endif 



