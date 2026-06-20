MODULE_NAME := cksu
$(MODULE_NAME)-objs := src/ksymless_core.o src/ksymless_verify.o src/resolve.o src/hook.o src/selinux_bypass.o src/su_elevate.o src/audit_filter.o src/module_main.o
obj-m := $(MODULE_NAME).o

ccflags-y += -Isrc
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-strict-prototypes

KDIR ?= /home/Dere3046/code/cyta/kernel
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) LLVM=1 modules

clean:
	make -C $(KDIR) M=$(PWD) LLVM=1 clean
