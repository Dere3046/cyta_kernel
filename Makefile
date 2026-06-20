# SPDX-License-Identifier: GPL-2.0-only
MODULE_NAME := cksu
$(MODULE_NAME)-objs := src/ksymless/ksymless.o src/hooks/kprobe.o \
	src/hooks/selinux.o src/hooks/elevate.o src/hooks/audit.o src/main.o
obj-m := $(MODULE_NAME).o

ccflags-y += -Isrc -Isrc/ksymless -Isrc/hooks
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
