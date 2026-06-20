# SPDX-License-Identifier: GPL-2.0-only
MODULE_NAME := cksu
$(MODULE_NAME)-objs := \
	src/ksymless/ksymless.o \
	src/supercall/supercall.o \
	src/supercall/dispatch.o \
	src/supercall/auth.o \
	src/policy/allowlist.o \
	src/policy/context.o \
	src/policy/virt_selinux.o \
	src/hooks/kprobe.o \
	src/hooks/selinux.o \
	src/hooks/audit.o \
	src/hooks/elevate.o \
	src/hooks/execve.o \
	src/hooks/access.o \
	src/boot/rc_inject.o \
	src/main.o
obj-m := $(MODULE_NAME).o

ccflags-y += -I$(src)/src -I$(src)/src/ksymless -I$(src)/src/hooks
ccflags-y += -I$(src)/src/supercall -I$(src)/src/policy -I$(src)/src/boot
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
ccflags-y += -Wno-unused-function
ccflags-y += -Wno-strict-prototypes
ccflags-y += -Wno-gcc-compat
ccflags-y += -std=gnu11

KDIR ?= /home/Dere3046/code/cyta/kernel
PWD := $(shell pwd)

all:
	make -C $(KDIR) M=$(PWD) LLVM=1 modules

clean:
	make -C $(KDIR) M=$(PWD) LLVM=1 clean
