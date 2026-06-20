// SPDX-License-Identifier: GPL-2.0-only
// Derived from KernelSU (GPL-2.0)
#ifndef CKSU_SYSCALL_HOOK_H
#define CKSU_SYSCALL_HOOK_H

#include <asm/syscall.h>

typedef long (*cksu_syscall_fn)(const struct pt_regs *regs);

int cksu_syscall_hook_init(void);
void cksu_syscall_hook_exit(void);
int cksu_syscall_replace(int nr, cksu_syscall_fn fn, cksu_syscall_fn *orig);
void cksu_syscall_restore(int nr);

#endif
