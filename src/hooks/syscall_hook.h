// SPDX-License-Identifier: GPL-2.0-only
// Derived from KernelSU (GPL-2.0)
#ifndef CKSU_SYSCALL_HOOK_H
#define CKSU_SYSCALL_HOOK_H

#include <asm/syscall.h>

typedef long (*cksu_syscall_hook_fn)(int nr, const struct pt_regs *regs);

extern syscall_fn_t *cksu_sct;

int cksu_syscall_hook_init(void);
void cksu_syscall_hook_exit(void);
int cksu_register_syscall_hook(int nr, cksu_syscall_hook_fn fn);
void cksu_unregister_syscall_hook(int nr);

#endif
