// SPDX-License-Identifier: GPL-2.0-only
// Derived from KernelSU (GPL-2.0)
/*
 * syscall_hook.c — direct syscall table patching
 *
 * Copyright (C) 2023 bmax121
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <asm/syscall.h>
#include "syscall_hook.h"
#include "patch_memory.h"

#include "ksymless.h"

static syscall_fn_t *sct;

struct hook_entry {
	int nr;
	syscall_fn_t orig;
};

static struct hook_entry entries[8];
static int entry_count;

int cksu_syscall_hook_init(void)
{
	sct = (syscall_fn_t *)kallsyms_name_to_addr("sys_call_table");
	if (!sct) {
		pr_err("[cksu] sys_call_table not found\n");
		return -ENOENT;
	}
	entry_count = 0;
	pr_info("[cksu] syscall_hook: table=0x%lx\n", (unsigned long)sct);
	return 0;
}

void cksu_syscall_hook_exit(void)
{
	for (int i = 0; i < entry_count; i++) {
		syscall_fn_t orig = entries[i].orig;
		int nr = entries[i].nr;
		if (cksu_patch_text(&sct[nr], &orig, sizeof(orig),
				    CKSU_PATCH_FLUSH_DCACHE))
			pr_err("[cksu] restore syscall %d failed\n", nr);
		else
			pr_info("[cksu] restored syscall %d\n", nr);
	}
	entry_count = 0;
}

int cksu_syscall_replace(int nr, cksu_syscall_fn fn, cksu_syscall_fn *orig)
{
	syscall_fn_t new_fn = (syscall_fn_t)fn;
	int ret;

	if (nr < 0 || nr >= __NR_syscalls)
		return -EINVAL;
	if (entry_count >= ARRAY_SIZE(entries))
		return -ENOMEM;

	if (orig)
		*orig = (cksu_syscall_fn)sct[nr];

	entries[entry_count].nr = nr;
	entries[entry_count].orig = sct[nr];
	entry_count++;

	ret = cksu_patch_text(&sct[nr], &new_fn, sizeof(new_fn),
			      CKSU_PATCH_FLUSH_DCACHE);
	if (ret) {
		entry_count--;
		pr_err("[cksu] patch syscall %d failed: %d\n", nr, ret);
		return ret;
	}

	pr_info("[cksu] hooked syscall %d\n", nr);
	return 0;
}

void cksu_syscall_restore(int nr)
{
	for (int i = 0; i < entry_count; i++) {
		if (entries[i].nr == nr) {
			syscall_fn_t orig = entries[i].orig;
			cksu_patch_text(&sct[nr], &orig, sizeof(orig),
					CKSU_PATCH_FLUSH_DCACHE);
			entries[i] = entries[--entry_count];
			return;
		}
	}
}
