// SPDX-License-Identifier: GPL-2.0-only
/*
 * supercall.c — truncate syscall hook entry point (via table patching)
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include "supercall.h"
#include "auth.h"
#include "dispatch.h"
#include "syscall_hook.h"

static cksu_syscall_fn orig_truncate;

static long __nocfi hook_truncate(const struct pt_regs *regs)
{
	const char __user *u_arg0 = (const char __user *)regs->regs[0];
	long cmd = (long)regs->regs[1];
	u8 resp[CKSU_HASH_LEN];
	long ret;

	if (cmd < CKSU_HELLO || cmd > CKSU_SET_KEY)
		return orig_truncate(regs);

	if (cmd == CKSU_HELLO || cmd == CKSU_GET_CHALLENGE) {
		long arg1 = (long)regs->regs[2];
		ret = cksu_dispatch(NULL, 0, cmd, arg1, 0);
	} else {
		long arg1 = (long)regs->regs[2];
		long arg2 = (long)regs->regs[3];
		if (copy_from_user(resp, u_arg0, CKSU_HASH_LEN))
			return orig_truncate(regs);
		ret = cksu_dispatch((const char *)resp, CKSU_HASH_LEN, cmd, arg1, arg2);
	}

	return ret;
}

int cksu_supercall_init(void)
{
	int ret = cksu_syscall_replace(__NR_truncate, (cksu_syscall_fn)hook_truncate,
				       &orig_truncate);
	if (!ret)
		pr_info("[cksu] supercall ready\n");
	return ret;
}

void cksu_supercall_exit(void)
{
	cksu_syscall_restore(__NR_truncate);
}
