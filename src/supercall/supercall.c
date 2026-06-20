// SPDX-License-Identifier: GPL-2.0-only
/*
 * supercall.c — truncate syscall hook via tracepoint dispatcher
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

static long hook_truncate(int nr, const struct pt_regs *regs)
{
	const char __user *u_arg0 = (const char __user *)regs->regs[0];
	long cmd = (long)regs->regs[1];
	long arg1 = (long)regs->regs[2];
	long arg2 = (long)regs->regs[3];
	u8 resp[CKSU_HASH_LEN];
	long ret;

	if (cmd < CKSU_HELLO || cmd > CKSU_CMD_MAX)
		return cksu_sct[nr](regs);

	if (cmd == CKSU_HELLO || cmd == CKSU_GET_CHALLENGE) {
		ret = cksu_dispatch(NULL, 0, cmd, arg1, arg2);
	} else {
		if (copy_from_user(resp, u_arg0, CKSU_HASH_LEN))
			return cksu_sct[nr](regs);
		ret = cksu_dispatch((const char *)resp, CKSU_HASH_LEN, cmd, arg1, arg2);
	}

	return ret;
}

int cksu_supercall_init(void)
{
	int ret = cksu_register_syscall_hook(__NR_truncate, hook_truncate);
	if (!ret)
		pr_info("[cksu] supercall ready\n");
	return ret;
}

void cksu_supercall_exit(void)
{
	cksu_unregister_syscall_hook(__NR_truncate);
}
