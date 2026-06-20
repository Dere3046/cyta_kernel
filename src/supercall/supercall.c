// SPDX-License-Identifier: GPL-2.0-only
/*
 * supercall.c — truncate syscall hook entry point
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "supercall.h"
#include "auth.h"
#include "dispatch.h"

static struct kprobe supercall_kp;

static int supercall_pre_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *ur = (struct pt_regs *)regs->regs[0];
	const char __user *u_arg0 = (const char __user *)ur->regs[0];
	long cmd = (long)ur->regs[1];
	long arg1 = (long)ur->regs[2];
	long arg2 = (long)ur->regs[3];
	u8 resp[CKSU_HASH_LEN];
	long ret;

	if (cmd < CKSU_HELLO || cmd > CKSU_SET_KEY)
		return 0;

	if (cmd == CKSU_HELLO || cmd == CKSU_GET_CHALLENGE) {
		ret = cksu_dispatch(NULL, 0, cmd, arg1, arg2);
	} else {
		if (copy_from_user(resp, u_arg0, CKSU_HASH_LEN))
			return 0;
		ret = cksu_dispatch((const char *)resp, CKSU_HASH_LEN, cmd, arg1, arg2);
	}

	regs->regs[0] = (unsigned long)ret;
	regs->pc = regs->regs[30];
	return 1;
}

int cksu_supercall_init(void)
{
	int ret;

	supercall_kp.symbol_name = "__arm64_sys_truncate";
	supercall_kp.pre_handler = supercall_pre_handler;

	ret = register_kprobe(&supercall_kp);
	if (!ret)
		pr_info("[cksu] supercall ready\n");
	return ret;
}

void cksu_supercall_exit(void)
{
	unregister_kprobe(&supercall_kp);
}
