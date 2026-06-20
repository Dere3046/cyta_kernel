// SPDX-License-Identifier: GPL-2.0-only
/*
 * selinux.c — hook avc_denied, bypass SELinux for root
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include "kprobe.h"
#include "selinux.h"

static struct cksu_hook hook_avc_denied;

static int handler_avc_denied(struct kprobe *p, struct pt_regs *regs)
{
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID)) {
		regs->regs[0] = 0;
		regs->pc = regs->regs[30];
		return 1;
	}
	return 0;
}

int cksu_selinux_init(void)
{
	return cksu_hook_install(&hook_avc_denied, "avc_denied",
				 handler_avc_denied);
}

void cksu_selinux_exit(void)
{
	cksu_hook_remove(&hook_avc_denied);
}
