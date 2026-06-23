// SPDX-License-Identifier: GPL-2.0-only
/*
 * audit.c — hook audit_log_start, suppress audit for blessed + virtual domains
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include "kprobe.h"
#include "audit.h"
#include "context.h"
#include "virt_selinux.h"

static struct cksu_hook hook_audit_log_start;

static int handler_audit_log_start(struct kprobe *p, struct pt_regs *regs)
{
	if (cksu_is_blessed())
		goto suppress;

	if (cksu_virt_get_cred_sid(current_cred()))
		goto suppress;

	uid_t uid = from_kuid(&init_user_ns, current_uid());
	if (cksu_virt_uid_has_domain(uid))
		goto suppress;

	return 0;

suppress:
	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
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
