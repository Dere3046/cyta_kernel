// SPDX-License-Identifier: GPL-2.0-only
/*
 * selinux.c — hook avc_denied, bypass SELinux via virtual policy
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include "kprobe.h"
#include "selinux.h"
#include "context.h"
#include "virt_selinux.h"

static struct cksu_hook hook_avc_denied;

static int handler_avc_denied(struct kprobe *p, struct pt_regs *regs)
{
	uid_t uid;
	u32 ssid, tsid, requested;
	u16 tclass;

	if (cksu_is_blessed())
		goto allow;

	uid = from_kuid(&init_user_ns, current_uid());

	if (cksu_virt_uid_has_domain(uid)) {
		ssid = (u32)regs->regs[1];
		tsid = (u32)regs->regs[2];
		tclass = (u16)regs->regs[3];
		requested = (u32)regs->regs[4];

		if (cksu_virt_is_permissive(ssid))
			goto allow;
		if (cksu_virt_check(ssid, tsid, tclass, requested))
			goto allow;
	}

	return 0;

allow:
	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
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
