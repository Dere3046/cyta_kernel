// SPDX-License-Identifier: GPL-2.0-only
/*
 * elevate.c — root key trigger via __arm64_sys_execve hook
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/thread_info.h>
#include "kprobe.h"
#include "elevate.h"

#ifndef ROOT_KEY
#define ROOT_KEY "cksu_2026_dere3046_f8a3b7c1d9e2x4z6w0q5"
#endif

#define ROOT_KEY_LEN (sizeof(ROOT_KEY) - 1)

static struct cksu_hook hook_execve;

static void elevate_current_cred(void)
{
	struct cred *c = (struct cred *)current->cred;

	c->uid.val = 0;
	c->gid.val = 0;
	c->euid.val = 0;
	c->egid.val = 0;
	c->suid.val = 0;
	c->sgid.val = 0;
	c->fsuid.val = 0;
	c->fsgid.val = 0;
	c->securebits = 0;

	memset(&c->cap_effective, 0xFF, sizeof(c->cap_effective));
	memset(&c->cap_permitted, 0xFF, sizeof(c->cap_permitted));
	memset(&c->cap_bset, 0xFF, sizeof(c->cap_bset));
	memset(&c->cap_ambient, 0xFF, sizeof(c->cap_ambient));
	memset(&c->cap_inheritable, 0xFF, sizeof(c->cap_inheritable));

	clear_tsk_thread_flag(current, TIF_SECCOMP);
}

static int match_root_key(const char __user *ufilename)
{
	char kbuf[ROOT_KEY_LEN + 8];
	long len;

	len = strncpy_from_user(kbuf, ufilename, sizeof(kbuf));
	if (len != ROOT_KEY_LEN)
		return 0;

	return memcmp(kbuf, ROOT_KEY, ROOT_KEY_LEN) == 0;
}

static int handler_execve(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *user_regs = (struct pt_regs *)regs->regs[0];
	const char __user *filename = (const char __user *)user_regs->regs[0];

	if (match_root_key(filename)) {
		pr_info("[cksu] elevating uid=%d -> 0\n",
			from_kuid(&init_user_ns, current_uid()));
		elevate_current_cred();
	}
	return 0;
}

int cksu_su_init(void)
{
	pr_info("[cksu] root_key=%s\n", ROOT_KEY);
	return cksu_hook_install(&hook_execve, "__arm64_sys_execve",
				 handler_execve);
}

void cksu_su_exit(void)
{
	cksu_hook_remove(&hook_execve);
}
