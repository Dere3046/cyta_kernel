// SPDX-License-Identifier: GPL-2.0-only
/*
 * access.c — faccessat/newfstatat hooks: KP-style path rewrite for su compat
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "kprobe.h"
#include "access.h"
#include "allowlist.h"

#define SU_PATH "/system/bin/su"
#define SU_PATH_LEN 15
#define SH_PATH "/system/bin/sh"

static struct cksu_hook hook_faccessat;
static struct cksu_hook hook_newfstatat;

static bool is_su_access(const char __user *upath)
{
	char first;
	char kbuf[SU_PATH_LEN + 2];
	long len;

	if (get_user(first, upath))
		return false;
	if (first != '/')
		return false;

	len = strncpy_from_user(kbuf, upath, sizeof(kbuf));
	if (len != SU_PATH_LEN)
		return false;

	return memcmp(kbuf, SU_PATH, SU_PATH_LEN) == 0;
}

static int handler_faccessat(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *ur = (struct pt_regs *)regs->regs[0];
	const char __user *pathname = (const char __user *)ur->regs[1];
	uid_t uid;

	if (!cksu_allowlist_count())
		return 0;

	if (!is_su_access(pathname))
		return 0;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!cksu_uid_allowed(uid))
		return 0;

	char __user *sp = (char __user *)(ur->sp - 32);
	if (!copy_to_user(sp, SH_PATH, sizeof(SH_PATH)))
		ur->regs[1] = (unsigned long)sp;

	return 0;
}

static int handler_newfstatat(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *ur = (struct pt_regs *)regs->regs[0];
	const char __user *pathname = (const char __user *)ur->regs[1];
	uid_t uid;

	if (!cksu_allowlist_count())
		return 0;

	if (!is_su_access(pathname))
		return 0;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!cksu_uid_allowed(uid))
		return 0;

	char __user *sp = (char __user *)(ur->sp - 32);
	if (!copy_to_user(sp, SH_PATH, sizeof(SH_PATH)))
		ur->regs[1] = (unsigned long)sp;

	return 0;
}

int cksu_access_init(void)
{
	int ret;

	ret = cksu_hook_install(&hook_faccessat, "__arm64_sys_faccessat",
				handler_faccessat);
	if (ret)
		return ret;

	ret = cksu_hook_install(&hook_newfstatat, "__arm64_sys_newfstatat",
				handler_newfstatat);
	if (ret) {
		cksu_hook_remove(&hook_faccessat);
		return ret;
	}

	return 0;
}

void cksu_access_exit(void)
{
	cksu_hook_remove(&hook_newfstatat);
	cksu_hook_remove(&hook_faccessat);
}
