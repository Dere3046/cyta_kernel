// SPDX-License-Identifier: GPL-2.0-only
/*
 * access.c — faccessat/newfstatat hooks via syscall table patching
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include "access.h"
#include "syscall_hook.h"
#include "allowlist.h"

#define SU_PATH "/system/bin/su"

static cksu_syscall_fn orig_faccessat;
static cksu_syscall_fn orig_newfstatat;

static bool is_su_access(const char __user *upath)
{
	char kbuf[32];
	long len;

	len = strncpy_from_user(kbuf, upath, sizeof(kbuf));
	if (len <= 0)
		return false;

	return strcmp(kbuf, SU_PATH) == 0;
}

static long __nocfi hook_faccessat(const struct pt_regs *regs)
{
	const char __user *pathname = (const char __user *)regs->regs[1];
	uid_t uid;

	if (is_su_access(pathname)) {
		uid = from_kuid(&init_user_ns, current_uid());
		if (cksu_uid_allowed(uid))
			return 0;
	}

	return orig_faccessat(regs);
}

static long __nocfi hook_newfstatat(const struct pt_regs *regs)
{
	const char __user *pathname = (const char __user *)regs->regs[1];
	uid_t uid;

	if (is_su_access(pathname)) {
		uid = from_kuid(&init_user_ns, current_uid());
		if (cksu_uid_allowed(uid))
			return 0;
	}

	return orig_newfstatat(regs);
}

int cksu_access_init(void)
{
	int ret;

	ret = cksu_syscall_replace(__NR_faccessat, hook_faccessat, &orig_faccessat);
	if (ret)
		return ret;

	ret = cksu_syscall_replace(__NR_newfstatat, hook_newfstatat, &orig_newfstatat);
	if (ret) {
		cksu_syscall_restore(__NR_faccessat);
		return ret;
	}

	return 0;
}

void cksu_access_exit(void)
{
	cksu_syscall_restore(__NR_newfstatat);
	cksu_syscall_restore(__NR_faccessat);
}
