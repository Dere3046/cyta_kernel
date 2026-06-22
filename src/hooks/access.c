// SPDX-License-Identifier: GPL-2.0-only
/*
 * access.c — faccessat/newfstatat hooks via tracepoint dispatcher
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include "access.h"
#include "syscall_hook.h"
#include "allowlist.h"
#include "cksu_sym.h"

#define SH_PATH "/system/bin/sh"

static bool is_su_access(const char __user *upath)
{
	char kbuf[CKSU_SU_PATH_MAX];
	long len;
	const char *su_path = cksu_get_su_path();

	len = strncpy_from_user(kbuf, upath, sizeof(kbuf));
	if (len <= 0)
		return false;

	return strcmp(kbuf, su_path) == 0;
}

static long hook_faccessat(int nr, const struct pt_regs *regs)
{
	const char __user *pathname = (const char __user *)regs->regs[1];
	uid_t uid;

	if (!cksu_allowlist_count())
		goto orig;

	if (!is_su_access(pathname))
		goto orig;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!cksu_uid_allowed(uid))
		goto orig;

	char __user *sp = (char __user *)(current_pt_regs()->sp - 32);
	if (!copy_to_user(sp, SH_PATH, sizeof(SH_PATH)))
		((struct pt_regs *)regs)->regs[1] = (unsigned long)sp;

orig:
	return cksu_sct[nr](regs);
}

static long hook_newfstatat(int nr, const struct pt_regs *regs)
{
	const char __user *pathname = (const char __user *)regs->regs[1];
	uid_t uid;

	if (!cksu_allowlist_count())
		goto orig;

	if (!is_su_access(pathname))
		goto orig;

	uid = from_kuid(&init_user_ns, current_uid());
	if (!cksu_uid_allowed(uid))
		goto orig;

	char __user *sp = (char __user *)(current_pt_regs()->sp - 32);
	if (!copy_to_user(sp, SH_PATH, sizeof(SH_PATH)))
		((struct pt_regs *)regs)->regs[1] = (unsigned long)sp;

orig:
	return cksu_sct[nr](regs);
}

int cksu_access_init(void)
{
	int ret;

	ret = cksu_register_syscall_hook(__NR_faccessat, hook_faccessat);
	if (ret)
		return ret;

	ret = cksu_register_syscall_hook(__NR_newfstatat, hook_newfstatat);
	if (ret) {
		cksu_unregister_syscall_hook(__NR_faccessat);
		return ret;
	}

	return 0;
}

void cksu_access_exit(void)
{
	cksu_unregister_syscall_hook(__NR_newfstatat);
	cksu_unregister_syscall_hook(__NR_faccessat);
}
