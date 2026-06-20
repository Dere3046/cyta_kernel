// SPDX-License-Identifier: GPL-2.0-only
/*
 * access.c — faccessat/newfstatat hooks via tracepoint dispatcher
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
#define SU_PATH_LEN 15
#define SH_PATH "/system/bin/sh"

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
