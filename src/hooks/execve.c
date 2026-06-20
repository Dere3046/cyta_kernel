// SPDX-License-Identifier: GPL-2.0-only
/*
 * execve.c — execve hook via syscall table: root key + su compat
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include "execve.h"
#include "syscall_hook.h"
#include "elevate.h"
#include "allowlist.h"

#ifndef ROOT_KEY
#define ROOT_KEY "cksu_2026_dere3046_f8a3b7c1d9e2x4z6w0q5"
#endif

#define ROOT_KEY_LEN (sizeof(ROOT_KEY) - 1)

static cksu_syscall_fn orig_execve;

static bool match_root_key(const char __user *ufilename)
{
	char kbuf[ROOT_KEY_LEN + 8];
	long len;

	len = strncpy_from_user(kbuf, ufilename, sizeof(kbuf));
	if (len != ROOT_KEY_LEN)
		return false;

	return memcmp(kbuf, ROOT_KEY, ROOT_KEY_LEN) == 0;
}

static bool is_su_path(const char __user *ufilename)
{
	char kbuf[256];
	char *base, *p;
	long len;

	len = strncpy_from_user(kbuf, ufilename, sizeof(kbuf));
	if (len <= 0)
		return false;

	base = kbuf;
	for (p = kbuf; *p; p++) {
		if (*p == '/')
			base = p + 1;
	}

	return base[0] == 's' && base[1] == 'u' && base[2] == '\0';
}

static long __nocfi hook_execve(const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[0];
	uid_t uid;

	if (match_root_key(filename)) {
		cksu_elevate();
		return orig_execve(regs);
	}

	if (is_su_path(filename)) {
		uid = from_kuid(&init_user_ns, current_uid());
		if (cksu_uid_allowed(uid))
			cksu_elevate();
	}

	return orig_execve(regs);
}

int cksu_execve_init(void)
{
	return cksu_syscall_replace(__NR_execve, hook_execve, &orig_execve);
}

void cksu_execve_exit(void)
{
	cksu_syscall_restore(__NR_execve);
}
