// SPDX-License-Identifier: GPL-2.0-only
/*
 * execve.c — execve hook via tracepoint dispatcher: root key + su compat
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <asm/unistd.h>
#include "execve.h"
#include "syscall_hook.h"
#include "elevate.h"
#include "allowlist.h"

#ifndef ROOT_KEY
#define ROOT_KEY "cksu_2026_dere3046_f8a3b7c1d9e2x4z6w0q5"
#endif

#define ROOT_KEY_LEN (sizeof(ROOT_KEY) - 1)
#define CSUD_PATH "/data/adb/cksu/bin/csud"
#define SH_PATH "/system/bin/sh"

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

static long hook_execve(int nr, const struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[0];
	uid_t uid;

	if (match_root_key(filename)) {
		cksu_elevate();
		goto orig;
	}

	if (!cksu_allowlist_count())
		goto orig;

	if (is_su_path(filename)) {
		uid = from_kuid(&init_user_ns, current_uid());
		if (cksu_uid_allowed(uid)) {
			struct file *f;
			const char *target;
			size_t tlen;

			f = filp_open(CSUD_PATH, O_PATH, 0);
			if (!IS_ERR(f)) {
				filp_close(f, NULL);
				target = CSUD_PATH;
				tlen = sizeof(CSUD_PATH);
			} else {
				target = SH_PATH;
				tlen = sizeof(SH_PATH);
			}

			cksu_elevate();
			char __user *sp = (char __user *)(current_pt_regs()->sp - 64);
			if (!copy_to_user(sp, target, tlen))
				((struct pt_regs *)regs)->regs[0] = (unsigned long)sp;
		}
	}

orig:
	return cksu_sct[nr](regs);
}

int cksu_execve_init(void)
{
	return cksu_register_syscall_hook(__NR_execve, hook_execve);
}

void cksu_execve_exit(void)
{
	cksu_unregister_syscall_hook(__NR_execve);
}
