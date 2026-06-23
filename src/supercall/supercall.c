// SPDX-License-Identifier: GPL-2.0-only
/*
 * supercall.c — truncate syscall hook with key-derived magic + version guard
 */

#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include "supercall.h"
#include "auth.h"
#include "dispatch.h"
#include "syscall_hook.h"
#include "sha256.h"
#include "context.h"
#include "virt_selinux.h"

static u32 supercall_magic;

static long hook_truncate(int nr, const struct pt_regs *regs);

int cksu_supercall_init(const char *key)
{
	int ret;
	u8 hash[32];

	if (key && key[0]) {
		cksu_sha256((const u8 *)key, strlen(key), hash);
		supercall_magic = *(u32 *)hash;
	}

	ret = cksu_register_syscall_hook(__NR_truncate, hook_truncate);
	if (!ret)
		pr_info("[cksu] supercall ready\n");
	return ret;
}

static long hook_truncate(int nr, const struct pt_regs *regs)
{
	const char __user *u_arg0 = (const char __user *)regs->regs[0];
	u64 raw = (u64)regs->regs[1];
	long arg1 = (long)regs->regs[2];
	long arg2 = (long)regs->regs[3];
	u8 resp[CKSU_HASH_LEN];
	u32 magic;
	u16 version, cmd;
	long ret;

	if (cksu_is_blessed() || cksu_virt_get_cred_sid(current_cred())) {
		cmd = (u16)(raw & 0xFFFF);
		return cksu_dispatch(NULL, 0, cmd, arg1, arg2);
	}

	magic = (u32)(raw >> 32);
	if (magic != supercall_magic)
		return cksu_sct[nr](regs);

	version = (u16)((raw >> 16) & 0xFFFF);
	if (version != CKSU_VERSION)
		return cksu_sct[nr](regs);

	cmd = (u16)(raw & 0xFFFF);

	if (cmd == CKSU_HELLO || cmd == CKSU_GET_CHALLENGE) {
		ret = cksu_dispatch(NULL, 0, cmd, arg1, arg2);
	} else {
		if (copy_from_user(resp, u_arg0, CKSU_HASH_LEN))
			return cksu_sct[nr](regs);
		ret = cksu_dispatch((const char *)resp, CKSU_HASH_LEN, cmd, arg1, arg2);
	}

	return ret;
}

void cksu_supercall_exit(void)
{
	cksu_unregister_syscall_hook(__NR_truncate);
}
