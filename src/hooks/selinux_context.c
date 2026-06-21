// SPDX-License-Identifier: GPL-2.0-only
/*
 * selinux_context.c — fake SELinux context via virtual SID
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include "kprobe.h"
#include "virt_selinux.h"
#include "context.h"

static struct cksu_hook hook_ctx_to_sid;
static struct cksu_hook hook_sid_to_ctx;

static u32 extract_type_hash_from_context(const char *ctx, u32 len)
{
	int colons = 0;
	const char *start = NULL, *end = NULL;
	const char *p;
	u32 i, h = 0;

	for (i = 0; i < len; i++) {
		if (ctx[i] == ':') {
			colons++;
			if (colons == 2)
				start = &ctx[i + 1];
			if (colons == 3) {
				end = &ctx[i];
				break;
			}
		}
	}
	if (!start || !end || end <= start)
		return 0;

	for (p = start; p < end; p++)
		h = h * 31 + *p;
	return h;
}

static int handler_ctx_to_sid(struct kprobe *p, struct pt_regs *regs)
{
	const char *scontext = (const char *)regs->regs[0];
	u32 scontext_len = (u32)regs->regs[1];
	u32 *sid_out = (u32 *)regs->regs[2];
	uid_t uid = from_kuid(&init_user_ns, current_uid());
	char buf[128];
	u32 copy_len, type_hash;

	if (!cksu_is_blessed() && !cksu_virt_uid_has_domain(uid))
		return 0;

	copy_len = scontext_len < 127 ? scontext_len : 127;
	memcpy(buf, scontext, copy_len);
	buf[copy_len] = '\0';

	type_hash = extract_type_hash_from_context(buf, copy_len);
	if (!type_hash || !cksu_virt_type_exists(type_hash))
		return 0;

	*sid_out = cksu_virt_type_to_sid(type_hash);
	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

static int handler_sid_to_ctx(struct kprobe *p, struct pt_regs *regs)
{
	u32 sid = (u32)regs->regs[0];
	char **scontext_out = (char **)regs->regs[1];
	u32 *len_out = (u32 *)regs->regs[2];
	u32 proc_sid;
	const char *ctx;

	if (!cksu_is_virtual_sid(sid))
		return 0;

	proc_sid = cksu_virt_get_proc_sid(current->pid);
	if (proc_sid && proc_sid == sid) {
		/* this process owns this virtual SID */
	} else if (!cksu_is_blessed() &&
		   !cksu_virt_uid_has_domain(from_kuid(&init_user_ns, current_uid()))) {
		return 0;
	}

	ctx = cksu_virt_sid_to_context(sid);
	if (!ctx)
		return 0;

	*scontext_out = kstrdup(ctx, GFP_KERNEL);
	if (*scontext_out)
		*len_out = strlen(ctx);

	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

int cksu_selinux_context_init(void)
{
	int ret;

	ret = cksu_hook_install(&hook_ctx_to_sid, "security_context_to_sid",
				handler_ctx_to_sid);
	if (ret)
		return ret;

	ret = cksu_hook_install(&hook_sid_to_ctx, "security_sid_to_context",
				handler_sid_to_ctx);
	if (ret) {
		cksu_hook_remove(&hook_ctx_to_sid);
		return ret;
	}
	return 0;
}

void cksu_selinux_context_exit(void)
{
	cksu_hook_remove(&hook_sid_to_ctx);
	cksu_hook_remove(&hook_ctx_to_sid);
}
