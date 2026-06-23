// SPDX-License-Identifier: GPL-2.0-only
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
static struct cksu_hook hook_bounded_transition;
static struct cksu_hook hook_prepare_creds;
static struct cksu_hook hook_cred_free;

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
	char buf[128];
	u32 copy_len, type_hash;

	if (!cksu_is_blessed() &&
	    !cksu_virt_get_cred_sid(current_cred()) &&
	    !cksu_virt_uid_has_domain(from_kuid(&init_user_ns, current_uid())))
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
	u32 real_sid, cred_sid;
	char *dup;

	real_sid = cksu_virt_get_cred_real_sid(current_cred());
	if (real_sid && real_sid == sid) {
		cred_sid = cksu_virt_get_cred_sid(current_cred());
		if (cred_sid) {
			dup = cksu_virt_sid_to_context_dup(cred_sid, GFP_ATOMIC);
			if (dup) {
				*scontext_out = dup;
				*len_out = strlen(dup);
				regs->regs[0] = 0;
				regs->pc = regs->regs[30];
				return 1;
			}
		}
	}

	if (!cksu_is_virtual_sid(sid))
		return 0;

	dup = cksu_virt_sid_to_context_dup(sid, GFP_ATOMIC);
	if (!dup)
		return 0;

	*scontext_out = dup;
	*len_out = strlen(dup);
	regs->regs[0] = 0;
	regs->pc = regs->regs[30];
	return 1;
}

static int handler_bounded_transition(struct kprobe *p, struct pt_regs *regs)
{
	u32 old_sid = (u32)regs->regs[0];
	u32 new_sid = (u32)regs->regs[1];

	if (cksu_is_virtual_sid(new_sid) || cksu_is_virtual_sid(old_sid)) {
		regs->regs[0] = 0;
		regs->pc = regs->regs[30];
		return 1;
	}
	return 0;
}

static int handler_prepare_creds(struct kprobe *p, struct pt_regs *regs)
{
	struct cred *new_cred = (struct cred *)regs->regs[0];
	const struct cred *old_cred = (const struct cred *)regs->regs[1];
	u32 virt_sid, real_sid;

	virt_sid = cksu_virt_get_cred_sid(old_cred);
	if (virt_sid) {
		real_sid = cksu_virt_get_cred_real_sid(old_cred);
		cksu_virt_set_cred_sid(new_cred, real_sid, virt_sid);
	}
	return 0;
}

static int handler_cred_free(struct kprobe *p, struct pt_regs *regs)
{
	struct cred *cred = (struct cred *)regs->regs[0];

	cksu_virt_remove_cred_sid(cred);
	return 0;
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
	if (ret)
		goto err_ctx_to_sid;

	ret = cksu_hook_install(&hook_bounded_transition,
				"security_bounded_transition",
				handler_bounded_transition);
	if (ret)
		goto err_sid_to_ctx;

	ret = cksu_hook_install(&hook_prepare_creds,
				"security_prepare_creds",
				handler_prepare_creds);
	if (ret)
		goto err_bounded;

	ret = cksu_hook_install(&hook_cred_free,
				"security_cred_free",
				handler_cred_free);
	if (ret)
		goto err_prepare;

	return 0;

err_prepare:
	cksu_hook_remove(&hook_prepare_creds);
err_bounded:
	cksu_hook_remove(&hook_bounded_transition);
err_sid_to_ctx:
	cksu_hook_remove(&hook_sid_to_ctx);
err_ctx_to_sid:
	cksu_hook_remove(&hook_ctx_to_sid);
	return ret;
}

void cksu_selinux_context_exit(void)
{
	cksu_hook_remove(&hook_cred_free);
	cksu_hook_remove(&hook_prepare_creds);
	cksu_hook_remove(&hook_bounded_transition);
	cksu_hook_remove(&hook_sid_to_ctx);
	cksu_hook_remove(&hook_ctx_to_sid);
}
