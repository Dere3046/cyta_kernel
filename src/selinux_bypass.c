/*
 * selinux_bypass.c — hook avc_denied
 *
 * avc_denied returns 0 (allow) or -EACCES (deny).
 * For root tasks we force return 0 at entry via kprobe.
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include "hook.h"
#include "selinux_bypass.h"

static struct cksu_hook hook_avc_denied;

static int handler_avc_denied(struct kprobe *p, struct pt_regs *regs)
{
	if (uid_eq(current_uid(), GLOBAL_ROOT_UID)) {
		regs->regs[0] = 0;
		return 1;
	}
	return 0;
}

int cksu_selinux_init(void)
{
	return cksu_hook_install(&hook_avc_denied, "avc_denied",
				 handler_avc_denied);
}

void cksu_selinux_exit(void)
{
	cksu_hook_remove(&hook_avc_denied);
}
