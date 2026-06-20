/*
 * su_elevate.c — hook __arm64_sys_execve, elevate su to root
 *
 * prepare_exec_creds() copies from current->cred, so we modify
 * it before exec path reaches begin_new_exec().
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/thread_info.h>
#include "hook.h"
#include "su_elevate.h"
#include "resolve.h"

/*
 * struct cred layout matching kernel include/linux/cred.h
 * manually defined to avoid UND symbols from prepare_creds/commit_creds
 */
struct cksu_cred {
	long usage;
	kuid_t uid;
	kgid_t gid;
	kuid_t suid;
	kgid_t sgid;
	kuid_t euid;
	kgid_t egid;
	kuid_t fsuid;
	kgid_t fsgid;
	unsigned securebits;
	long cap_inheritable[2];
	long cap_permitted[2];
	long cap_effective[2];
	long cap_bset[2];
	long cap_ambient[2];
};

#define SU_PATH_MAX 256

static struct cksu_hook hook_execve;

static void elevate_current_cred(void)
{
	struct cksu_cred *new;

	if (!cksu_prepare_creds || !cksu_commit_creds)
		return;

	new = (struct cksu_cred *)cksu_prepare_creds();
	if (!new)
		return;

	new->uid = GLOBAL_ROOT_UID;
	new->gid = GLOBAL_ROOT_GID;
	new->euid = GLOBAL_ROOT_UID;
	new->egid = GLOBAL_ROOT_GID;
	new->suid = GLOBAL_ROOT_UID;
	new->sgid = GLOBAL_ROOT_GID;
	new->fsuid = GLOBAL_ROOT_UID;
	new->fsgid = GLOBAL_ROOT_GID;
	new->securebits = 0;

	/* all caps max */
	new->cap_effective[0] = ~0UL;
	new->cap_effective[1] = ~0UL;
	new->cap_permitted[0] = ~0UL;
	new->cap_permitted[1] = ~0UL;
	new->cap_bset[0] = ~0UL;
	new->cap_bset[1] = ~0UL;
	new->cap_ambient[0] = ~0UL;
	new->cap_ambient[1] = ~0UL;
	new->cap_inheritable[0] = ~0UL;
	new->cap_inheritable[1] = ~0UL;

	cksu_commit_creds((struct cred *)new);

	clear_tsk_thread_flag(current, TIF_SECCOMP);
}

static int is_su_path(const char __user *ufilename)
{
	char kbuf[SU_PATH_MAX];
	char *p;

	if (strncpy_from_user(kbuf, ufilename, sizeof(kbuf)) <= 0)
		return 0;

	p = kbuf;
	while (*p) {
		if (*p == '/')
			p = kbuf + (p - kbuf) + 1;
		else
			p++;
	}

	p = kbuf;
	if (p[0] == 's' && p[1] == 'u') {
		if (p[2] == '\0')
			return 1;
		if (p[2] >= '0' && p[2] <= '9')
			return 1;
	}
	return 0;
}

static int handler_execve(struct kprobe *p, struct pt_regs *regs)
{
	const char __user *filename = (const char __user *)regs->regs[0];

	if (is_su_path(filename)) {
		pr_info("[cksu] su elevating uid=%d -> 0\n",
			from_kuid(&init_user_ns, current_uid()));
		elevate_current_cred();
	}
	return 0;
}

int cksu_su_init(void)
{
	return cksu_hook_install(&hook_execve, "__arm64_sys_execve",
				 handler_execve);
}

void cksu_su_exit(void)
{
	cksu_hook_remove(&hook_execve);
}
