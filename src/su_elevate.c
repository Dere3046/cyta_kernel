/*
 * su_elevate.c — hook __arm64_sys_execve, elevate su to root
 *
 * prepare_exec_creds() copies from current->cred, so we modify
 * it before exec path reaches begin_new_exec().
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/uaccess.h>
#include <linux/thread_info.h>
#include "hook.h"
#include "su_elevate.h"

#define SU_PATH_MAX 256

static struct cksu_hook hook_execve;

static void elevate_current_cred(void)
{
	struct cred *new;

	new = prepare_creds();
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

	cap_raise(new->cap_effective, CAP_DAC_OVERRIDE);
	cap_raise(new->cap_permitted, CAP_DAC_OVERRIDE);
	cap_raise(new->cap_effective, CAP_FOWNER);
	cap_raise(new->cap_permitted, CAP_FOWNER);
	cap_raise(new->cap_effective, CAP_FSETID);
	cap_raise(new->cap_permitted, CAP_FSETID);
	cap_raise(new->cap_effective, CAP_KILL);
	cap_raise(new->cap_permitted, CAP_KILL);
	cap_raise(new->cap_effective, CAP_SETGID);
	cap_raise(new->cap_permitted, CAP_SETGID);
	cap_raise(new->cap_effective, CAP_SETUID);
	cap_raise(new->cap_permitted, CAP_SETUID);
	cap_raise(new->cap_effective, CAP_SETPCAP);
	cap_raise(new->cap_permitted, CAP_SETPCAP);
	cap_raise(new->cap_effective, CAP_NET_ADMIN);
	cap_raise(new->cap_permitted, CAP_NET_ADMIN);
	cap_raise(new->cap_effective, CAP_NET_RAW);
	cap_raise(new->cap_permitted, CAP_NET_RAW);
	cap_raise(new->cap_effective, CAP_SYS_CHROOT);
	cap_raise(new->cap_permitted, CAP_SYS_CHROOT);
	cap_raise(new->cap_effective, CAP_SYS_PTRACE);
	cap_raise(new->cap_permitted, CAP_SYS_PTRACE);
	cap_raise(new->cap_effective, CAP_SYS_ADMIN);
	cap_raise(new->cap_permitted, CAP_SYS_ADMIN);

	new->cap_bset = new->cap_permitted;
	new->cap_ambient = new->cap_permitted;
	new->cap_inheritable = new->cap_permitted;

	commit_creds(new);

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
