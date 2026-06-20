// SPDX-License-Identifier: GPL-2.0-only
/*
 * elevate.c — credential manipulation
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/thread_info.h>
#include "elevate.h"

void cksu_elevate(void)
{
	struct cred *c = (struct cred *)current->cred;

	c->uid.val = 0;
	c->gid.val = 0;
	c->euid.val = 0;
	c->egid.val = 0;
	c->suid.val = 0;
	c->sgid.val = 0;
	c->fsuid.val = 0;
	c->fsgid.val = 0;
	c->securebits = 0;

	memset(&c->cap_effective, 0xFF, sizeof(c->cap_effective));
	memset(&c->cap_permitted, 0xFF, sizeof(c->cap_permitted));
	memset(&c->cap_bset, 0xFF, sizeof(c->cap_bset));
	memset(&c->cap_ambient, 0xFF, sizeof(c->cap_ambient));
	memset(&c->cap_inheritable, 0xFF, sizeof(c->cap_inheritable));

	clear_tsk_thread_flag(current, TIF_SECCOMP);
}
