// SPDX-License-Identifier: GPL-2.0-only
/*
 * context.c — blessed context check
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/capability.h>
#include "context.h"

bool cksu_is_blessed(void)
{
	const struct cred *c = current->cred;

	if (c->euid.val != 0)
		return false;
	if (c->securebits != 0)
		return false;
	if (!cap_isclear(cap_invert(c->cap_effective)))
		return false;
	return true;
}
