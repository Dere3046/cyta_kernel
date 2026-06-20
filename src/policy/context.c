// SPDX-License-Identifier: GPL-2.0-only
/*
 * context.c — blessed context check
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include "context.h"

bool cksu_is_blessed(void)
{
	const struct cred *c = current->cred;
	kernel_cap_t full;

	if (c->euid.val != 0)
		return false;
	if (c->securebits != 0)
		return false;

	memset(&full, 0xFF, sizeof(full));
	if (memcmp(&c->cap_effective, &full, sizeof(full)) != 0)
		return false;

	return true;
}
