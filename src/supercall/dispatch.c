// SPDX-License-Identifier: GPL-2.0-only
/*
 * dispatch.c — supercall command routing
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include "supercall.h"
#include "dispatch.h"
#include "auth.h"
#include "allowlist.h"
#include "context.h"
#include "elevate.h"

long cksu_dispatch(const char *arg0, int arg0_len, long cmd, long a1, long a2)
{
	switch (cmd) {
	case CKSU_HELLO:
		return CKSU_VERSION;

	case CKSU_GET_CHALLENGE:
		return cksu_auth_get_challenge((u8 __user *)a1);

	case CKSU_GRANT_ROOT:
		if (arg0_len != CKSU_HASH_LEN) {
			pr_warn("[cksu] grant: bad len %d\n", arg0_len);
			return -EINVAL;
		}
		if (!cksu_auth_verify((const u8 *)arg0)) {
			pr_warn("[cksu] grant: auth failed\n");
			return -EPERM;
		}
		pr_info("[cksu] grant: elevating uid=%d\n",
			from_kuid(&init_user_ns, current_uid()));
		cksu_elevate();
		return 0;

	case CKSU_ADD_UID:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;
		if (!cksu_is_blessed())
			return -EPERM;
		return cksu_allowlist_add((uid_t)a1);

	case CKSU_REMOVE_UID:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;
		if (!cksu_is_blessed())
			return -EPERM;
		return cksu_allowlist_remove((uid_t)a1);

	case CKSU_GET_LIST:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;
		if (!cksu_is_blessed())
			return -EPERM;
		return cksu_allowlist_get((uid_t __user *)a1, (int)a2);

	case CKSU_SET_KEY:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;
		if (!cksu_is_blessed())
			return -EPERM;
		cksu_auth_init((const char __user *)a1);
		return 0;
	}

	return -ENOTTY;
}
