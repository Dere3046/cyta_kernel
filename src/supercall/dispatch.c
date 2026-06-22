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
#include <linux/uaccess.h>
#include "supercall.h"
#include "dispatch.h"
#include "auth.h"
#include "allowlist.h"
#include "context.h"
#include "elevate.h"
#include "virt_selinux.h"
#include "cksu_sym.h"

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

		return cksu_allowlist_add((uid_t)a1);

	case CKSU_REMOVE_UID:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;

		return cksu_allowlist_remove((uid_t)a1);

	case CKSU_GET_LIST:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;

		return cksu_allowlist_get((uid_t __user *)a1, (int)a2);

	case CKSU_SET_KEY:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;

		cksu_auth_init((const char __user *)a1);
		return 0;

	case CKSU_LOAD_SEPOLICY:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;

		return cksu_virt_load_rules(
			(const struct cksu_sepolicy_cmd __user *)a1, (int)a2);

	case CKSU_CLEAR_SEPOLICY:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;

		cksu_virt_clear_all();
		return 0;

	case CKSU_SET_VIRT_DOMAIN:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;

		return cksu_virt_set_domain((uid_t)a1, (u32)a2);

	case CKSU_REPORT_EVENT:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;

		return 0;

	case CKSU_ADD_VIRT_TYPE: {
		struct { char type_name[64]; char context[128]; } __user *udata =
			(void __user *)a1;
		struct { char type_name[64]; char context[128]; } kdata;

		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;

		if (copy_from_user(&kdata, udata, sizeof(kdata)))
			return -EFAULT;
		kdata.type_name[63] = '\0';
		kdata.context[127] = '\0';
		return cksu_virt_add_type(kdata.type_name, kdata.context);
	}

	case CKSU_REMOVE_VIRT_TYPE: {
		char type_name[64];

		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;

		if (strncpy_from_user(type_name, (const char __user *)a1, 64) <= 0)
			return -EFAULT;
		type_name[63] = '\0';
		return cksu_virt_remove_type(type_name);
	}

	case CKSU_SET_SU_PATH:
		if (arg0_len != CKSU_HASH_LEN)
			return -EINVAL;
		if (!cksu_auth_verify((const u8 *)arg0))
			return -EPERM;
		return cksu_set_su_path_user((const char __user *)a1);

	case CKSU_GET_SU_PATH:
		return cksu_get_su_path_user((char __user *)a1, (int)a2);
	}

	return -ENOTTY;
}
