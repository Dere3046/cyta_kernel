// SPDX-License-Identifier: GPL-2.0-only
/*
 * main.c — CKSU v2 module entry
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/printk.h>
#include <linux/init.h>

#include "ksymless.h"
#include "auth.h"
#include "supercall.h"
#include "allowlist.h"
#include "virt_selinux.h"
#include "selinux.h"
#include "audit.h"
#include "execve.h"
#include "access.h"
#include "rc_inject.h"

static char *superkey = NULL;
module_param(superkey, charp, 0);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CKSU");
MODULE_AUTHOR("dere3046");

static int __init cksu_init(void)
{
	int ret;

	pr_info("[cksu] init v2\n");

	find_kallsyms_base();
	ksymless_cache_kln();

	cksu_auth_init(superkey);
	cksu_allowlist_init();
	cksu_virt_selinux_init();

	ret = cksu_supercall_init();
	if (ret)
		pr_warn("[cksu] supercall failed: %d\n", ret);

	ret = cksu_selinux_init();
	if (ret)
		pr_warn("[cksu] selinux hook failed: %d\n", ret);

	ret = cksu_audit_init();
	if (ret)
		pr_warn("[cksu] audit hook failed: %d\n", ret);

	ret = cksu_execve_init();
	if (ret)
		pr_warn("[cksu] execve hook failed: %d\n", ret);

	ret = cksu_access_init();
	if (ret)
		pr_warn("[cksu] access hook failed: %d\n", ret);

	cksu_rc_inject_init();

	pr_info("[cksu] ready\n");
	return 0;
}

static void __exit cksu_exit(void)
{
	cksu_rc_inject_exit();
	cksu_access_exit();
	cksu_execve_exit();
	cksu_audit_exit();
	cksu_selinux_exit();
	cksu_supercall_exit();
	cksu_virt_selinux_exit();
	cksu_allowlist_exit();
	pr_info("[cksu] exit\n");
}

module_init(cksu_init);
module_exit(cksu_exit);
