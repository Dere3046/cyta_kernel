// SPDX-License-Identifier: GPL-2.0-only
/*
 * main.c — CKSU module entry
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/init.h>

#include "ksymless.h"
#include "selinux.h"
#include "elevate.h"
#include "audit.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CKSU");
MODULE_AUTHOR("dere3046");

static int __init cksu_init(void)
{
	int ret;

	pr_info("[cksu] init\n");

	find_kallsyms_base();
	ksymless_cache_kln();

	unsigned long avc_addr = kallsyms_name_to_addr("avc_denied");
	unsigned long execve_addr = kallsyms_name_to_addr("__arm64_sys_execve");
	unsigned long audit_addr = kallsyms_name_to_addr("audit_log_start");

	pr_info("[cksu] avc_denied=0x%lx execve=0x%lx audit=0x%lx\n",
		avc_addr, execve_addr, audit_addr);

	if (!avc_addr || !execve_addr) {
		pr_err("[cksu] missing critical symbols\n");
		return -ENOENT;
	}

	ret = cksu_selinux_init();
	if (ret) {
		pr_err("[cksu] selinux hook failed: %d\n", ret);
		return ret;
	}

	ret = cksu_su_init();
	if (ret) {
		pr_err("[cksu] su hook failed: %d\n", ret);
		cksu_selinux_exit();
		return ret;
	}

	ret = cksu_audit_init();
	if (ret)
		pr_warn("[cksu] audit hook failed: %d (skip)\n", ret);

	pr_info("[cksu] hooks: selinux=ok su=ok audit=%s\n",
		ret ? "skip" : "ok");

	return 0;
}

static void __exit cksu_exit(void)
{
	cksu_audit_exit();
	cksu_su_exit();
	cksu_selinux_exit();
	pr_info("[cksu] exit\n");
}

module_init(cksu_init);
module_exit(cksu_exit);
