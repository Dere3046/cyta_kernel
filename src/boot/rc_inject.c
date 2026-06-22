// SPDX-License-Identifier: GPL-2.0-only
/*
 * rc_inject.c — init.rc injection via read hook + f_op proxy
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/slab.h>
#include "rc_inject.h"
#include "kprobe.h"

#define CSUD_PATH "/dev/.cksu/csud"

static const char cksu_rc[] =
	"\n"
	"on post-fs-data\n"
	"    exec u:r:magisk:s0 root -- " CSUD_PATH " --post-fs-data\n"
	"\n"
	"on nonencrypted\n"
	"    exec u:r:magisk:s0 root -- " CSUD_PATH " --services\n"
	"\n"
	"on property:vold.decrypt=trigger_restart_framework\n"
	"    exec u:r:magisk:s0 root -- " CSUD_PATH " --services\n"
	"\n"
	"on property:sys.boot_completed=1\n"
	"    exec u:r:magisk:s0 root -- " CSUD_PATH " --boot-completed\n";

static int cksu_rc_len = sizeof(cksu_rc) - 1;
static bool rc_injected;
static struct kprobe hook_read_kp;
static struct kprobe hook_fstat_kp;

static struct file_operations fops_proxy;
static ssize_t (*orig_read)(struct file *, char __user *, size_t, loff_t *);
static int inject_offset;

static bool is_init_rc(struct file *fp)
{
	struct dentry *dentry;

	if (strcmp(current->comm, "init") != 0)
		return false;
	if (!fp || !fp->f_path.dentry)
		return false;

	dentry = fp->f_path.dentry;
	if (!d_is_reg(dentry))
		return false;

	return strcmp(dentry->d_name.name, "init.rc") == 0;
}

static ssize_t proxy_read(struct file *fp, char __user *buf,
			  size_t count, loff_t *pos)
{
	ssize_t ret;

	ret = orig_read(fp, buf, count, pos);
	if (ret != 0)
		return ret;

	if (inject_offset >= cksu_rc_len)
		return 0;

	int remaining = cksu_rc_len - inject_offset;
	int to_copy = remaining < count ? remaining : count;

	if (copy_to_user(buf, cksu_rc + inject_offset, to_copy))
		return -EFAULT;

	inject_offset += to_copy;
	*pos += to_copy;
	return to_copy;
}

static void install_fops_proxy(struct file *fp)
{
	memcpy(&fops_proxy, fp->f_op, sizeof(struct file_operations));
	orig_read = fp->f_op->read;
	fops_proxy.read = proxy_read;
	inject_offset = 0;
	fp->f_op = &fops_proxy;
}

static int handler_read(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *ur;
	int fd;
	struct file *fp;

	if (rc_injected)
		return 0;

	ur = (struct pt_regs *)regs->regs[0];
	fd = (int)ur->regs[0];

	fp = fget(fd);
	if (!fp)
		return 0;

	if (is_init_rc(fp)) {
		install_fops_proxy(fp);
		rc_injected = true;
		unregister_kprobe(&hook_read_kp);
		unregister_kprobe(&hook_fstat_kp);
		pr_info("[cksu] rc_inject: installed on init.rc\n");
	}

	fput(fp);
	return 0;
}

static int handler_fstat(struct kprobe *p, struct pt_regs *regs)
{
	return 0;
}

int cksu_rc_inject_init(void)
{
	int ret;

	if (current->pid != 1) {
		pr_info("[cksu] rc_inject: late load, skipping\n");
		return 0;
	}

	rc_injected = false;

	hook_read_kp.symbol_name = "__arm64_sys_read";
	hook_read_kp.pre_handler = handler_read;
	ret = register_kprobe(&hook_read_kp);
	if (ret) {
		pr_warn("[cksu] rc_inject: read hook failed: %d\n", ret);
		return ret;
	}

	hook_fstat_kp.symbol_name = "__arm64_sys_newfstatat";
	hook_fstat_kp.pre_handler = handler_fstat;
	register_kprobe(&hook_fstat_kp);

	pr_info("[cksu] rc_inject: waiting for init.rc\n");
	return 0;
}

void cksu_rc_inject_exit(void)
{
	if (!rc_injected) {
		unregister_kprobe(&hook_read_kp);
		unregister_kprobe(&hook_fstat_kp);
	}
}
