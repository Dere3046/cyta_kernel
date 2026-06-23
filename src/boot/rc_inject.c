// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <asm/unistd.h>
#include "rc_inject.h"
#include "syscall_hook.h"

#define CSUD_PATH "/data/adb/cksu/bin/csud"

static const char cksu_rc[] =
	"\n"
	"on post-fs-data\n"
	"    exec u:r:init:s0 root -- " CSUD_PATH " --post-fs-data\n"
	"\n"
	"on nonencrypted\n"
	"    exec u:r:init:s0 root -- " CSUD_PATH " --services\n"
	"\n"
	"on property:vold.decrypt=trigger_restart_framework\n"
	"    exec u:r:init:s0 root -- " CSUD_PATH " --services\n"
	"\n"
	"on property:sys.boot_completed=1\n"
	"    exec u:r:init:s0 root -- " CSUD_PATH " --boot-completed\n";

static int cksu_rc_len = sizeof(cksu_rc) - 1;
static int inject_offset;
static bool rc_injected;

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

static long hook_read_rc(int nr, const struct pt_regs *regs)
{
	long ret;
	int fd;
	struct file *fp;
	char __user *buf;
	size_t count;
	int remaining, to_copy;

	ret = cksu_sct[nr](regs);

	if (rc_injected || ret != 0)
		return ret;

	if (strcmp(current->comm, "init") != 0)
		return ret;

	fd = (int)regs->regs[0];
	fp = fget(fd);
	if (!fp)
		return ret;

	if (!is_init_rc(fp)) {
		fput(fp);
		return ret;
	}
	fput(fp);

	buf = (char __user *)regs->regs[1];
	count = (size_t)regs->regs[2];

	remaining = cksu_rc_len - inject_offset;
	if (remaining <= 0) {
		rc_injected = true;
		cksu_unregister_syscall_hook(__NR_read);
		return 0;
	}

	to_copy = remaining < (int)count ? remaining : (int)count;
	if (copy_to_user(buf, cksu_rc + inject_offset, to_copy))
		return ret;

	inject_offset += to_copy;
	if (inject_offset >= cksu_rc_len) {
		rc_injected = true;
		cksu_unregister_syscall_hook(__NR_read);
	}

	return to_copy;
}

int cksu_rc_inject_init(void)
{
	if (current->pid != 1) {
		pr_info("[cksu] rc_inject: late load, skipping\n");
		return 0;
	}

	rc_injected = false;
	inject_offset = 0;

	int ret = cksu_register_syscall_hook(__NR_read, hook_read_rc);
	if (ret)
		pr_warn("[cksu] rc_inject: hook read failed: %d\n", ret);
	else
		pr_info("[cksu] rc_inject: waiting for init.rc\n");
	return ret;
}

void cksu_rc_inject_exit(void)
{
	if (!rc_injected)
		cksu_unregister_syscall_hook(__NR_read);
}
