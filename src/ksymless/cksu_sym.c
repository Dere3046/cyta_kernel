// SPDX-License-Identifier: GPL-2.0-only
#include <linux/string.h>
#include <linux/printk.h>
#include <linux/uaccess.h>
#include <asm/barrier.h>
#include "cksu_sym.h"
#include "ksymless.h"

struct file *(*ksym_filp_open)(const char *, int, umode_t);
int (*ksym_filp_close)(struct file *, fl_owner_t);
struct mm_struct *ksym_init_mm;
void (*ksym_set_fixmap)(unsigned long, phys_addr_t, pgprot_t);
long (*ksym_copy_nofault)(void *, const void *, size_t);
void (*ksym_flush_dcache)(unsigned long, unsigned long);
void **ksym_sys_call_table;
unsigned long ksym_ni_syscall;
struct tracepoint *ksym_tp_sys_enter;
int (*ksym_sid_to_context)(u32, char **, u32 *);

struct sym_entry {
	const char *name;
	const char *fallback;
	void **storage;
	bool required;
};

static struct sym_entry sym_table[] = {
	{ "sys_call_table",          NULL,                    (void **)&ksym_sys_call_table, true },
	{ "__arm64_sys_ni_syscall",  NULL,                    (void **)&ksym_ni_syscall,     true },
	{ "__tracepoint_sys_enter",  NULL,                    (void **)&ksym_tp_sys_enter,   true },
	{ "init_mm",                 NULL,                    (void **)&ksym_init_mm,        true },
	{ "__set_fixmap",            NULL,                    (void **)&ksym_set_fixmap,     true },
	{ "copy_to_kernel_nofault",  "probe_kernel_write",   (void **)&ksym_copy_nofault,   true },
	{ "dcache_clean_inval_poc",  "__flush_dcache_area",  (void **)&ksym_flush_dcache,   false },
	{ "filp_open",               NULL,                    (void **)&ksym_filp_open,      false },
	{ "filp_close",              NULL,                    (void **)&ksym_filp_close,     false },
	{ "security_sid_to_context", NULL,                    (void **)&ksym_sid_to_context, false },
	{ NULL, NULL, NULL, false }
};

static char su_path[CKSU_SU_PATH_MAX] = "/system/bin/ck";
static char su_name[16] = "ck";

const char *cksu_get_su_path(void)
{
	return su_path;
}

const char *cksu_get_su_name(void)
{
	return su_name;
}

int cksu_set_su_path(const char *path)
{
	const char *slash;

	if (!path || !path[0] || path[0] != '/')
		return -EINVAL;

	strscpy(su_path, path, sizeof(su_path));
	slash = strrchr(su_path, '/');
	strscpy(su_name, slash ? slash + 1 : su_path, sizeof(su_name));
	dsb(ish);
	return 0;
}

int cksu_set_su_path_user(const char __user *upath)
{
	char kbuf[CKSU_SU_PATH_MAX];
	long len;

	len = strncpy_from_user(kbuf, upath, sizeof(kbuf));
	if (len <= 0)
		return -EFAULT;
	kbuf[sizeof(kbuf) - 1] = '\0';
	return cksu_set_su_path(kbuf);
}

int cksu_get_su_path_user(char __user *buf, int len)
{
	int slen = strlen(su_path) + 1;

	if (len < slen)
		return -ENOSPC;
	if (copy_to_user(buf, su_path, slen))
		return -EFAULT;
	return slen;
}

int cksu_sym_init(void)
{
	struct sym_entry *e;
	char name[128];
	unsigned int i;
	int total = 0, resolved = 0, fail = 0;

	for (e = sym_table; e->name; e++)
		total++;

	for (i = 0; i < klnum_val && resolved < total; i++) {
		unsigned long addr = sym_addr(i);
		if (!addr)
			continue;

		expand_sym(get_sym_offset(get_sym_seq(i)), name, sizeof(name));

		for (e = sym_table; e->name; e++) {
			if (*e->storage)
				continue;
			if (strcmp(name, e->name) == 0 ||
			    (e->fallback && strcmp(name, e->fallback) == 0)) {
				*e->storage = (void *)addr;
				resolved++;
				break;
			}
		}
	}

	for (e = sym_table; e->name; e++) {
		if (!*e->storage) {
			if (e->required) {
				pr_err("[cksu] sym MISSING: %s\n", e->name);
				fail++;
			} else {
				pr_warn("[cksu] sym optional: %s\n", e->name);
			}
		}
	}

	pr_info("[cksu] sym: resolved %d/%d\n", resolved, total);
	return fail ? -ENOENT : 0;
}
