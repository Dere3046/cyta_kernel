/*
 * resolve.c — resolve kernel symbols at runtime
 *
 * Use ksymless kallsyms_name_to_addr to find symbols,
 * then cache as function pointers. No direct UND references.
 */

#include <linux/module.h>
#include <linux/printk.h>
#include "ksymless_core.h"
#include "resolve.h"

prepare_creds_fn cksu_prepare_creds;
commit_creds_fn cksu_commit_creds;

int cksu_resolve_init(void)
{
	unsigned long addr;

	find_kallsyms_base();

	addr = kallsyms_name_to_addr("prepare_creds");
	if (addr) {
		cksu_prepare_creds = (prepare_creds_fn)addr;
		pr_info("[cksu] prepare_creds @ 0x%lx\n", addr);
	} else {
		pr_err("[cksu] prepare_creds not found\n");
		return -ENOENT;
	}

	addr = kallsyms_name_to_addr("commit_creds");
	if (addr) {
		cksu_commit_creds = (commit_creds_fn)addr;
		pr_info("[cksu] commit_creds @ 0x%lx\n", addr);
	} else {
		pr_err("[cksu] commit_creds not found\n");
		return -ENOENT;
	}

	return 0;
}
