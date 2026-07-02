// SPDX-License-Identifier: GPL-2.0-only
#include <linux/module.h>
#include <linux/printk.h>
#include "ksymless.h"

static unsigned long (*kln_cached)(const char *);

static unsigned long ksymless_bsearch(const char *name)
{
	int low = 0, high = (int)klnum_val;
	char nbuf[128];

	while (low <= high) {
		int mid = low + (high - low) / 2;
		unsigned int seq;
		unsigned int off;

		seq = get_sym_seq(mid);
		off = get_sym_offset(seq);
		expand_sym(off, nbuf, sizeof(nbuf));

		int r = strcmp(name, nbuf);
		if (r > 0)
			low = mid + 1;
		else if (r < 0)
			high = mid - 1;
		else
			return sym_addr(seq);
	}
	return 0;
}

void ksymless_cache_kln(void)
{
	unsigned long addr = ksymless_bsearch("kallsyms_lookup_name");
	if (addr) {
		kln_cached = (typeof(kln_cached))addr;
		pr_info("[ksymless] cached kallsyms_lookup_name @ 0x%lx\n", addr);
	}
}
