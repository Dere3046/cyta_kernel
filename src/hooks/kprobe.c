// SPDX-License-Identifier: GPL-2.0-only
/*
 * kprobe.c — kprobe install/remove wrapper
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/module.h>
#include <linux/kprobes.h>
#include "kprobe.h"

int cksu_hook_install(struct cksu_hook *h, const char *symbol,
		      int (*handler)(struct kprobe *p, struct pt_regs *regs))
{
	int ret;

	memset(h, 0, sizeof(*h));
	h->kp.symbol_name = symbol;
	h->kp.pre_handler = handler;

	ret = register_kprobe(&h->kp);
	if (ret < 0) {
		pr_warn("[cksu] kprobe %s failed: %d\n", symbol, ret);
		return ret;
	}

	h->orig_fn = (void *)h->kp.addr;
	pr_info("[cksu] hooked %s @ 0x%lx\n", symbol, (unsigned long)h->orig_fn);
	return 0;
}

void cksu_hook_remove(struct cksu_hook *h)
{
	unregister_kprobe(&h->kp);
}
