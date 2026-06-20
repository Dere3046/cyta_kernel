// SPDX-License-Identifier: GPL-2.0-only
/*
 * kprobe.h — kprobe install/remove wrapper
 *
 * Copyright (C) 2026 dere3046
 */

#ifndef CKSU_KPROBE_H
#define CKSU_KPROBE_H

#include <linux/kprobes.h>

struct cksu_hook {
	struct kprobe kp;
	void *orig_fn;
};

int cksu_hook_install(struct cksu_hook *h, const char *symbol,
		      int (*handler)(struct kprobe *p, struct pt_regs *regs));
void cksu_hook_remove(struct cksu_hook *h);

#endif
