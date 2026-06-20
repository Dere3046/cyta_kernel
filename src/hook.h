/*
 * hook.h — kprobe wrapper
 */

#ifndef HOOK_H
#define HOOK_H

#include <linux/kprobes.h>

struct cksu_hook {
	struct kprobe kp;
	void *orig_fn;
};

int cksu_hook_install(struct cksu_hook *h, const char *symbol,
		      int (*handler)(struct kprobe *p, struct pt_regs *regs));
void cksu_hook_remove(struct cksu_hook *h);

#endif
