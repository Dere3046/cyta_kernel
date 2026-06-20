// SPDX-License-Identifier: GPL-2.0-only
// Derived from KernelSU (GPL-2.0)
/*
 * syscall_hook.c — tracepoint-based syscall dispatcher (KSU approach)
 *
 * Bypasses KCFI by using sys_enter tracepoint to redirect syscallno
 * BEFORE the kernel's CFI-checked indirect call through sys_call_table.
 */

#include <linux/module.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/tracepoint.h>
#include <linux/version.h>
#include <asm/syscall.h>
#include "syscall_hook.h"
#include "patch_memory.h"
#include "ksymless.h"

#define ORIG_NR(r) ((r)->regs[8])

syscall_fn_t *cksu_sct;
static int dispatcher_nr = -1;
static cksu_syscall_hook_fn syscall_hooks[__NR_syscalls];
static syscall_fn_t orig_ni_fn;
static struct tracepoint *tp_sys_enter;

static long cksu_syscall_dispatcher(const struct pt_regs *regs)
{
	int orig_nr;

	if (regs->syscallno != dispatcher_nr)
		return -ENOSYS;

	orig_nr = (int)ORIG_NR(regs);
	if (regs->syscallno == orig_nr)
		return -ENOSYS;

	((struct pt_regs *)regs)->syscallno = orig_nr;
	((struct pt_regs *)regs)->regs[8] = orig_nr;

	if (likely(orig_nr >= 0 && orig_nr < __NR_syscalls)) {
		cksu_syscall_hook_fn fn = READ_ONCE(syscall_hooks[orig_nr]);
		if (likely(fn))
			return fn(orig_nr, regs);
	}

	return -ENOSYS;
}

static void sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
	struct pt_regs *kregs;

	if (unlikely(is_compat_task()))
		return;
	if (dispatcher_nr < 0)
		return;
	if (id < 0 || id >= __NR_syscalls)
		return;
	if (!READ_ONCE(syscall_hooks[id]))
		return;

	kregs = task_pt_regs(current);
	if (!kregs)
		return;
	kregs->regs[8] = id;
	kregs->syscallno = dispatcher_nr;
}

static void mark_all_processes(void)
{
	struct task_struct *p;

	rcu_read_lock();
	for_each_process(p)
		set_tsk_thread_flag(p, TIF_SYSCALL_TRACEPOINT);
	rcu_read_unlock();
}

int cksu_register_syscall_hook(int nr, cksu_syscall_hook_fn fn)
{
	if (nr < 0 || nr >= __NR_syscalls)
		return -EINVAL;
	WRITE_ONCE(syscall_hooks[nr], fn);
	pr_info("[cksu] registered syscall hook %d\n", nr);
	return 0;
}

void cksu_unregister_syscall_hook(int nr)
{
	if (nr < 0 || nr >= __NR_syscalls)
		return;
	WRITE_ONCE(syscall_hooks[nr], NULL);
}

int cksu_syscall_hook_init(void)
{
	unsigned long ni_addr;
	int slot = -1;
	syscall_fn_t dispatcher_fn;
	int ret;

	pr_info("[cksu] syscall_hook: step 1 resolve sct\n");
	cksu_sct = (syscall_fn_t *)kallsyms_name_to_addr("sys_call_table");
	if (!cksu_sct) {
		pr_err("[cksu] sys_call_table not found\n");
		return -ENOENT;
	}

	pr_info("[cksu] syscall_hook: step 2 resolve ni_syscall\n");
	ni_addr = kallsyms_name_to_addr("__arm64_sys_ni_syscall");
	if (!ni_addr) {
		pr_err("[cksu] sys_ni_syscall not found\n");
		return -ENOENT;
	}

	pr_info("[cksu] syscall_hook: step 3 find slot\n");
	for (int i = 0; i < __NR_syscalls; i++) {
		if ((unsigned long)cksu_sct[i] == ni_addr) {
			slot = i;
			break;
		}
	}
	if (slot < 0) {
		pr_err("[cksu] no ni_syscall slot found\n");
		return -ENOENT;
	}

	pr_info("[cksu] syscall_hook: step 4 patch slot %d\n", slot);
	dispatcher_nr = slot;
	orig_ni_fn = cksu_sct[slot];
	dispatcher_fn = (syscall_fn_t)cksu_syscall_dispatcher;

	ret = cksu_patch_text(&cksu_sct[slot], &dispatcher_fn, sizeof(dispatcher_fn),
			      CKSU_PATCH_FLUSH_DCACHE);
	if (ret) {
		pr_err("[cksu] patch dispatcher slot %d failed: %d\n", slot, ret);
		dispatcher_nr = -1;
		return ret;
	}

	pr_info("[cksu] syscall_hook: step 5 resolve tracepoint\n");
	tp_sys_enter = (struct tracepoint *)kallsyms_name_to_addr("__tracepoint_sys_enter");
	if (!tp_sys_enter) {
		pr_err("[cksu] __tracepoint_sys_enter not found\n");
		cksu_patch_text(&cksu_sct[slot], &orig_ni_fn, sizeof(orig_ni_fn),
				CKSU_PATCH_FLUSH_DCACHE);
		dispatcher_nr = -1;
		return -ENOENT;
	}

	pr_info("[cksu] syscall_hook: step 6 register tracepoint\n");
	memset(syscall_hooks, 0, sizeof(syscall_hooks));

	ret = tracepoint_probe_register(tp_sys_enter, (void *)sys_enter_handler, NULL);
	if (ret) {
		pr_err("[cksu] tracepoint register failed: %d\n", ret);
		cksu_patch_text(&cksu_sct[slot], &orig_ni_fn, sizeof(orig_ni_fn),
				CKSU_PATCH_FLUSH_DCACHE);
		dispatcher_nr = -1;
		return ret;
	}

	pr_info("[cksu] syscall_hook: step 7 mark processes\n");
	mark_all_processes();

	pr_info("[cksu] syscall_hook: table=0x%lx slot=%d tp=0x%lx done\n",
		(unsigned long)cksu_sct, slot, (unsigned long)tp_sys_enter);
	return 0;
}

void cksu_syscall_hook_exit(void)
{
	if (tp_sys_enter) {
		tracepoint_probe_unregister(tp_sys_enter, (void *)sys_enter_handler, NULL);
		tracepoint_synchronize_unregister();
	}

	if (dispatcher_nr >= 0 && cksu_sct) {
		cksu_patch_text(&cksu_sct[dispatcher_nr], &orig_ni_fn,
				sizeof(orig_ni_fn), CKSU_PATCH_FLUSH_DCACHE);
	}

	memset(syscall_hooks, 0, sizeof(syscall_hooks));
	dispatcher_nr = -1;
	pr_info("[cksu] syscall_hook: cleaned up\n");
}
