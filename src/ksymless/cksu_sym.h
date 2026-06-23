// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_SYM_H
#define CKSU_SYM_H

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <asm/pgtable-types.h>

struct tracepoint;

// VFS
extern struct file *(*ksym_filp_open)(const char *, int, umode_t);
extern int (*ksym_filp_close)(struct file *, fl_owner_t);

// Memory patching
extern struct mm_struct *ksym_init_mm;
extern void (*ksym_set_fixmap)(unsigned long, phys_addr_t, pgprot_t);
extern long (*ksym_copy_nofault)(void *, const void *, size_t);
extern void (*ksym_flush_dcache)(unsigned long, unsigned long);

// Syscall table
extern void **ksym_sys_call_table;
extern unsigned long ksym_ni_syscall;
extern struct tracepoint *ksym_tp_sys_enter;

// SELinux
extern int (*ksym_sid_to_context)(u32, char **, u32 *);
extern void (*ksym_cred_getsecid)(const struct cred *, u32 *);

// Cred groups
extern struct group_info *(*ksym_groups_alloc)(int);
extern void (*ksym_groups_free)(struct group_info *);

// Su path
#define CKSU_SU_PATH_MAX 64

const char *cksu_get_su_path(void);
const char *cksu_get_su_name(void);
int cksu_set_su_path(const char *path);
int cksu_set_su_path_user(const char __user *upath);
int cksu_get_su_path_user(char __user *buf, int len);

int cksu_sym_init(void);

#endif
