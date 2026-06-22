// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_VIRT_SELINUX_H
#define CKSU_VIRT_SELINUX_H

#include <linux/types.h>

#define CKSU_SEPOLICY_ALLOW       1
#define CKSU_SEPOLICY_PERMISSIVE  2

#define VIRTUAL_SID_BASE 0x80000000

struct cksu_sepolicy_cmd {
	u8 action;
	u32 source;
	u32 target;
	u16 tclass;
	u32 perms;
};

int cksu_virt_selinux_init(void);
void cksu_virt_selinux_exit(void);

bool cksu_virt_check(u32 ssid, u32 tsid, u16 tclass, u32 requested);
bool cksu_virt_is_permissive(u32 sid);
bool cksu_virt_uid_has_domain(uid_t uid);

int cksu_virt_add_rule(u32 source, u32 target, u16 tclass, u32 perms);
int cksu_virt_set_permissive(u32 sid);
int cksu_virt_set_domain(uid_t uid, u32 sid);
void cksu_virt_clear_all(void);
int cksu_virt_load_rules(const struct cksu_sepolicy_cmd __user *cmds, int count);

int cksu_virt_add_type(const char *type_name, const char *context);
int cksu_virt_remove_type(const char *type_name);
bool cksu_virt_type_exists(u32 type_hash);
u32 cksu_virt_type_to_sid(u32 type_hash);
const char *cksu_virt_sid_to_context(u32 sid);
bool cksu_is_virtual_sid(u32 sid);
void cksu_virt_set_proc_sid(pid_t pid, u32 sid);
u32 cksu_virt_get_proc_sid(pid_t pid);

#endif
