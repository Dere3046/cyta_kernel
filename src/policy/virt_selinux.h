// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_VIRT_SELINUX_H
#define CKSU_VIRT_SELINUX_H

#include <linux/types.h>

#define CKSU_SEPOLICY_ALLOW       1
#define CKSU_SEPOLICY_PERMISSIVE  2

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

#endif
