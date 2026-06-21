// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_SHADOW_POLICY_H
#define CKSU_SHADOW_POLICY_H

#include <linux/types.h>

int cksu_shadow_policy_init(void);
bool cksu_shadow_check(u32 ssid, u32 tsid, u16 tclass, u32 requested);

#endif
