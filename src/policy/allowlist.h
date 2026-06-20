// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_ALLOWLIST_H
#define CKSU_ALLOWLIST_H

#include <linux/types.h>

#define CKSU_ALLOWLIST_PATH "/data/adb/cksu/.allowlist"
#define CKSU_ALLOWLIST_MAGIC 0x434B5355

int cksu_allowlist_init(void);
void cksu_allowlist_exit(void);
bool cksu_uid_allowed(uid_t uid);
int cksu_allowlist_add(uid_t uid);
int cksu_allowlist_remove(uid_t uid);
int cksu_allowlist_get(uid_t __user *out, int max);
int cksu_allowlist_count(void);

#endif
