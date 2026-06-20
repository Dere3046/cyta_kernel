// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_AUTH_H
#define CKSU_AUTH_H

#include <linux/types.h>

#define CKSU_KEY_MAX    64
#define CKSU_NONCE_LEN  32
#define CKSU_HASH_LEN   32

void cksu_auth_init(const char *key);
int cksu_auth_get_challenge(u8 __user *out);
bool cksu_auth_verify(const u8 *response);

#endif
