// SPDX-License-Identifier: GPL-2.0-only
/*
 * auth.c — challenge-response authentication
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/random.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/timekeeping.h>
#include <crypto/sha2.h>
#include "auth.h"

static char superkey[CKSU_KEY_MAX];
static u8 pending_nonce[CKSU_NONCE_LEN];
static bool nonce_valid;
static ktime_t nonce_created;

#define NONCE_TIMEOUT_MS 5000

void cksu_auth_init(const char *key)
{
	if (key && key[0]) {
		strscpy(superkey, key, sizeof(superkey));
	} else {
		get_random_bytes(superkey, 16);
		superkey[16] = '\0';
		pr_info("[cksu] generated key: %s\n", superkey);
	}
	nonce_valid = false;
}

int cksu_auth_get_challenge(u8 __user *out)
{
	get_random_bytes(pending_nonce, CKSU_NONCE_LEN);
	nonce_valid = true;
	nonce_created = ktime_get();

	if (copy_to_user(out, pending_nonce, CKSU_NONCE_LEN))
		return -EFAULT;
	return 0;
}

bool cksu_auth_verify(const u8 *response)
{
	u8 expected[CKSU_HASH_LEN];
	u8 buf[CKSU_KEY_MAX + CKSU_NONCE_LEN];
	int key_len, rc;

	if (!nonce_valid)
		return false;

	if (ktime_ms_delta(ktime_get(), nonce_created) > NONCE_TIMEOUT_MS) {
		nonce_valid = false;
		return false;
	}

	nonce_valid = false;

	key_len = strnlen(superkey, CKSU_KEY_MAX);
	memcpy(buf, superkey, key_len);
	memcpy(buf + key_len, pending_nonce, CKSU_NONCE_LEN);

	sha256(buf, key_len + CKSU_NONCE_LEN, expected);

	rc = crypto_memneq(expected, response, CKSU_HASH_LEN);
	memzero_explicit(buf, sizeof(buf));
	memzero_explicit(expected, sizeof(expected));

	return rc == 0;
}
