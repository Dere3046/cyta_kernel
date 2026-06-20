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
#include "sha256.h"
#include "auth.h"

static int cksu_memneq(const void *a, const void *b, size_t len)
{
	const u8 *x = a, *y = b;
	int ret = 0;
	for (size_t i = 0; i < len; i++)
		ret |= x[i] ^ y[i];
	return ret;
}

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

	if (!nonce_valid) {
		pr_warn("[cksu] auth: no valid nonce\n");
		return false;
	}

	if (ktime_ms_delta(ktime_get(), nonce_created) > NONCE_TIMEOUT_MS) {
		nonce_valid = false;
		pr_warn("[cksu] auth: nonce timeout\n");
		return false;
	}

	nonce_valid = false;

	key_len = strnlen(superkey, CKSU_KEY_MAX);
	memcpy(buf, superkey, key_len);
	memcpy(buf + key_len, pending_nonce, CKSU_NONCE_LEN);

	cksu_sha256(buf, key_len + CKSU_NONCE_LEN, expected);

	rc = cksu_memneq(expected, response, CKSU_HASH_LEN);

	if (rc)
		pr_warn("[cksu] auth: hash mismatch (key_len=%d)\n", key_len);

	memzero_explicit(buf, sizeof(buf));
	memzero_explicit(expected, sizeof(expected));

	return rc == 0;
}
