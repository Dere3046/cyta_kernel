// SPDX-License-Identifier: GPL-2.0-only
#ifndef LIBCKSU_H
#define LIBCKSU_H

#include <unistd.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdint.h>
#include "sha256.h"

#define CKSU_NR         __NR_truncate
#define CKSU_HELLO          0x0001
#define CKSU_GET_CHALLENGE  0x1000
#define CKSU_GRANT_ROOT     0x1001
#define CKSU_ADD_UID        0x1002
#define CKSU_REMOVE_UID     0x1003
#define CKSU_GET_LIST       0x1004
#define CKSU_SET_KEY        0x1005

static inline long cksu_hello(void)
{
	return syscall(CKSU_NR, "", CKSU_HELLO, 0, 0);
}

static inline long cksu_get_challenge(uint8_t nonce[32])
{
	return syscall(CKSU_NR, "", CKSU_GET_CHALLENGE, nonce, 0);
}

static inline void cksu_compute_response(const char *key, const uint8_t nonce[32], uint8_t resp[32])
{
	sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (const uint8_t *)key, strlen(key));
	sha256_update(&ctx, nonce, 32);
	sha256_final(&ctx, resp);
}

static inline long cksu_auth_call(const char *key, long cmd, long a1, long a2)
{
	uint8_t nonce[32], resp[32];
	long ret;

	ret = cksu_get_challenge(nonce);
	if (ret)
		return ret;

	cksu_compute_response(key, nonce, resp);
	return syscall(CKSU_NR, resp, cmd, a1, a2);
}

static inline long cksu_grant_root(const char *key)
{
	return cksu_auth_call(key, CKSU_GRANT_ROOT, 0, 0);
}

static inline long cksu_add_uid(const char *key, uid_t uid)
{
	return cksu_auth_call(key, CKSU_ADD_UID, uid, 0);
}

static inline long cksu_remove_uid(const char *key, uid_t uid)
{
	return cksu_auth_call(key, CKSU_REMOVE_UID, uid, 0);
}

static inline long cksu_get_list(const char *key, uid_t *buf, int max)
{
	return cksu_auth_call(key, CKSU_GET_LIST, (long)buf, max);
}

#endif
