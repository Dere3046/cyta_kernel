// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_PATCH_MEMORY_H
#define CKSU_PATCH_MEMORY_H

#include <linux/types.h>

#define CKSU_PATCH_FLUSH_ICACHE  1
#define CKSU_PATCH_FLUSH_DCACHE  2

void cksu_patch_memory_init(void);
int cksu_patch_text(void *dst, void *src, size_t len, int flags);

#endif
