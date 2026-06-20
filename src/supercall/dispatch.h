// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_DISPATCH_H
#define CKSU_DISPATCH_H

#include <linux/types.h>

long cksu_dispatch(const char *arg0, int arg0_len, long cmd, long a1, long a2);

#endif
