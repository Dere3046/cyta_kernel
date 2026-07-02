// SPDX-License-Identifier: GPL-2.0-only
#ifndef CKSU_KSYMLESS_H
#define CKSU_KSYMLESS_H

#include "ksymless_android/src/core.h"

#define MAX_VISIT 64

extern unsigned long visited_fns[MAX_VISIT];
extern int nv;

int collect_adrp_pages(unsigned long fn, unsigned long *pages, int max);
int follow_bl(unsigned long fn, unsigned long *visited, int *nv_cnt, int depth);
void ksymless_cache_kln(void);

#endif
