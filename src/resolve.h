/*
 * resolve.h — runtime symbol resolution via ksymless
 */

#ifndef CKSU_RESOLVE_H
#define CKSU_RESOLVE_H

#include <linux/types.h>

struct cred;

typedef struct cred *(*prepare_creds_fn)(void);
typedef int (*commit_creds_fn)(struct cred *new);

extern prepare_creds_fn cksu_prepare_creds;
extern commit_creds_fn cksu_commit_creds;

int cksu_resolve_init(void);

#endif
