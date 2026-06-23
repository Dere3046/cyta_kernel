// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/thread_info.h>
#include "elevate.h"
#include "virt_selinux.h"
#include "cksu_sym.h"

void cksu_elevate(void)
{
	struct cred *c = (struct cred *)current->cred;
	u32 real_sid = 0;
	u32 magisk_hash = 0;
	u32 magisk_sid;
	const char *p;

	if (ksym_cred_getsecid)
		ksym_cred_getsecid((const struct cred *)c, &real_sid);

	c->uid.val = 0;
	c->gid.val = 0;
	c->euid.val = 0;
	c->egid.val = 0;
	c->suid.val = 0;
	c->sgid.val = 0;
	c->fsuid.val = 0;
	c->fsgid.val = 0;
	c->securebits = 0;

	memset(&c->cap_effective, 0xFF, sizeof(c->cap_effective));
	memset(&c->cap_permitted, 0xFF, sizeof(c->cap_permitted));
	memset(&c->cap_bset, 0xFF, sizeof(c->cap_bset));
	memset(&c->cap_ambient, 0xFF, sizeof(c->cap_ambient));
	memset(&c->cap_inheritable, 0xFF, sizeof(c->cap_inheritable));

	if (ksym_groups_alloc && c->group_info && c->group_info->ngroups > 0) {
		struct group_info *gi = ksym_groups_alloc(0);
		if (gi) {
			struct group_info *old = c->group_info;
			c->group_info = gi;
			if (refcount_dec_and_test(&old->usage) && ksym_groups_free)
				ksym_groups_free(old);
		}
	}

	clear_tsk_thread_flag(current, TIF_SECCOMP);

	for (p = "magisk"; *p; p++)
		magisk_hash = magisk_hash * 31 + *p;

	magisk_sid = cksu_virt_type_to_sid(magisk_hash);
	if (magisk_sid)
		cksu_virt_set_cred_sid(c, real_sid, magisk_sid);
}
