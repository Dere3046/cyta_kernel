// SPDX-License-Identifier: GPL-2.0-only
/*
 * shadow_policy.c — precise SELinux access evaluation via SID→context→virtual rules
 *
 * Phase 1: resolve security_sid_to_context, convert SIDs to types, match virtual table
 * Phase 2 (future): full policydb duplication + context_struct_compute_av
 */

#include <linux/slab.h>
#include <linux/string.h>
#include "shadow_policy.h"
#include "virt_selinux.h"
#include "ksymless.h"

static int (*sid_to_context_fn)(u32 sid, char **scontext, u32 *scontext_len);

int cksu_shadow_policy_init(void)
{
	sid_to_context_fn = (void *)kallsyms_name_to_addr("security_sid_to_context");
	if (!sid_to_context_fn) {
		pr_warn("[cksu] shadow_policy: security_sid_to_context not found\n");
		return -ENOENT;
	}
	pr_info("[cksu] shadow_policy: sid_to_context=0x%lx\n",
		(unsigned long)sid_to_context_fn);
	return 0;
}

static u32 hash_type(const char *type, int len)
{
	u32 h = 0;
	for (int i = 0; i < len; i++)
		h = h * 31 + type[i];
	return h;
}

static u32 extract_type_hash(const char *context, u32 len)
{
	const char *p = context;
	const char *end = context + len;
	int colons = 0;
	const char *type_start = NULL;
	const char *type_end = NULL;

	while (p < end) {
		if (*p == ':') {
			colons++;
			if (colons == 2)
				type_start = p + 1;
			if (colons == 3) {
				type_end = p;
				break;
			}
		}
		p++;
	}

	if (!type_start || !type_end || type_end <= type_start)
		return 0;

	return hash_type(type_start, type_end - type_start);
}

bool cksu_shadow_check(u32 ssid, u32 tsid, u16 tclass, u32 requested)
{
	char *scontext = NULL, *tcontext = NULL;
	u32 slen = 0, tlen = 0;
	u32 src_hash, tgt_hash;
	bool result = false;

	if (!sid_to_context_fn)
		return false;

	if (sid_to_context_fn(ssid, &scontext, &slen))
		goto out;
	if (sid_to_context_fn(tsid, &tcontext, &tlen))
		goto out;

	src_hash = extract_type_hash(scontext, slen);
	tgt_hash = extract_type_hash(tcontext, tlen);

	if (!src_hash)
		goto out;

	if (cksu_virt_is_permissive(src_hash)) {
		result = true;
		goto out;
	}

	if (tgt_hash && cksu_virt_check(src_hash, tgt_hash, tclass, requested))
		result = true;

out:
	kfree(scontext);
	kfree(tcontext);
	return result;
}
