// SPDX-License-Identifier: GPL-2.0-only
/*
 * allowlist.c — UID whitelist with RCU hash table
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/slab.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include "allowlist.h"

struct allow_entry {
	struct hlist_node node;
	struct rcu_head rcu;
	uid_t uid;
};

static DEFINE_HASHTABLE(allow_table, 8);
static DEFINE_SPINLOCK(allow_lock);
static int allow_count;

int cksu_allowlist_init(void)
{
	hash_init(allow_table);
	allow_count = 0;
	return 0;
}

void cksu_allowlist_exit(void)
{
	struct allow_entry *e;
	struct hlist_node *tmp;
	int bkt;

	spin_lock(&allow_lock);
	hash_for_each_safe(allow_table, bkt, tmp, e, node) {
		hash_del_rcu(&e->node);
		kfree_rcu(e, rcu);
	}
	allow_count = 0;
	spin_unlock(&allow_lock);
}

bool cksu_uid_allowed(uid_t uid)
{
	struct allow_entry *e;

	rcu_read_lock();
	hash_for_each_possible_rcu(allow_table, e, node, uid) {
		if (e->uid == uid) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

int cksu_allowlist_add(uid_t uid)
{
	struct allow_entry *e;

	if (cksu_uid_allowed(uid))
		return 0;

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	e->uid = uid;
	spin_lock(&allow_lock);
	hash_add_rcu(allow_table, &e->node, uid);
	allow_count++;
	spin_unlock(&allow_lock);
	return 0;
}

int cksu_allowlist_remove(uid_t uid)
{
	struct allow_entry *e;
	struct hlist_node *tmp;

	spin_lock(&allow_lock);
	hash_for_each_possible_safe(allow_table, e, tmp, node, uid) {
		if (e->uid == uid) {
			hash_del_rcu(&e->node);
			allow_count--;
			spin_unlock(&allow_lock);
			kfree_rcu(e, rcu);
			return 0;
		}
	}
	spin_unlock(&allow_lock);
	return -ENOENT;
}

int cksu_allowlist_get(uid_t __user *out, int max)
{
	struct allow_entry *e;
	int bkt, n = 0;

	rcu_read_lock();
	hash_for_each_rcu(allow_table, bkt, e, node) {
		if (n >= max)
			break;
		if (put_user(e->uid, &out[n])) {
			rcu_read_unlock();
			return -EFAULT;
		}
		n++;
	}
	rcu_read_unlock();
	return n;
}

int cksu_allowlist_count(void)
{
	return allow_count;
}
