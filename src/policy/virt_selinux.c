// SPDX-License-Identifier: GPL-2.0-only
/*
 * virt_selinux.c — virtual SELinux domain (AVC-level policy simulation)
 *
 * Copyright (C) 2026 dere3046
 */

#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/rcupdate.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include "virt_selinux.h"

struct virt_rule {
	u32 source;
	u32 target;
	u16 tclass;
	u32 perms;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct virt_permissive {
	u32 sid;
	struct hlist_node node;
	struct rcu_head rcu;
};

struct virt_domain {
	uid_t uid;
	u32 sid;
	struct hlist_node node;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(rule_table, 10);
static DEFINE_HASHTABLE(permissive_table, 6);
static DEFINE_HASHTABLE(domain_table, 8);
static DEFINE_SPINLOCK(virt_lock);

int cksu_virt_selinux_init(void)
{
	hash_init(rule_table);
	hash_init(permissive_table);
	hash_init(domain_table);
	return 0;
}

void cksu_virt_selinux_exit(void)
{
	cksu_virt_clear_all();
}

bool cksu_virt_check(u32 ssid, u32 tsid, u16 tclass, u32 requested)
{
	struct virt_rule *r;
	u32 key = ssid ^ tsid ^ tclass;

	rcu_read_lock();
	hash_for_each_possible_rcu(rule_table, r, node, key) {
		if (r->source == ssid && r->target == tsid &&
		    r->tclass == tclass && (r->perms & requested) == requested) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

bool cksu_virt_is_permissive(u32 sid)
{
	struct virt_permissive *p;

	rcu_read_lock();
	hash_for_each_possible_rcu(permissive_table, p, node, sid) {
		if (p->sid == sid) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

bool cksu_virt_uid_has_domain(uid_t uid)
{
	struct virt_domain *d;

	rcu_read_lock();
	hash_for_each_possible_rcu(domain_table, d, node, uid) {
		if (d->uid == uid) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

static u32 get_uid_sid(uid_t uid)
{
	struct virt_domain *d;

	rcu_read_lock();
	hash_for_each_possible_rcu(domain_table, d, node, uid) {
		if (d->uid == uid) {
			rcu_read_unlock();
			return d->sid;
		}
	}
	rcu_read_unlock();
	return 0;
}

int cksu_virt_add_rule(u32 source, u32 target, u16 tclass, u32 perms)
{
	struct virt_rule *r;
	u32 key = source ^ target ^ tclass;

	r = kmalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;

	r->source = source;
	r->target = target;
	r->tclass = tclass;
	r->perms = perms;

	spin_lock(&virt_lock);
	hash_add_rcu(rule_table, &r->node, key);
	spin_unlock(&virt_lock);
	return 0;
}

int cksu_virt_set_permissive(u32 sid)
{
	struct virt_permissive *p;

	p = kmalloc(sizeof(*p), GFP_KERNEL);
	if (!p)
		return -ENOMEM;

	p->sid = sid;

	spin_lock(&virt_lock);
	hash_add_rcu(permissive_table, &p->node, sid);
	spin_unlock(&virt_lock);
	return 0;
}

int cksu_virt_set_domain(uid_t uid, u32 sid)
{
	struct virt_domain *d;

	d = kmalloc(sizeof(*d), GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	d->uid = uid;
	d->sid = sid;

	spin_lock(&virt_lock);
	hash_add_rcu(domain_table, &d->node, uid);
	spin_unlock(&virt_lock);
	return 0;
}

void cksu_virt_clear_all(void)
{
	struct virt_rule *r;
	struct virt_permissive *p;
	struct virt_domain *d;
	struct hlist_node *tmp;
	int bkt;

	spin_lock(&virt_lock);
	hash_for_each_safe(rule_table, bkt, tmp, r, node) {
		hash_del_rcu(&r->node);
		kfree_rcu(r, rcu);
	}
	hash_for_each_safe(permissive_table, bkt, tmp, p, node) {
		hash_del_rcu(&p->node);
		kfree_rcu(p, rcu);
	}
	hash_for_each_safe(domain_table, bkt, tmp, d, node) {
		hash_del_rcu(&d->node);
		kfree_rcu(d, rcu);
	}
	spin_unlock(&virt_lock);
}

int cksu_virt_load_rules(const struct cksu_sepolicy_cmd __user *cmds, int count)
{
	struct cksu_sepolicy_cmd cmd;
	int i;

	for (i = 0; i < count; i++) {
		if (copy_from_user(&cmd, &cmds[i], sizeof(cmd)))
			return -EFAULT;

		switch (cmd.action) {
		case CKSU_SEPOLICY_ALLOW:
			cksu_virt_add_rule(cmd.source, cmd.target,
					   cmd.tclass, cmd.perms);
			break;
		case CKSU_SEPOLICY_PERMISSIVE:
			cksu_virt_set_permissive(cmd.source);
			break;
		}
	}
	return 0;
}
