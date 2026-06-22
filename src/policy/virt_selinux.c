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
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/errno.h>
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

#define MAX_VIRT_TYPES 64

struct virt_type_entry {
	u32 hash;
	u32 sid;
	char context[128];
	struct hlist_node node;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(virt_type_table, 6);
static atomic_t next_virt_sid = ATOMIC_INIT(VIRTUAL_SID_BASE);

struct virt_proc_sid {
	pid_t pid;
	u32 virt_sid;
	struct hlist_node node;
	struct rcu_head rcu;
};

static DEFINE_HASHTABLE(virt_proc_table, 8);

int cksu_virt_selinux_init(void)
{
	hash_init(rule_table);
	hash_init(permissive_table);
	hash_init(domain_table);
	hash_init(virt_type_table);
	hash_init(virt_proc_table);
	return 0;
}

void cksu_virt_selinux_exit(void)
{
	struct virt_type_entry *t;
	struct virt_proc_sid *ps;
	struct hlist_node *tmp;
	int bkt;

	cksu_virt_clear_all();

	spin_lock(&virt_lock);
	hash_for_each_safe(virt_type_table, bkt, tmp, t, node) {
		hash_del_rcu(&t->node);
		kfree_rcu(t, rcu);
	}
	hash_for_each_safe(virt_proc_table, bkt, tmp, ps, node) {
		hash_del_rcu(&ps->node);
		kfree_rcu(ps, rcu);
	}
	spin_unlock(&virt_lock);
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

int cksu_virt_remove_type(const char *type_name)
{
	struct virt_type_entry *e;
	struct hlist_node *tmp;
	u32 hash = 0;
	const char *p;

	for (p = type_name; *p; p++)
		hash = hash * 31 + *p;

	spin_lock(&virt_lock);
	hash_for_each_possible_safe(virt_type_table, e, tmp, node, hash) {
		if (e->hash == hash) {
			hash_del_rcu(&e->node);
			spin_unlock(&virt_lock);
			kfree_rcu(e, rcu);
			return 0;
		}
	}
	spin_unlock(&virt_lock);
	return -ENOENT;
}

void cksu_virt_clear_all(void)
{
	struct virt_rule *r;
	struct virt_permissive *p;
	struct virt_domain *d;
	struct virt_type_entry *t;
	struct virt_proc_sid *ps;
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
	hash_for_each_safe(virt_type_table, bkt, tmp, t, node) {
		hash_del_rcu(&t->node);
		kfree_rcu(t, rcu);
	}
	hash_for_each_safe(virt_proc_table, bkt, tmp, ps, node) {
		hash_del_rcu(&ps->node);
		kfree_rcu(ps, rcu);
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

int cksu_virt_add_type(const char *type_name, const char *context)
{
	struct virt_type_entry *e;
	u32 hash = 0;
	const char *p;

	for (p = type_name; *p; p++)
		hash = hash * 31 + *p;

	if (cksu_virt_type_exists(hash))
		return 0;

	if ((u32)atomic_read(&next_virt_sid) - VIRTUAL_SID_BASE >= MAX_VIRT_TYPES)
		return -ENOSPC;

	e = kmalloc(sizeof(*e), GFP_KERNEL);
	if (!e)
		return -ENOMEM;

	e->hash = hash;
	e->sid = (u32)atomic_inc_return(&next_virt_sid) - 1;
	strscpy(e->context, context, sizeof(e->context));

	spin_lock(&virt_lock);
	hash_add_rcu(virt_type_table, &e->node, hash);
	spin_unlock(&virt_lock);
	return 0;
}

bool cksu_virt_type_exists(u32 type_hash)
{
	struct virt_type_entry *e;

	rcu_read_lock();
	hash_for_each_possible_rcu(virt_type_table, e, node, type_hash) {
		if (e->hash == type_hash) {
			rcu_read_unlock();
			return true;
		}
	}
	rcu_read_unlock();
	return false;
}

u32 cksu_virt_type_to_sid(u32 type_hash)
{
	struct virt_type_entry *e;

	rcu_read_lock();
	hash_for_each_possible_rcu(virt_type_table, e, node, type_hash) {
		if (e->hash == type_hash) {
			u32 sid = e->sid;
			rcu_read_unlock();
			return sid;
		}
	}
	rcu_read_unlock();
	return 0;
}

const char *cksu_virt_sid_to_context(u32 sid)
{
	struct virt_type_entry *e;
	int bkt;

	rcu_read_lock();
	hash_for_each_rcu(virt_type_table, bkt, e, node) {
		if (e->sid == sid) {
			rcu_read_unlock();
			return e->context;
		}
	}
	rcu_read_unlock();
	return NULL;
}

char *cksu_virt_sid_to_context_dup(u32 sid, gfp_t gfp)
{
	struct virt_type_entry *e;
	char *dup = NULL;
	int bkt;

	rcu_read_lock();
	hash_for_each_rcu(virt_type_table, bkt, e, node) {
		if (e->sid == sid) {
			dup = kstrdup(e->context, gfp);
			break;
		}
	}
	rcu_read_unlock();
	return dup;
}

bool cksu_is_virtual_sid(u32 sid)
{
	return sid >= VIRTUAL_SID_BASE;
}

void cksu_virt_set_proc_sid(pid_t pid, u32 sid)
{
	struct virt_proc_sid *ps;

	spin_lock(&virt_lock);
	hash_for_each_possible(virt_proc_table, ps, node, pid) {
		if (ps->pid == pid) {
			ps->virt_sid = sid;
			spin_unlock(&virt_lock);
			return;
		}
	}
	spin_unlock(&virt_lock);

	ps = kmalloc(sizeof(*ps), GFP_KERNEL);
	if (!ps)
		return;

	ps->pid = pid;
	ps->virt_sid = sid;

	spin_lock(&virt_lock);
	hash_add_rcu(virt_proc_table, &ps->node, pid);
	spin_unlock(&virt_lock);
}

u32 cksu_virt_get_proc_sid(pid_t pid)
{
	struct virt_proc_sid *ps;

	rcu_read_lock();
	hash_for_each_possible_rcu(virt_proc_table, ps, node, pid) {
		if (ps->pid == pid) {
			u32 sid = ps->virt_sid;
			rcu_read_unlock();
			return sid;
		}
	}
	rcu_read_unlock();
	return 0;
}
