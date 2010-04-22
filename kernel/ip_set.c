/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 * Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module for IP set management */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <net/netlink.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/ip_set.h>
#include <linux/netfilter/ip_set_jhash.h>

static struct list_head ip_set_type_list;	/* all registered sets */
static struct ip_set **ip_set_list;		/* all individual sets */
static DEFINE_MUTEX(ip_set_type_mutex);		/* protects ip_set_type_lists */
static ip_set_id_t ip_set_max = CONFIG_IP_SET_MAX;

#define STREQ(a,b)	(strncmp(a,b,IPSET_MAXNAMELEN) == 0)

static int max_sets;

module_param(max_sets, int, 0600);
MODULE_PARM_DESC(max_sets, "maximal number of sets");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
MODULE_DESCRIPTION("core IP set support");
MODULE_ALIAS_NFNL_SUBSYS(NFNL_SUBSYS_IPSET);

/*
 * The set types are implemented in modules and registered set types
 * can be found in ip_set_type_list. Adding/deleting types is
 * serialized by ip_set_type_list_lock/ip_set_type_list_unlock.
 */

static inline void
ip_set_type_list_lock(void)
{
	mutex_lock(&ip_set_type_mutex);
}

static inline void
ip_set_type_list_unlock(void)
{
	mutex_unlock(&ip_set_type_mutex);
}

/*
 * Creating/destroying/renaming/swapping affect the existence and
 * integrity of a set. All of these can be executed from userspace only
 * and serialized by nfnl_lock/nfnl_unlock indirectly from nfnetlink.
 *
 * Sets are identified by their index in ip_set_list and the index 
 * is used by the external references (set/SET netfilter modules).
 *
 * The set behind an index may change by swapping.
 *
 */

static inline void
__ip_set_get(ip_set_id_t index)
{
	atomic_inc(&ip_set_list[index]->ref);
}

static inline void
__ip_set_put(ip_set_id_t index)
{
	atomic_dec(&ip_set_list[index]->ref);
}

/* Add, del and test set entries from kernel */

int
ip_set_test(ip_set_id_t index, const struct sk_buff *skb,
	    uint8_t family, const uint8_t *flags)
{
	struct ip_set *set;
	int ret = 0;

	rcu_read_lock();
	set = rcu_dereference(ip_set_list[index]);
	D("set %s, index %u", set->name, index);

	read_lock_bh(&set->lock);
	ret = set->variant->kadt(set, skb, IPSET_TEST, family, flags);
	read_unlock_bh(&set->lock);

	if (ret == -EAGAIN) {
		/* Type requests element to be re-added */
		write_lock_bh(&set->lock);
		set->variant->kadt(set, skb, IPSET_ADD, family, flags);
		write_unlock_bh(&set->lock);
		ret = 1;
	}

	rcu_read_unlock();

	return (ret < 0 ? 0 : ret);
}

int
ip_set_add(ip_set_id_t index, const struct sk_buff *skb,
	   uint8_t family, const uint8_t *flags)
{
	struct ip_set *set;
	int ret = 0, retried = 0;

retry:
	rcu_read_lock();
	set = rcu_dereference(ip_set_list[index]);
	D("set %s, index %u", set->name, index);

	write_lock_bh(&set->lock);
	ret = set->variant->kadt(set, skb, IPSET_ADD, family, flags);
	write_unlock_bh(&set->lock);

	rcu_read_unlock();
	/* Retry function must be called without holding any lock */
	if (ret == -EAGAIN
	    && set->variant->resize
	    && (ret = set->variant->resize(set, retried++)) == 0)
	    	goto retry;
	
	return ret;
}

int
ip_set_del(ip_set_id_t index, const struct sk_buff *skb,
	   uint8_t family, const uint8_t *flags)
{
	struct ip_set *set;
	int ret = 0;

	rcu_read_lock();
	set = rcu_dereference(ip_set_list[index]);
	D("set %s, index %u", set->name, index);

	write_lock_bh(&set->lock);
	ret = set->variant->kadt(set, skb, IPSET_DEL, family, flags);
	write_unlock_bh(&set->lock);

	rcu_read_unlock();
	
	return ret;
}

/* Register and deregister settype */

#define family_name(f)	((f) == AF_INET ? "inet" : \
			 (f) == AF_INET6 ? "inet6" : "any")

static inline struct ip_set_type *
find_set_type(const char *name, uint8_t family, uint8_t revision)
{
	struct ip_set_type *type;

	list_for_each_entry(type, &ip_set_type_list, list)
		if (STREQ(type->name, name)
		    && (type->family == family || type->family == AF_UNSPEC)
		    && type->revision == revision)
			return type;
	return NULL;
}

int
ip_set_type_register(struct ip_set_type *type)
{
	int ret = 0;
	
	if (type->protocol != IPSET_PROTOCOL) {
		printk("set type %s, family %s, revision %u uses "
		       "wrong protocol version %u (want %u)\n",
		       type->name, family_name(type->family), type->revision,
		       type->protocol, IPSET_PROTOCOL);
		return -EINVAL;
	}

	ip_set_type_list_lock();
	if (find_set_type(type->name, type->family, type->revision)) {
		/* Duplicate! */
		printk("type %s, family %s, revision %u already registered!\n",
		       type->name, family_name(type->family), type->revision);
		ret = -EINVAL;
		goto unlock;
	}
	list_add(&type->list, &ip_set_type_list);
	D("type %s, family %s, revision %u registered.",
	  type->name, family_name(type->family), type->revision);
unlock:
	ip_set_type_list_unlock();
	return ret;
}

void
ip_set_type_unregister(struct ip_set_type *type)
{
	ip_set_type_list_lock();
	if (!find_set_type(type->name, type->family, type->revision)) {
		printk("type %s, family %s, revision %u not registered\n",
		       type->name, family_name(type->family), type->revision);
		goto unlock;
	}
	list_del(&type->list);
	D("type %s, family %s, revision %u unregistered.",
	  type->name, family_name(type->family), type->revision);
unlock:
	ip_set_type_list_unlock();
}

/* Get/put a set with referencing */

/*
 * Find set by name, reference it once. The reference makes sure the
 * thing pointed to, does not go away under our feet. Drop the reference
 * later, using ip_set_put*().
 */
ip_set_id_t
ip_set_get_byname(const char *name)
{
	ip_set_id_t i, index = IPSET_INVALID_ID;
	
	nfnl_lock();	
	for (i = 0; index == IPSET_INVALID_ID && i < ip_set_max; i++)
		if (STREQ(ip_set_list[i]->name, name)) {
			__ip_set_get(i);
			index = i;
		}
	nfnl_unlock();

	return index;
}

/*
 * If the given set pointer points to a valid set, decrement
 * reference count by 1. The caller shall not assume the index
 * to be valid, after calling this function.
 */
void
ip_set_put_byindex(ip_set_id_t index)
{
	nfnl_lock();
	if (ip_set_list[index])
		__ip_set_put(index);
	nfnl_unlock();
}

static ip_set_id_t
find_set_id(const char *name)
{
	ip_set_id_t i, index = IPSET_INVALID_ID;
	
	for (i = 0; index == IPSET_INVALID_ID && i < ip_set_max; i++) {
		if (ip_set_list[i] != NULL
		    && STREQ(ip_set_list[i]->name, name))
			index = i;
	}
	return index;
}

static ip_set_id_t
find_set_id_rcu(const char *name)
{
	ip_set_id_t i, index = IPSET_INVALID_ID;
	struct ip_set *set;
	
	for (i = 0; index == IPSET_INVALID_ID && i < ip_set_max; i++) {
		set = rcu_dereference(ip_set_list[i]);
		if (set != NULL && STREQ(set->name, name))
			index = i;
	}
	return index;
}

static struct ip_set *
find_set(const char *name)
{
	ip_set_id_t index = find_set_id(name);

	return index == IPSET_INVALID_ID ? NULL : ip_set_list[index];
}

/* Communication protocol with userspace over netlink */

/* Create a set */

static const struct nla_policy
ip_set_create_policy[IPSET_ATTR_CMD_MAX + 1] __read_mostly = {
	[IPSET_ATTR_PROTOCOL]	= { .type = NLA_U8 },
	[IPSET_ATTR_SETNAME]	= { .type = NLA_STRING,
				    .len = IPSET_MAXNAMELEN },
	[IPSET_ATTR_TYPENAME]	= { .type = NLA_STRING,
				    .len = IPSET_MAXNAMELEN },
	[IPSET_ATTR_REVISION]	= { .type = NLA_U8 },
	[IPSET_ATTR_FAMILY]	= { .type = NLA_U8 },
	[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
	[IPSET_ATTR_DATA]	= { .type = NLA_NESTED },
};

static inline bool
protocol_failed(const struct nlattr * const tb[])
{
	return !tb[IPSET_ATTR_PROTOCOL]
	       || nla_get_u8(tb[IPSET_ATTR_PROTOCOL]) != IPSET_PROTOCOL;
}

static inline uint32_t
flag_exist(const struct nlmsghdr *nlh)
{
	return nlh->nlmsg_flags & NLM_F_EXCL ? 0 : IPSET_FLAG_EXIST;
}

static inline bool
flag_nested(const struct nlattr *nla)
{
	return nla->nla_type & NLA_F_NESTED;
}

static struct ip_set_type *
find_set_type_lock(const char *name, uint8_t family, uint8_t revision)
{
	struct ip_set_type *type;
	
	ip_set_type_list_lock();
	type = find_set_type(name, family, revision);
	if (type == NULL)
		ip_set_type_list_unlock();

	return type;
}

static int
find_free_id(const char *name, ip_set_id_t *index, struct ip_set **set)
{
	ip_set_id_t i;

	*index = IPSET_INVALID_ID;
	for (i = 0;  i < ip_set_max; i++) {
		if (ip_set_list[i] == NULL) {
			if (*index == IPSET_INVALID_ID)
				*index = i;
		} else if (STREQ(name, ip_set_list[i]->name)) {
			/* Name clash */
			*set = ip_set_list[i];
			return -EEXIST;
		}
	}
	if (*index == IPSET_INVALID_ID)
		/* No free slot remained */
		return -IPSET_ERR_MAX_SETS;
	return 0;
}

static struct nlmsghdr *
start_msg(struct sk_buff *skb, u32 pid, u32 seq, unsigned int flags,
	  enum ipset_cmd cmd)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfmsg;

	nlh = nlmsg_put(skb, pid, seq, cmd | (NFNL_SUBSYS_IPSET << 8),
			sizeof(*nfmsg), flags);
	if (nlh == NULL)
		return NULL;

	nfmsg = nlmsg_data(nlh);
	nfmsg->nfgen_family = AF_INET;
	nfmsg->version = NFNETLINK_V0;
	nfmsg->res_id = 0;
	
	return nlh;
}

static inline void
load_type_module(const char *typename)
{
	D("try to load ip_set_%s", typename);
	request_module("ip_set_%s", typename);
}

static int
ip_set_create(struct sock *ctnl, struct sk_buff *skb,
	      const struct nlmsghdr *nlh,
	      const struct nlattr * const attr[])
{
	struct ip_set *set, *clash;
	ip_set_id_t index = IPSET_INVALID_ID;
	const char *name, *typename;
	uint8_t family, revision;
	uint32_t flags = flag_exist(nlh);
	int ret = 0, len;

	if (unlikely(protocol_failed(attr)	
		     || attr[IPSET_ATTR_SETNAME] == NULL
		     || attr[IPSET_ATTR_TYPENAME] == NULL
		     || attr[IPSET_ATTR_REVISION] == NULL
		     || attr[IPSET_ATTR_FAMILY] == NULL
		     || (attr[IPSET_ATTR_DATA] != NULL
		         && !flag_nested(attr[IPSET_ATTR_DATA]))))
		return -IPSET_ERR_PROTOCOL;

	name = nla_data(attr[IPSET_ATTR_SETNAME]);
	typename = nla_data(attr[IPSET_ATTR_TYPENAME]);
	family = nla_get_u8(attr[IPSET_ATTR_FAMILY]);
	revision = nla_get_u8(attr[IPSET_ATTR_REVISION]);
	D("setname: %s, typename: %s, family: %s, revision: %u",
	  name, typename, family_name(family), revision);

	/*
	 * First, and without any locks, allocate and initialize
	 * a normal base set structure.
	 */
	set = kzalloc(sizeof(struct ip_set), GFP_KERNEL);
	if (!set)
		return -ENOMEM;
	rwlock_init(&set->lock);
	strncpy(set->name, name, IPSET_MAXNAMELEN);
	atomic_set(&set->ref, 0);

	/*
	 * Next, check that we know the type, and take
	 * a reference on the type, to make sure it stays available
	 * while constructing our new set.
	 *
	 * After referencing the type, we try to create the type
	 * specific part of the set without holding any locks.
	 */
	set->type = find_set_type_lock(typename, family, revision);
	if (set->type == NULL) {
		/* Try loading the module */
		load_type_module(typename);
		set->type = find_set_type_lock(typename, family, revision);
		if (set->type == NULL) {
			printk("Can't find type %s, family %s, revision %u:"
			       " set '%s' not created",
			       typename, family_name(family), revision, name);
			ret = -IPSET_ERR_FIND_TYPE;
			goto out;
		}
	}
	if (!try_module_get(set->type->me)) {
		ip_set_type_list_unlock();
		ret = -EFAULT;
		goto out;
	}
	ip_set_type_list_unlock();

	/*
	 * Without holding any locks, create private part.
	 */
	len = attr[IPSET_ATTR_DATA] ? nla_len(attr[IPSET_ATTR_DATA]) : 0;
	D("data len: %u", len);
	ret = set->type->create(set, attr[IPSET_ATTR_DATA] ?
				nla_data(attr[IPSET_ATTR_DATA]) : NULL, len,
				flags);
	if (ret != 0)
		goto put_out;

	/* BTW, ret==0 here. */

	/*
	 * Here, we have a valid, constructed set and we are protected
	 * by nfnl_lock. Find the first free index in ip_set_list and
	 * check clashing.
	 */
	if ((ret = find_free_id(set->name, &index, &clash)) != 0) {
		/* If this is the same set and requested, ignore error */
		if (ret == -EEXIST
		    && (flags & IPSET_FLAG_EXIST)
		    && STREQ(set->type->name, clash->type->name)
		    && set->type->family == clash->type->family
		    && set->type->revision == clash->type->revision)
		    	ret = 0;
		goto cleanup;
	}

	/*
	 * Finally! Add our shiny new set to the list, and be done.
	 */
	D("create: '%s' created with index %u!", set->name, index);
	ip_set_list[index] = set;

	return ret;
	
cleanup:
	set->variant->destroy(set);
put_out:
	module_put(set->type->me);
out:
	kfree(set);
	return ret;
}

/* Destroy sets */

static const struct nla_policy
ip_set_setname_policy[IPSET_ATTR_CMD_MAX + 1] __read_mostly = {
	[IPSET_ATTR_PROTOCOL]	= { .type = NLA_U8 },
	[IPSET_ATTR_SETNAME]	= { .type = NLA_STRING,
				    .len = IPSET_MAXNAMELEN },
};

static inline void
ip_set_destroy_set(ip_set_id_t index)
{
	struct ip_set *set = ip_set_list[index];

	D("set: %s",  set->name);
	ip_set_list[index] = NULL;

	/* Must call it without holding any lock */
	set->variant->destroy(set);
	module_put(set->type->me);
	kfree(set);
}

static int
ip_set_destroy(struct sock *ctnl, struct sk_buff *skb,
	       const struct nlmsghdr *nlh,
	       const struct nlattr * const attr[])
{
	ip_set_id_t i;
	
	if (unlikely(protocol_failed(attr)))
		return -IPSET_ERR_PROTOCOL;

	/* References are protected by the nfnl mutex */
	if (!attr[IPSET_ATTR_SETNAME]) {
		for (i = 0; i < ip_set_max; i++) {
			if (ip_set_list[i] != NULL
			    && (atomic_read(&ip_set_list[i]->ref)))
			    	return -IPSET_ERR_BUSY;
		}
		for (i = 0; i < ip_set_max; i++) {
			if (ip_set_list[i] != NULL)
				ip_set_destroy_set(i);
		}
	} else {
		i = find_set_id(nla_data(attr[IPSET_ATTR_SETNAME]));
		if (i == IPSET_INVALID_ID)
			return -EEXIST;
		else if (atomic_read(&ip_set_list[i]->ref))
			return -IPSET_ERR_BUSY;

		ip_set_destroy_set(i);
	}
	return 0;
}

/* Flush sets */

static inline void
ip_set_flush_set(struct ip_set *set)
{
	D("set: %s",  set->name);

	write_lock_bh(&set->lock);
	set->variant->flush(set);
	write_unlock_bh(&set->lock);
}

static int
ip_set_flush(struct sock *ctnl, struct sk_buff *skb,
	     const struct nlmsghdr *nlh,
	     const struct nlattr * const attr[])
{
	ip_set_id_t i;

	if (unlikely(protocol_failed(attr)))
		return -EPROTO;

	if (!attr[IPSET_ATTR_SETNAME]) {
		for (i = 0; i < ip_set_max; i++)
			if (ip_set_list[i] != NULL)
				ip_set_flush_set(ip_set_list[i]);
	} else {
		i = find_set_id(nla_data(attr[IPSET_ATTR_SETNAME]));
		if (i == IPSET_INVALID_ID)
			return -EEXIST;

		ip_set_flush_set(ip_set_list[i]);
	}

	return 0;
}

/* Rename a set */

static const struct nla_policy
ip_set_setname2_policy[IPSET_ATTR_CMD_MAX + 1] __read_mostly = {
	[IPSET_ATTR_PROTOCOL]	= { .type = NLA_U8 },
	[IPSET_ATTR_SETNAME]	= { .type = NLA_STRING,
				    .len = IPSET_MAXNAMELEN },
	[IPSET_ATTR_SETNAME2]	= { .type = NLA_STRING,
				    .len = IPSET_MAXNAMELEN },
};

static int
ip_set_rename(struct sock *ctnl, struct sk_buff *skb,
	      const struct nlmsghdr *nlh,
	      const struct nlattr * const attr[])
{
	struct ip_set *set;
	const char *name2;
	ip_set_id_t i;

	if (unlikely(protocol_failed(attr)
		     || attr[IPSET_ATTR_SETNAME] == NULL
		     || attr[IPSET_ATTR_SETNAME2] == NULL))
		return -IPSET_ERR_PROTOCOL;

	set = find_set(nla_data(attr[IPSET_ATTR_SETNAME]));
	if (set == NULL)
		return -EEXIST;

	name2 = nla_data(attr[IPSET_ATTR_SETNAME2]);
	for (i = 0; i < ip_set_max; i++) {
		if (ip_set_list[i] != NULL
		    && STREQ(ip_set_list[i]->name, name2))
			return -IPSET_ERR_EXIST_SETNAME2;
	}
	strncpy(set->name, name2, IPSET_MAXNAMELEN);

	return 0;
}

/* Swap two sets so that name/index points to the other.
 * References are also swapped. */

static int
ip_set_swap(struct sock *ctnl, struct sk_buff *skb,
	    const struct nlmsghdr *nlh,
	    const struct nlattr * const attr[])
{
	struct ip_set *from, *to;
	ip_set_id_t from_id, to_id;
	char from_name[IPSET_MAXNAMELEN];
	uint32_t from_ref;
	
	if (unlikely(protocol_failed(attr)
		     || attr[IPSET_ATTR_SETNAME] == NULL
		     || attr[IPSET_ATTR_SETNAME2] == NULL))
		return -IPSET_ERR_PROTOCOL;

	from_id = find_set_id(nla_data(attr[IPSET_ATTR_SETNAME]));
	if (from_id == IPSET_INVALID_ID)
		return -EEXIST;

	to_id = find_set_id(nla_data(attr[IPSET_ATTR_SETNAME2]));
	if (to_id == IPSET_INVALID_ID)
		return -IPSET_ERR_EXIST_SETNAME2;

	from = ip_set_list[from_id];
	to = ip_set_list[to_id];
	
	/* Features must not change.
	 * Not an artifical restriction anymore, as we must prevent
	 * possible loops created by swapping in setlist type of sets. */
	if (!(from->type->features == to->type->features
	      && from->type->family == to->type->family))
		return -IPSET_ERR_TYPE_MISMATCH;

	/* No magic here: ref munging protected by the mutex */	
	strncpy(from_name, from->name, IPSET_MAXNAMELEN);
	from_ref = atomic_read(&from->ref);

	strncpy(from->name, to->name, IPSET_MAXNAMELEN);
	atomic_set(&from->ref, atomic_read(&to->ref));
	strncpy(to->name, from_name, IPSET_MAXNAMELEN);
	atomic_set(&to->ref, from_ref);
	
	rcu_assign_pointer(ip_set_list[from_id], to);
	rcu_assign_pointer(ip_set_list[to_id], from);
	synchronize_rcu();

	return 0;
}

/* List/save set data */

static int
ip_set_dump_done(struct netlink_callback *cb)
{
	if (cb->args[2])
		__ip_set_put((ip_set_id_t) cb->args[1]);
	return 0;
}

static inline void
dump_attrs(struct nlmsghdr *nlh)
{
	struct nlattr *attr;
	int rem;

	D("dump nlmsg");	
	nlmsg_for_each_attr(attr, nlh, sizeof(struct nfgenmsg), rem) {
		D("type: %u, len %u", nla_type(attr), attr->nla_len);
	}
}

static int
ip_set_dump_start(struct sk_buff *skb, struct netlink_callback *cb)
{
	ip_set_id_t index = IPSET_INVALID_ID, max;
	struct ip_set *set = NULL;
	struct nlmsghdr *nlh = NULL;
	unsigned int flags = NETLINK_CB(cb->skb).pid ? NLM_F_MULTI : 0;
	int ret = 0;

	max = cb->args[0] ? cb->args[1] + 1 : ip_set_max;
	rcu_read_lock();
	for (; cb->args[1] < max; cb->args[1]++) {
		index = (ip_set_id_t) cb->args[1];
		set = rcu_dereference(ip_set_list[index]);
		if (set == NULL) {
			if (cb->args[0]) {
				ret = -EEXIST;
				goto unlock;
			}
			continue;
		}
		D("List set: %s", set->name);
		if (!cb->args[2]) {
			/* Start listing: make sure set won't be destroyed */
			D("reference set");
			__ip_set_get(index);
		}
		nlh = start_msg(skb, NETLINK_CB(cb->skb).pid,
				cb->nlh->nlmsg_seq, flags,
				IPSET_CMD_LIST);
		if (!nlh) {
			ret = -EFAULT;
			goto release_refcount;
		}
		NLA_PUT_U8(skb, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
		NLA_PUT_STRING(skb, IPSET_ATTR_SETNAME, set->name);
		switch (cb->args[2]) {
		case 0:
			/* Core header data */
			NLA_PUT_STRING(skb, IPSET_ATTR_TYPENAME,
				       set->type->name);
			NLA_PUT_U8(skb, IPSET_ATTR_FAMILY,
				   set->type->family);
			NLA_PUT_U8(skb, IPSET_ATTR_REVISION,
				   set->type->revision);
			ret = set->variant->head(set, skb);
			if (ret < 0)
				goto release_refcount;
			/* Fall through and add elements */
		default:
			read_lock_bh(&set->lock);
			ret = set->variant->list(set, skb, cb);
			read_unlock_bh(&set->lock);
			if (!cb->args[2])
				/* Set is done, proceed with next one */
				cb->args[1]++;
			goto release_refcount;
		}
	}
	goto unlock;

nla_put_failure:
	ret = -EFAULT;
release_refcount:
	/* If there was an error or set is done, release set */
	if (ret || !cb->args[2]) {
		D("release set");
		__ip_set_put(index);
	}
unlock:
	rcu_read_unlock();

	if (nlh) {
		nlmsg_end(skb, nlh);
		D("nlmsg_len: %u", nlh->nlmsg_len);
		dump_attrs(nlh);
	}
	
	return ret < 0 ? ret : skb->len;
}

static int
ip_set_dump(struct sock *ctnl, struct sk_buff *skb,
	    const struct nlmsghdr *nlh,
	    const struct nlattr * const attr[])
{
	ip_set_id_t index;
	
	if (unlikely(protocol_failed(attr)))
		return -IPSET_ERR_PROTOCOL;

	if (!attr[IPSET_ATTR_SETNAME])
		return netlink_dump_start(ctnl, skb, nlh,
					  ip_set_dump_start,
					  ip_set_dump_done);

	rcu_read_lock();
	index = find_set_id_rcu(nla_data(attr[IPSET_ATTR_SETNAME]));
	if (index == IPSET_INVALID_ID) {
		rcu_read_unlock();
		return -EEXIST;
	}
	rcu_read_unlock();

	/* cb->args[0] : 1 => dump single set,
	 *	       : 0 => dump all sets
	 * 	   [1] : set index
	 *         [..]: type specific
	 */
	return netlink_dump_init(ctnl, skb, nlh,
				 ip_set_dump_start,
				 ip_set_dump_done,
				 2, 1, index);
}

/* Add, del and test */

static const struct nla_policy
ip_set_adt_policy[IPSET_ATTR_CMD_MAX + 1] __read_mostly = {
	[IPSET_ATTR_PROTOCOL]	= { .type = NLA_U8 },
	[IPSET_ATTR_SETNAME]	= { .type = NLA_STRING,
				    .len = IPSET_MAXNAMELEN },
	[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
	[IPSET_ATTR_DATA]	= { .type = NLA_NESTED },
	[IPSET_ATTR_ADT]	= { .type = NLA_NESTED },
};

static int
call_ad(struct sock *ctnl, struct sk_buff *skb,
	const struct nlattr * const attr[],
	struct ip_set *set, const struct nlattr *nla,
	enum ipset_adt adt, uint32_t flags)
{
	struct nlattr *head = nla_data(nla);
	int ret, len = nla_len(nla), retried = 0;
	uint32_t lineno = 0;
	bool eexist = flags & IPSET_FLAG_EXIST;
	
	do {
		write_lock_bh(&set->lock);
		ret = set->variant->uadt(set, head, len, adt,
					 &lineno, flags);
		write_unlock_bh(&set->lock);
	} while (ret == -EAGAIN
		 && set->variant->resize
		 && (ret = set->variant->resize(set, retried++)) == 0);

	if (!ret || (ret == -IPSET_ERR_EXIST && eexist))
		return 0;
	if (lineno && attr[IPSET_ATTR_LINENO]) {
		/* Error in restore/batch mode: send back lineno */
		uint32_t *errline = nla_data(attr[IPSET_ATTR_LINENO]);
		
		*errline = lineno;
	}
	
	return ret;
}

static int
ip_set_uadd(struct sock *ctnl, struct sk_buff *skb,
	    const struct nlmsghdr *nlh,
	    const struct nlattr * const attr[])
{
	struct ip_set *set;
	const struct nlattr *nla;
	uint32_t flags = flag_exist(nlh);
	int ret = 0;

	if (unlikely(protocol_failed(attr)
		     || attr[IPSET_ATTR_SETNAME] == NULL
		     || !((attr[IPSET_ATTR_DATA] != NULL) ^ 
		          (attr[IPSET_ATTR_ADT] != NULL))
		     || (attr[IPSET_ATTR_DATA] != NULL
		         && !flag_nested(attr[IPSET_ATTR_DATA]))
		     || (attr[IPSET_ATTR_ADT] != NULL
		         && (!flag_nested(attr[IPSET_ATTR_ADT])
		             || attr[IPSET_ATTR_LINENO] == NULL))))
		return -IPSET_ERR_PROTOCOL;

	set = find_set(nla_data(attr[IPSET_ATTR_SETNAME]));
	if (set == NULL)
		return -EEXIST;

	if (attr[IPSET_ATTR_DATA]) {
		ret = call_ad(ctnl, skb, attr,
			      set, attr[IPSET_ATTR_DATA], IPSET_ADD, flags);
	} else {
		int nla_rem;
		
		nla_for_each_nested(nla, attr[IPSET_ATTR_ADT], nla_rem) {
			if (nla_type(nla) != IPSET_ATTR_DATA
			    || !flag_nested(nla))
				return -IPSET_ERR_PROTOCOL;
			ret = call_ad(ctnl, skb, attr,
				       set, nla, IPSET_ADD, flags);
			if (ret < 0)
				return ret;
		}
	}
	return ret;
}

static int
ip_set_udel(struct sock *ctnl, struct sk_buff *skb,
	    const struct nlmsghdr *nlh,
	    const struct nlattr * const attr[])
{
	struct ip_set *set;
	const struct nlattr *nla;
	uint32_t flags = flag_exist(nlh);
	int ret = 0;

	if (unlikely(protocol_failed(attr)
		     || attr[IPSET_ATTR_SETNAME] == NULL
		     || !((attr[IPSET_ATTR_DATA] != NULL) ^ 
		          (attr[IPSET_ATTR_ADT] != NULL))
		     || (attr[IPSET_ATTR_DATA] != NULL
		         && !flag_nested(attr[IPSET_ATTR_DATA]))
		     || (attr[IPSET_ATTR_ADT] != NULL
		         && (!flag_nested(attr[IPSET_ATTR_ADT])
		             || attr[IPSET_ATTR_LINENO] == NULL))))
		return -IPSET_ERR_PROTOCOL;
	
	set = find_set(nla_data(attr[IPSET_ATTR_SETNAME]));
	if (set == NULL)
		return -EEXIST;
	
	if (attr[IPSET_ATTR_DATA]) {
		ret = call_ad(ctnl, skb, attr,
			      set, attr[IPSET_ATTR_DATA], IPSET_DEL, flags);
	} else {
		int nla_rem;
		
		nla_for_each_nested(nla, attr[IPSET_ATTR_ADT], nla_rem) {
			if (nla_type(nla) != IPSET_ATTR_DATA
			    || !flag_nested(nla))
				return -IPSET_ERR_PROTOCOL;
			ret = call_ad(ctnl, skb, attr,
				       set, nla, IPSET_DEL, flags);
			if (ret < 0)
				return ret;
		}
	}
	return ret;
}

static int
ip_set_utest(struct sock *ctnl, struct sk_buff *skb,
	     const struct nlmsghdr *nlh,
	     const struct nlattr * const attr[])
{
	struct ip_set *set;
	int ret = 0;

	if (unlikely(protocol_failed(attr)
		     || attr[IPSET_ATTR_SETNAME] == NULL
		     || attr[IPSET_ATTR_DATA] == NULL
		     || !flag_nested(attr[IPSET_ATTR_DATA])))
		return -IPSET_ERR_PROTOCOL;
	
	set = find_set(nla_data(attr[IPSET_ATTR_SETNAME]));
	if (set == NULL)
		return -EEXIST;
	
	read_lock_bh(&set->lock);
	ret = set->variant->uadt(set,
				 nla_data(attr[IPSET_ATTR_DATA]),
				 nla_len(attr[IPSET_ATTR_DATA]),
				 IPSET_TEST, NULL, 0);
	read_unlock_bh(&set->lock);
	/* Userspace can't trigger element to be re-added */
	if (ret == -EAGAIN)
		ret = 1;
	
	return ret < 0 ? ret : ret > 0 ? 0 : -IPSET_ERR_EXIST;
}

/* Get headed data of a set */

static int
ip_set_header(struct sock *ctnl, struct sk_buff *skb,
	      const struct nlmsghdr *nlh,
	      const struct nlattr * const attr[])
{
	struct ip_set *set;
	struct sk_buff *skb2;
	struct nlmsghdr *nlh2;
	ip_set_id_t index;
	int ret = 0;

	if (unlikely(protocol_failed(attr)
		     || attr[IPSET_ATTR_SETNAME] == NULL))
		return -IPSET_ERR_PROTOCOL;
	
	index = find_set_id(nla_data(attr[IPSET_ATTR_SETNAME]));
	if (index == IPSET_INVALID_ID)
		return -EEXIST;
	set = ip_set_list[index];

	skb2 = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb2 == NULL)
		return -ENOMEM;
	
	nlh2 = start_msg(skb2, NETLINK_CB(skb).pid, nlh->nlmsg_seq, 0,
			 IPSET_CMD_HEADER);
	if (!nlh2)
		goto nlmsg_failure;
	NLA_PUT_U8(skb2, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
	NLA_PUT_STRING(skb2, IPSET_ATTR_SETNAME, set->name);
	NLA_PUT_STRING(skb2, IPSET_ATTR_TYPENAME, set->type->name);
	NLA_PUT_U8(skb2, IPSET_ATTR_FAMILY, set->type->family);
	NLA_PUT_U8(skb2, IPSET_ATTR_REVISION, set->type->revision);
	nlmsg_end(skb2, nlh2);

	ret = netlink_unicast(ctnl, skb2, NETLINK_CB(skb).pid, MSG_DONTWAIT);
	if (ret < 0)
		return -EFAULT;
	
	return 0;

nla_put_failure:
	nlmsg_cancel(skb2, nlh2);
nlmsg_failure:
	kfree_skb(skb2);	
	return -EFAULT;
}

/* Get type data */

static const struct nla_policy
ip_set_type_policy[IPSET_ATTR_CMD_MAX + 1] __read_mostly = {
	[IPSET_ATTR_PROTOCOL]	= { .type = NLA_U8 },
	[IPSET_ATTR_TYPENAME]	= { .type = NLA_STRING,
				    .len = IPSET_MAXNAMELEN },
	[IPSET_ATTR_FAMILY]	= { .type = NLA_U8 },
};

static bool
find_set_type_minmax(const char *name, uint8_t family,
		     uint8_t *min, uint8_t *max)
{
	struct ip_set_type *type;
	bool ret = false;
	
	*min = *max = 0;
	ip_set_type_list_lock();
	list_for_each_entry(type, &ip_set_type_list, list)
		if (STREQ(type->name, name)
		    && (type->family == family || type->family == AF_UNSPEC)) {
		    	ret = true;
		    	if (type->revision < *min)
		    		*min = type->revision;
			else if (type->revision > *max)
				*max = type->revision;
		}
	ip_set_type_list_unlock();

	return ret;
}

static int
ip_set_type(struct sock *ctnl, struct sk_buff *skb,
	    const struct nlmsghdr *nlh,
	    const struct nlattr * const attr[])
{
	struct sk_buff *skb2;
	struct nlmsghdr *nlh2;
	uint8_t family, min, max;
	const char *typename;
	int ret = 0;

	if (unlikely(protocol_failed(attr)
		     || attr[IPSET_ATTR_TYPENAME] == NULL
		     || attr[IPSET_ATTR_FAMILY] == NULL))
		return -IPSET_ERR_PROTOCOL;
	
	family = nla_get_u8(attr[IPSET_ATTR_FAMILY]);
	typename = nla_data(attr[IPSET_ATTR_TYPENAME]);
	if (!find_set_type_minmax(typename, family, &min, &max)) {
		/* Try to load in the type module */
		load_type_module(typename);
		if (!find_set_type_minmax(typename, family, &min, &max)) {
			D("can't find: %s, family: %u", typename, family);
			return -EEXIST;
		}
	}

	skb2 = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb2 == NULL)
		return -ENOMEM;
	
	nlh2 = start_msg(skb2, NETLINK_CB(skb).pid, nlh->nlmsg_seq, 0,
			 IPSET_CMD_TYPE);
	if (!nlh2)
		goto nlmsg_failure;
	NLA_PUT_U8(skb2, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
	NLA_PUT_STRING(skb2, IPSET_ATTR_TYPENAME, typename);
	NLA_PUT_U8(skb2, IPSET_ATTR_FAMILY, family);
	NLA_PUT_U8(skb2, IPSET_ATTR_REVISION, max);
	NLA_PUT_U8(skb2, IPSET_ATTR_REVISION_MIN, min);
	nlmsg_end(skb2, nlh2);

	D("Send TYPE, nlmsg_len: %u", nlh2->nlmsg_len);
	ret = netlink_unicast(ctnl, skb2, NETLINK_CB(skb).pid, MSG_DONTWAIT);
	if (ret < 0)
		return -EFAULT;
	
	return 0;

nla_put_failure:
	nlmsg_cancel(skb2, nlh2);
nlmsg_failure:
	kfree_skb(skb2);	
	return -EFAULT;
}

/* Get protocol version */

static const struct nla_policy
ip_set_protocol_policy[IPSET_ATTR_CMD_MAX + 1] __read_mostly = {
	[IPSET_ATTR_PROTOCOL]	= { .type = NLA_U8 },
};

static int
ip_set_protocol(struct sock *ctnl, struct sk_buff *skb,
	        const struct nlmsghdr *nlh,
	        const struct nlattr * const attr[])
{
	struct sk_buff *skb2;
	struct nlmsghdr *nlh2;
	int ret = 0;

	if (unlikely(attr[IPSET_ATTR_PROTOCOL] == NULL))
		return -IPSET_ERR_PROTOCOL;
	
	skb2 = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (skb2 == NULL)
		return -ENOMEM;
	
	nlh2 = start_msg(skb2, NETLINK_CB(skb).pid, nlh->nlmsg_seq, 0,
			 IPSET_CMD_PROTOCOL);
	if (!nlh2)
		goto nlmsg_failure;
	NLA_PUT_U8(skb2, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
	nlmsg_end(skb2, nlh2);

	ret = netlink_unicast(ctnl, skb2, NETLINK_CB(skb).pid, MSG_DONTWAIT);
	if (ret < 0)
		return -EFAULT;
	
	return 0;

nla_put_failure:
	nlmsg_cancel(skb2, nlh2);
nlmsg_failure:
	kfree_skb(skb2);	
	return -EFAULT;
}

static const struct nfnl_callback ip_set_netlink_subsys_cb[IPSET_MSG_MAX] = {
	[IPSET_CMD_CREATE]	= {
		.call		= ip_set_create,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_create_policy,
	},
	[IPSET_CMD_DESTROY]	= {
		.call		= ip_set_destroy,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_setname_policy,
	},
	[IPSET_CMD_FLUSH]	= {
		.call		= ip_set_flush,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_setname_policy,
	},
	[IPSET_CMD_RENAME]	= {
		.call		= ip_set_rename,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_setname2_policy,
	},
	[IPSET_CMD_SWAP]	= {
		.call		= ip_set_swap,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_setname2_policy,
	},
	[IPSET_CMD_LIST]	= {
		.call		= ip_set_dump,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_setname_policy,
	},
	[IPSET_CMD_SAVE]	= {
		.call		= ip_set_dump,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_setname_policy,
	},
	[IPSET_CMD_ADD]	= {
		.call		= ip_set_uadd,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_adt_policy,
	},
	[IPSET_CMD_DEL]	= {
		.call		= ip_set_udel,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_adt_policy,
	},
	[IPSET_CMD_TEST]	= {
		.call		= ip_set_utest,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_adt_policy,
	},
	[IPSET_CMD_HEADER]	= {
		.call		= ip_set_header,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_setname_policy,
	},
	[IPSET_CMD_TYPE]	= {
		.call		= ip_set_type,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_type_policy,
	},
	[IPSET_CMD_PROTOCOL]	= {
		.call		= ip_set_protocol,
		.attr_count	= IPSET_ATTR_CMD_MAX,
		.policy		= ip_set_protocol_policy,
	},
};

static struct nfnetlink_subsystem ip_set_netlink_subsys = {
	.name		= "ip_set",
	.subsys_id	= NFNL_SUBSYS_IPSET,
	.cb_count	= IPSET_MSG_MAX,
	.cb		= ip_set_netlink_subsys_cb,
};

static int __init
ip_set_init(void)
{
	int ret;

	if (max_sets)
		ip_set_max = max_sets;
	if (ip_set_max >= IPSET_INVALID_ID)
		ip_set_max = IPSET_INVALID_ID - 1;

	ip_set_list = kzalloc(sizeof(struct ip_set *) * ip_set_max, GFP_KERNEL);
	if (!ip_set_list) {
		printk(KERN_ERR "Unable to create ip_set_list\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&ip_set_type_list);

	ret = nfnetlink_subsys_register(&ip_set_netlink_subsys);
	if (ret != 0) {
		printk("ip_set_init: cannot register with nfnetlink.\n");
		kfree(ip_set_list);
		return ret;
	}

	printk("ip_set with protocol version %u loaded\n", IPSET_PROTOCOL);	
	return 0;
}

static void __exit
ip_set_fini(void)
{
	/* There can't be any existing set */
	nfnetlink_subsys_unregister(&ip_set_netlink_subsys);
	kfree(ip_set_list);
	D("these are the famous last words");
}

EXPORT_SYMBOL(ip_set_type_register);
EXPORT_SYMBOL(ip_set_type_unregister);

EXPORT_SYMBOL(ip_set_get_byname);
EXPORT_SYMBOL(ip_set_put_byindex);

EXPORT_SYMBOL(ip_set_add);
EXPORT_SYMBOL(ip_set_del);
EXPORT_SYMBOL(ip_set_test);

module_init(ip_set_init);
module_exit(ip_set_fini);
