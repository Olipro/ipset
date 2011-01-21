/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 * Copyright (C) 2003-2011 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module implementing an IP set type: the bitmap:ip type */

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <net/netlink.h>
#include <net/tcp.h>

#include <linux/netfilter/ipset/pfxlen.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_bitmap.h>
#define IP_SET_BITMAP_TIMEOUT
#include <linux/netfilter/ipset/ip_set_timeout.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
MODULE_DESCRIPTION("bitmap:ip type of IP sets");
MODULE_ALIAS("ip_set_bitmap:ip");

/* Base variant */

struct bitmap_ip {
	void *members;		/* the set members */
	u32 first_ip;		/* host byte order, included in range */
	u32 last_ip;		/* host byte order, included in range */
	u32 elements;		/* number of max elements in the set */
	u32 hosts;		/* number of hosts in a subnet */
	size_t memsize;		/* members size */
	u8 netmask;		/* subnet netmask */
};

static inline u32
ip_to_id(const struct bitmap_ip *m, u32 ip)
{
	return ((ip & ip_set_hostmask(m->netmask)) - m->first_ip)/m->hosts;
}

static inline int
bitmap_ip_test(const struct bitmap_ip *map, u32 id)
{
	return !!test_bit(id, map->members);
}

static inline int
bitmap_ip_add(struct bitmap_ip *map, u32 id)
{
	if (test_and_set_bit(id, map->members))
		return -IPSET_ERR_EXIST;

	return 0;
}

static inline int
bitmap_ip_del(struct bitmap_ip *map, u32 id)
{
	if (!test_and_clear_bit(id, map->members))
		return -IPSET_ERR_EXIST;

	return 0;
}

static int
bitmap_ip_kadt(struct ip_set *set, const struct sk_buff *skb,
	       enum ipset_adt adt, u8 pf, u8 dim, u8 flags)
{
	struct bitmap_ip *map = set->data;
	u32 ip;

	ip = ntohl(ip4addr(skb, flags & IPSET_DIM_ONE_SRC));
	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	ip = ip_to_id(map, ip);

	switch (adt) {
	case IPSET_TEST:
		return bitmap_ip_test(map, ip);
	case IPSET_ADD:
		return bitmap_ip_add(map, ip);
	case IPSET_DEL:
		return bitmap_ip_del(map, ip);
	default:
		return -EINVAL;
	}
}

static const struct nla_policy bitmap_ip_adt_policy[IPSET_ATTR_ADT_MAX+1] = {
	[IPSET_ATTR_IP]		= { .type = NLA_NESTED },
	[IPSET_ATTR_IP_TO]	= { .type = NLA_NESTED },
	[IPSET_ATTR_CIDR]	= { .type = NLA_U8 },
	[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
	[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
};

static int
bitmap_ip_uadt(struct ip_set *set, struct nlattr *head, int len,
	       enum ipset_adt adt, u32 *lineno, u32 flags)
{
	struct bitmap_ip *map = set->data;
	struct nlattr *tb[IPSET_ATTR_ADT_MAX+1];
	u32 ip, ip_to, id;
	int ret = 0;

	if (nla_parse(tb, IPSET_ATTR_ADT_MAX, head, len,
		      bitmap_ip_adt_policy))
		return -IPSET_ERR_PROTOCOL;

	if (unlikely(!tb[IPSET_ATTR_IP]))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP], &ip);
	if (ret)
		return ret;

	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	/* Set was defined without timeout support:
	 * don't ignore the attribute silently */
	if (tb[IPSET_ATTR_TIMEOUT])
		return -IPSET_ERR_TIMEOUT;

	if (adt == IPSET_TEST)
		return bitmap_ip_test(map, ip_to_id(map, ip));

	if (tb[IPSET_ATTR_IP_TO]) {
		ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP_TO], &ip_to);
		if (ret)
			return ret;
		if (ip > ip_to) {
			swap(ip, ip_to);
			if (ip < map->first_ip)
				return -IPSET_ERR_BITMAP_RANGE;
		}
	} else if (tb[IPSET_ATTR_CIDR]) {
		u8 cidr = nla_get_u8(tb[IPSET_ATTR_CIDR]);

		if (cidr > 32)
			return -IPSET_ERR_INVALID_CIDR;
		ip &= ip_set_hostmask(cidr);
		ip_to = ip | ~ip_set_hostmask(cidr);
	} else
		ip_to = ip;

	if (ip_to > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	for (; !before(ip_to, ip); ip += map->hosts) {
		id = ip_to_id(map, ip);
		ret = adt == IPSET_ADD ? bitmap_ip_add(map, id)
				       : bitmap_ip_del(map, id);

		if (ret && !ip_set_eexist(ret, flags))
			return ret;
		else
			ret = 0;
	}
	return ret;
}

static void
bitmap_ip_destroy(struct ip_set *set)
{
	struct bitmap_ip *map = set->data;

	ip_set_free(map->members);
	kfree(map);

	set->data = NULL;
}

static void
bitmap_ip_flush(struct ip_set *set)
{
	struct bitmap_ip *map = set->data;

	memset(map->members, 0, map->memsize);
}

static int
bitmap_ip_head(struct ip_set *set, struct sk_buff *skb)
{
	const struct bitmap_ip *map = set->data;
	struct nlattr *nested;

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP, htonl(map->first_ip));
	NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP_TO, htonl(map->last_ip));
	if (map->netmask != 32)
		NLA_PUT_U8(skb, IPSET_ATTR_NETMASK, map->netmask);
	NLA_PUT_NET32(skb, IPSET_ATTR_REFERENCES,
		      htonl(atomic_read(&set->ref) - 1));
	NLA_PUT_NET32(skb, IPSET_ATTR_MEMSIZE,
		      htonl(sizeof(*map) + map->memsize));
	ipset_nest_end(skb, nested);

	return 0;
nla_put_failure:
	return -EFAULT;
}

static int
bitmap_ip_list(const struct ip_set *set,
	       struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct bitmap_ip *map = set->data;
	struct nlattr *atd, *nested;
	u32 id, first = cb->args[2];

	atd = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!atd)
		return -EFAULT;
	for (; cb->args[2] < map->elements; cb->args[2]++) {
		id = cb->args[2];
		if (!bitmap_ip_test(map, id))
			continue;
		nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
		if (!nested) {
			if (id == first) {
				nla_nest_cancel(skb, atd);
				return -EFAULT;
			} else
				goto nla_put_failure;
		}
		NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP,
				htonl(map->first_ip + id * map->hosts));
		ipset_nest_end(skb, nested);
	}
	ipset_nest_end(skb, atd);
	/* Set listing finished */
	cb->args[2] = 0;
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nested);
	ipset_nest_end(skb, atd);
	return 0;
}

static bool
bitmap_ip_same_set(const struct ip_set *a, const struct ip_set *b)
{
	const struct bitmap_ip *x = a->data;
	const struct bitmap_ip *y = b->data;

	return x->first_ip == y->first_ip &&
	       x->last_ip == y->last_ip &&
	       x->netmask == y->netmask;
}

static const struct ip_set_type_variant bitmap_ip = {
	.kadt	= bitmap_ip_kadt,
	.uadt	= bitmap_ip_uadt,
	.destroy = bitmap_ip_destroy,
	.flush	= bitmap_ip_flush,
	.head	= bitmap_ip_head,
	.list	= bitmap_ip_list,
	.same_set = bitmap_ip_same_set,
};

/* Timeout variant */

struct bitmap_ip_timeout {
	unsigned long *members;	/* the set members */
	u32 first_ip;		/* host byte order, included in range */
	u32 last_ip;		/* host byte order, included in range */
	u32 elements;		/* number of max elements in the set */
	u32 hosts;		/* number of hosts in a subnet */
	size_t memsize;		/* members size */
	u8 netmask;		/* subnet netmask */

	u32 timeout;		/* timeout parameter */
	struct timer_list gc;	/* garbage collection */
};

static inline bool
bitmap_ip_timeout_test(const struct bitmap_ip_timeout *map, u32 id)
{
	return ip_set_timeout_test(map->members[id]);
}

static inline int
bitmap_ip_timeout_add(struct bitmap_ip_timeout *map,
		      u32 id, u32 timeout)
{
	if (bitmap_ip_timeout_test(map, id))
		return -IPSET_ERR_EXIST;

	map->members[id] = ip_set_timeout_set(timeout);

	return 0;
}

static inline int
bitmap_ip_timeout_del(struct bitmap_ip_timeout *map, u32 id)
{
	int ret = -IPSET_ERR_EXIST;

	if (bitmap_ip_timeout_test(map, id))
		ret = 0;

	map->members[id] = IPSET_ELEM_UNSET;
	return ret;
}

static int
bitmap_ip_timeout_kadt(struct ip_set *set, const struct sk_buff *skb,
		       enum ipset_adt adt, u8 pf, u8 dim, u8 flags)
{
	struct bitmap_ip_timeout *map = set->data;
	u32 ip;

	ip = ntohl(ip4addr(skb, flags & IPSET_DIM_ONE_SRC));
	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	ip = ip_to_id((const struct bitmap_ip *)map, ip);

	switch (adt) {
	case IPSET_TEST:
		return bitmap_ip_timeout_test(map, ip);
	case IPSET_ADD:
		return bitmap_ip_timeout_add(map, ip, map->timeout);
	case IPSET_DEL:
		return bitmap_ip_timeout_del(map, ip);
	default:
		return -EINVAL;
	}
}

static int
bitmap_ip_timeout_uadt(struct ip_set *set, struct nlattr *head, int len,
		       enum ipset_adt adt, u32 *lineno, u32 flags)
{
	struct bitmap_ip_timeout *map = set->data;
	struct nlattr *tb[IPSET_ATTR_ADT_MAX+1];
	u32 ip, ip_to, id, timeout = map->timeout;
	int ret = 0;

	if (nla_parse(tb, IPSET_ATTR_ADT_MAX, head, len,
		      bitmap_ip_adt_policy))
		return -IPSET_ERR_PROTOCOL;

	if (unlikely(!tb[IPSET_ATTR_IP] ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT)))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP], &ip);
	if (ret)
		return ret;

	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	if (adt == IPSET_TEST)
		return bitmap_ip_timeout_test(map,
				ip_to_id((const struct bitmap_ip *)map, ip));

	if (tb[IPSET_ATTR_IP_TO]) {
		ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP_TO], &ip_to);
		if (ret)
			return ret;
		if (ip > ip_to) {
			swap(ip, ip_to);
			if (ip < map->first_ip)
				return -IPSET_ERR_BITMAP_RANGE;
		}
	} else if (tb[IPSET_ATTR_CIDR]) {
		u8 cidr = nla_get_u8(tb[IPSET_ATTR_CIDR]);

		if (cidr > 32)
			return -IPSET_ERR_INVALID_CIDR;
		ip &= ip_set_hostmask(cidr);
		ip_to = ip | ~ip_set_hostmask(cidr);
	} else
		ip_to = ip;

	if (ip_to > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	if (tb[IPSET_ATTR_TIMEOUT])
		timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);

	for (; !before(ip_to, ip); ip += map->hosts) {
		id = ip_to_id((const struct bitmap_ip *)map, ip);
		ret = adt == IPSET_ADD
			? bitmap_ip_timeout_add(map, id, timeout)
			: bitmap_ip_timeout_del(map, id);

		if (ret && !ip_set_eexist(ret, flags))
			return ret;
		else
			ret = 0;
	}
	return ret;
}

static void
bitmap_ip_timeout_destroy(struct ip_set *set)
{
	struct bitmap_ip_timeout *map = set->data;

	del_timer_sync(&map->gc);
	ip_set_free(map->members);
	kfree(map);

	set->data = NULL;
}

static void
bitmap_ip_timeout_flush(struct ip_set *set)
{
	struct bitmap_ip_timeout *map = set->data;

	memset(map->members, IPSET_ELEM_UNSET, map->memsize);
}

static int
bitmap_ip_timeout_head(struct ip_set *set, struct sk_buff *skb)
{
	const struct bitmap_ip_timeout *map = set->data;
	struct nlattr *nested;

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP, htonl(map->first_ip));
	NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP_TO, htonl(map->last_ip));
	if (map->netmask != 32)
		NLA_PUT_U8(skb, IPSET_ATTR_NETMASK, map->netmask);
	NLA_PUT_NET32(skb, IPSET_ATTR_TIMEOUT, htonl(map->timeout));
	NLA_PUT_NET32(skb, IPSET_ATTR_REFERENCES,
		      htonl(atomic_read(&set->ref) - 1));
	NLA_PUT_NET32(skb, IPSET_ATTR_MEMSIZE,
		      htonl(sizeof(*map) + map->memsize));
	ipset_nest_end(skb, nested);

	return 0;
nla_put_failure:
	return -EFAULT;
}

static int
bitmap_ip_timeout_list(const struct ip_set *set,
		       struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct bitmap_ip_timeout *map = set->data;
	struct nlattr *adt, *nested;
	u32 id, first = cb->args[2];
	const unsigned long *table = map->members;

	adt = ipset_nest_start(skb, IPSET_ATTR_ADT);
	if (!adt)
		return -EFAULT;
	for (; cb->args[2] < map->elements; cb->args[2]++) {
		id = cb->args[2];
		if (!bitmap_ip_timeout_test(map, id))
			continue;
		nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
		if (!nested) {
			if (id == first) {
				nla_nest_cancel(skb, adt);
				return -EFAULT;
			} else
				goto nla_put_failure;
		}
		NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP,
				htonl(map->first_ip + id * map->hosts));
		NLA_PUT_NET32(skb, IPSET_ATTR_TIMEOUT,
			      htonl(ip_set_timeout_get(table[id])));
		ipset_nest_end(skb, nested);
	}
	ipset_nest_end(skb, adt);

	/* Set listing finished */
	cb->args[2] = 0;

	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nested);
	ipset_nest_end(skb, adt);
	return 0;
}

static bool
bitmap_ip_timeout_same_set(const struct ip_set *a, const struct ip_set *b)
{
	const struct bitmap_ip_timeout *x = a->data;
	const struct bitmap_ip_timeout *y = b->data;

	return x->first_ip == y->first_ip &&
	       x->last_ip == y->last_ip &&
	       x->netmask == y->netmask &&
	       x->timeout == y->timeout;
}

static const struct ip_set_type_variant bitmap_ip_timeout = {
	.kadt	= bitmap_ip_timeout_kadt,
	.uadt	= bitmap_ip_timeout_uadt,
	.destroy = bitmap_ip_timeout_destroy,
	.flush	= bitmap_ip_timeout_flush,
	.head	= bitmap_ip_timeout_head,
	.list	= bitmap_ip_timeout_list,
	.same_set = bitmap_ip_timeout_same_set,
};

static void
bitmap_ip_gc(unsigned long ul_set)
{
	struct ip_set *set = (struct ip_set *) ul_set;
	struct bitmap_ip_timeout *map = set->data;
	unsigned long *table = map->members;
	u32 id;

	/* We run parallel with other readers (test element)
	 * but adding/deleting new entries is locked out */
	read_lock_bh(&set->lock);
	for (id = 0; id < map->elements; id++)
		if (ip_set_timeout_expired(table[id]))
			table[id] = IPSET_ELEM_UNSET;
	read_unlock_bh(&set->lock);

	map->gc.expires = jiffies + IPSET_GC_PERIOD(map->timeout) * HZ;
	add_timer(&map->gc);
}

static void
bitmap_ip_gc_init(struct ip_set *set)
{
	struct bitmap_ip_timeout *map = set->data;

	init_timer(&map->gc);
	map->gc.data = (unsigned long) set;
	map->gc.function = bitmap_ip_gc;
	map->gc.expires = jiffies + IPSET_GC_PERIOD(map->timeout) * HZ;
	add_timer(&map->gc);
}

/* Create bitmap:ip type of sets */

static const struct nla_policy
bitmap_ip_create_policy[IPSET_ATTR_CREATE_MAX+1] = {
	[IPSET_ATTR_IP]		= { .type = NLA_NESTED },
	[IPSET_ATTR_IP_TO]	= { .type = NLA_NESTED },
	[IPSET_ATTR_CIDR]	= { .type = NLA_U8 },
	[IPSET_ATTR_NETMASK]	= { .type = NLA_U8  },
	[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
};

static bool
init_map_ip(struct ip_set *set, struct bitmap_ip *map,
	    u32 first_ip, u32 last_ip,
	    u32 elements, u32 hosts, u8 netmask)
{
	map->members = ip_set_alloc(map->memsize, GFP_KERNEL);
	if (!map->members)
		return false;
	map->first_ip = first_ip;
	map->last_ip = last_ip;
	map->elements = elements;
	map->hosts = hosts;
	map->netmask = netmask;

	set->data = map;
	set->family = AF_INET;

	return true;
}

static int
bitmap_ip_create(struct ip_set *set, struct nlattr *head, int len,
		 u32 flags)
{
	struct nlattr *tb[IPSET_ATTR_CREATE_MAX+1];
	u32 first_ip, last_ip, hosts, elements;
	u8 netmask = 32;
	int ret;

	if (nla_parse(tb, IPSET_ATTR_CREATE_MAX, head, len,
		      bitmap_ip_create_policy))
		return -IPSET_ERR_PROTOCOL;

	if (unlikely(!tb[IPSET_ATTR_IP] ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT)))
		return -IPSET_ERR_PROTOCOL;

	ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP], &first_ip);
	if (ret)
		return ret;

	if (tb[IPSET_ATTR_IP_TO]) {
		ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP_TO], &last_ip);
		if (ret)
			return ret;
		if (first_ip > last_ip) {
			u32 tmp = first_ip;

			first_ip = last_ip;
			last_ip = tmp;
		}
	} else if (tb[IPSET_ATTR_CIDR]) {
		u8 cidr = nla_get_u8(tb[IPSET_ATTR_CIDR]);

		if (cidr >= 32)
			return -IPSET_ERR_INVALID_CIDR;
		last_ip = first_ip | ~ip_set_hostmask(cidr);
	} else
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_NETMASK]) {
		netmask = nla_get_u8(tb[IPSET_ATTR_NETMASK]);

		if (netmask > 32)
			return -IPSET_ERR_INVALID_NETMASK;

		first_ip &= ip_set_hostmask(netmask);
		last_ip |= ~ip_set_hostmask(netmask);
	}

	if (netmask == 32) {
		hosts = 1;
		elements = last_ip - first_ip + 1;
	} else {
		u8 mask_bits;
		u32 mask;

		mask = range_to_mask(first_ip, last_ip, &mask_bits);

		if ((!mask && (first_ip || last_ip != 0xFFFFFFFF)) ||
		    netmask <= mask_bits)
			return -IPSET_ERR_BITMAP_RANGE;

		pr_debug("mask_bits %u, netmask %u\n", mask_bits, netmask);
		hosts = 2 << (32 - netmask - 1);
		elements = 2 << (netmask - mask_bits - 1);
	}
	if (elements > IPSET_BITMAP_MAX_RANGE + 1)
		return -IPSET_ERR_BITMAP_RANGE_SIZE;

	pr_debug("hosts %u, elements %u\n", hosts, elements);

	if (tb[IPSET_ATTR_TIMEOUT]) {
		struct bitmap_ip_timeout *map;

		map = kzalloc(sizeof(*map), GFP_KERNEL);
		if (!map)
			return -ENOMEM;

		map->memsize = elements * sizeof(unsigned long);

		if (!init_map_ip(set, (struct bitmap_ip *)map,
				 first_ip, last_ip,
				 elements, hosts, netmask)) {
			kfree(map);
			return -ENOMEM;
		}

		map->timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
		set->variant = &bitmap_ip_timeout;

		bitmap_ip_gc_init(set);
	} else {
		struct bitmap_ip *map;

		map = kzalloc(sizeof(*map), GFP_KERNEL);
		if (!map)
			return -ENOMEM;

		map->memsize = bitmap_bytes(0, elements - 1);

		if (!init_map_ip(set, map,
				 first_ip, last_ip,
				 elements, hosts, netmask)) {
			kfree(map);
			return -ENOMEM;
		}

		set->variant = &bitmap_ip;
	}
	return 0;
}

static struct ip_set_type bitmap_ip_type __read_mostly = {
	.name		= "bitmap:ip",
	.protocol	= IPSET_PROTOCOL,
	.features	= IPSET_TYPE_IP,
	.dimension	= IPSET_DIM_ONE,
	.family		= AF_INET,
	.revision	= 0,
	.create		= bitmap_ip_create,
	.me		= THIS_MODULE,
};

static int __init
bitmap_ip_init(void)
{
	return ip_set_type_register(&bitmap_ip_type);
}

static void __exit
bitmap_ip_fini(void)
{
	ip_set_type_unregister(&bitmap_ip_type);
}

module_init(bitmap_ip_init);
module_exit(bitmap_ip_fini);
