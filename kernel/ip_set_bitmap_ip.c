/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 * Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
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
#include <asm/uaccess.h>
#include <asm/bitops.h>
#include <linux/spinlock.h>
#include <linux/netlink.h>
#include <linux/delay.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <net/netlink.h>
#include <net/pfxlen.h>
#include <net/tcp.h>

#include <linux/netfilter/ip_set.h>
#include <linux/netfilter/ip_set_bitmap.h>
#define IP_SET_BITMAP_TIMEOUT
#include <linux/netfilter/ip_set_timeout.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
MODULE_DESCRIPTION("bitmap:ip type of IP sets");
MODULE_ALIAS("ip_set_bitmap:ip");

/* Base variant */

struct bitmap_ip {
	void *members;		/* the set members */
	uint32_t first_ip;	/* host byte order, included in range */
	uint32_t last_ip;	/* host byte order, included in range */
	uint32_t elements;	/* number of max elements in the set */
	uint32_t hosts;		/* number of hosts in a subnet */
	size_t memsize;		/* members size */
	uint8_t netmask;	/* subnet netmask */
};

static inline uint32_t
ip_to_id(const struct bitmap_ip *map, uint32_t ip)
{
	return ((ip & HOSTMASK(map->netmask)) - map->first_ip)/map->hosts;
}

static inline int
bitmap_ip_test(const struct bitmap_ip *map, uint32_t id)
{
	return !!test_bit(id, map->members);
}

static inline int
bitmap_ip_add(struct bitmap_ip *map, uint32_t id)
{
	if (test_and_set_bit(id, map->members))
		return -IPSET_ERR_EXIST;

	return 0;
}

static inline int
bitmap_ip_del(struct bitmap_ip *map, uint32_t id)
{
	if (!test_and_clear_bit(id, map->members))
		return -IPSET_ERR_EXIST;

	return 0;
}

static int
bitmap_ip_kadt(struct ip_set *set, const struct sk_buff *skb,
	       enum ipset_adt adt, uint8_t pf, const uint8_t *flags)
{
	struct bitmap_ip *map = set->data;
	uint32_t ip = ntohl(ip4addr(skb, flags));
	
	if (pf != AF_INET)
		return -EINVAL;

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

static const struct nla_policy
bitmap_ip_adt_policy[IPSET_ATTR_ADT_MAX+1] __read_mostly = {
	[IPSET_ATTR_IP]		= { .type = NLA_U32 },
	[IPSET_ATTR_IP_TO]	= { .type = NLA_U32 },
	[IPSET_ATTR_CIDR]	= { .type = NLA_U8 },
	[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
};

static int
bitmap_ip_uadt(struct ip_set *set, struct nlattr *head, int len,
	       enum ipset_adt adt, uint32_t *lineno, uint32_t flags)
{
	struct bitmap_ip *map = set->data;
	struct nlattr *tb[IPSET_ATTR_ADT_MAX];
	bool eexist = flags & IPSET_FLAG_EXIST;
	uint32_t ip, ip_to, id;
	int ret = 0;

	if (nla_parse(tb, IPSET_ATTR_ADT_MAX, head, len,
		      bitmap_ip_adt_policy))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_IP])
		ip = ip_set_get_h32(tb[IPSET_ATTR_IP]);
	else
		return -IPSET_ERR_PROTOCOL;

	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	if (tb[IPSET_ATTR_TIMEOUT])
		return -IPSET_ERR_TIMEOUT;

	if (adt == IPSET_TEST)
		return bitmap_ip_test(map, ip_to_id(map, ip));

	if (tb[IPSET_ATTR_IP_TO]) {
		ip_to = ip_set_get_h32(tb[IPSET_ATTR_IP_TO]);
		if (ip > ip_to) {
			swap(ip, ip_to);
			if (ip < map->first_ip)
				return -IPSET_ERR_BITMAP_RANGE;
		}
	} else if (tb[IPSET_ATTR_CIDR]) {
		uint8_t cidr = nla_get_u8(tb[IPSET_ATTR_CIDR]);
		
		if (cidr > 32)
			return -IPSET_ERR_INVALID_CIDR;
		ip_to = ip | ~HOSTMASK(cidr);
	} else
		ip_to = ip;

	if (ip_to > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;

	for (; !before(ip_to, ip); ip += map->hosts) {
		id = ip_to_id(map, ip);
		ret = adt == IPSET_ADD ? bitmap_ip_add(map, id)
				       : bitmap_ip_del(map, id);

		if (ret && !(ret == -IPSET_ERR_EXIST && eexist)) {
			if (tb[IPSET_ATTR_LINENO])
				*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);
			return ret;
		}
	};
	return ret;
}

static void
bitmap_ip_destroy(struct ip_set *set)
{
	struct bitmap_ip *map = set->data;
	
	ip_set_free(map->members, set->flags);
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
	uint32_t id, elements;

	for (id = 0, elements = 0; id < map->elements; id++)
		if (bitmap_ip_test(map, id)) 
			elements++;

	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	NLA_PUT_NET32(skb, IPSET_ATTR_IP, htonl(map->first_ip));
	NLA_PUT_NET32(skb, IPSET_ATTR_IP_TO, htonl(map->last_ip));
	if (map->netmask != 32)
		NLA_PUT_U8(skb, IPSET_ATTR_NETMASK, map->netmask);
	NLA_PUT_NET32(skb, IPSET_ATTR_ELEMENTS, htonl(elements));
	NLA_PUT_NET32(skb, IPSET_ATTR_REFERENCES,
		      htonl(atomic_read(&set->ref) - 1));
	NLA_PUT_NET32(skb, IPSET_ATTR_MEMSIZE, htonl(map->memsize));
	ipset_nest_end(skb, nested);
	
	return 0;
nla_put_failure:
	return -EFAULT;
}

static int
bitmap_ip_list(struct ip_set *set,
	       struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct bitmap_ip *map = set->data;
	struct nlattr *atd, *nested;
	uint32_t id, first = cb->args[2];

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
		NLA_PUT_NET32(skb, IPSET_ATTR_IP,
			      htonl(map->first_ip + id * map->hosts));
		if (map->netmask != 32)
			NLA_PUT_U8(skb, IPSET_ATTR_CIDR, map->netmask);
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

static const struct ip_set_type_variant bitmap_ip __read_mostly = {
	.kadt	= bitmap_ip_kadt,
	.uadt	= bitmap_ip_uadt,
	.destroy = bitmap_ip_destroy,
	.flush	= bitmap_ip_flush,
	.head	= bitmap_ip_head,
	.list	= bitmap_ip_list,
};

/* Timeout variant */

struct bitmap_ip_timeout {
	void *members;		/* the set members */
	uint32_t first_ip;	/* host byte order, included in range */
	uint32_t last_ip;	/* host byte order, included in range */
	uint32_t elements;	/* number of max elements in the set */
	uint32_t hosts;		/* number of hosts in a subnet */
	size_t memsize;		/* members size */
	uint8_t netmask;	/* subnet netmask */

	uint32_t timeout;	/* timeout parameter */
	struct timer_list gc;	/* garbage collection */
};

static inline bool
bitmap_ip_timeout_test(const struct bitmap_ip_timeout *map, uint32_t id)
{
	unsigned long *table = map->members;

	return ip_set_timeout_test(table[id]);
}

static int
bitmap_ip_timeout_add(struct bitmap_ip_timeout *map,
		      uint32_t id, uint32_t timeout)
{
	unsigned long *table = map->members;

	if (bitmap_ip_timeout_test(map, id))
		return -IPSET_ERR_EXIST;

	table[id] = ip_set_timeout_set(timeout);

	return 0;
}

static int
bitmap_ip_timeout_del(struct bitmap_ip_timeout *map, uint32_t id)
{
	unsigned long *table = map->members;
	int ret = -IPSET_ERR_EXIST;

	if (bitmap_ip_timeout_test(map, id))
		ret = 0;
	
	table[id] = IPSET_ELEM_UNSET;
	return ret;
}

static int
bitmap_ip_timeout_kadt(struct ip_set *set, const struct sk_buff *skb,
		       enum ipset_adt adt, uint8_t pf, const uint8_t *flags)
{
	struct bitmap_ip_timeout *map = set->data;
	uint32_t ip = ntohl(ip4addr(skb, flags));

	if (pf != AF_INET)
		return -EINVAL;

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
		       enum ipset_adt adt, uint32_t *lineno, uint32_t flags)
{
	struct bitmap_ip_timeout *map = set->data;
	struct nlattr *tb[IPSET_ATTR_ADT_MAX];
	bool eexist = flags & IPSET_FLAG_EXIST;
	uint32_t ip, ip_to, id, timeout = map->timeout;
	int ret = 0;

	if (nla_parse(tb, IPSET_ATTR_ADT_MAX, head, len,
		      bitmap_ip_adt_policy))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_IP])
		ip = ip_set_get_h32(tb[IPSET_ATTR_IP]);
	else
		return -IPSET_ERR_PROTOCOL;

	if (ip < map->first_ip || ip > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;
	
	if (adt == IPSET_TEST)
		return bitmap_ip_timeout_test(map,
				ip_to_id((const struct bitmap_ip *)map, ip));

	if (tb[IPSET_ATTR_IP_TO]) {
		ip_to = ip_set_get_h32(tb[IPSET_ATTR_IP_TO]);
		if (ip > ip_to) {
			swap(ip, ip_to);
			if (ip < map->first_ip)
				return -IPSET_ERR_BITMAP_RANGE;
		}
	} else if (tb[IPSET_ATTR_CIDR]) {
		uint8_t cidr = nla_get_u8(tb[IPSET_ATTR_CIDR]);
		
		if (cidr > 32)
			return -IPSET_ERR_INVALID_CIDR;
		ip_to = ip | ~HOSTMASK(cidr);
	} else
		ip_to = ip;

	if (ip_to > map->last_ip)
		return -IPSET_ERR_BITMAP_RANGE;
	
	if (tb[IPSET_ATTR_TIMEOUT]) {
		timeout = ip_set_get_h32(tb[IPSET_ATTR_TIMEOUT]);
	}

	for (; !before(ip_to, ip); ip += map->hosts) {
		id = ip_to_id((const struct bitmap_ip *)map, ip);
		ret = adt == IPSET_ADD
			? bitmap_ip_timeout_add(map, id, timeout)
			: bitmap_ip_timeout_del(map, id);

		if (ret && !(ret == -IPSET_ERR_EXIST && eexist)) {
			if (tb[IPSET_ATTR_LINENO])
				*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);
			return ret;
		}
	}
	return ret;
}

static void
bitmap_ip_timeout_destroy(struct ip_set *set)
{
	struct bitmap_ip_timeout *map = set->data;

	/* gc might be running: del_timer_sync can't be used */
	while (!del_timer(&map->gc))
		msleep(IPSET_DESTROY_TIMER_SLEEP);

	ip_set_free(map->members, set->flags);
	kfree(map);
	
	set->data = NULL;
}

static void
bitmap_ip_timeout_flush(struct ip_set *set)
{
	struct bitmap_ip_timeout *map = set->data;
	
	memset(map->members, 0, map->memsize);
}

static int
bitmap_ip_timeout_head(struct ip_set *set, struct sk_buff *skb)
{
	const struct bitmap_ip_timeout *map = set->data;
	struct nlattr *nested;
	uint32_t id, elements;
	
	for (id = 0, elements = 0; id < map->elements; id++)
		if (bitmap_ip_timeout_test(map, id))
			elements++;
	
	nested = ipset_nest_start(skb, IPSET_ATTR_DATA);
	if (!nested)
		goto nla_put_failure;
	NLA_PUT_NET32(skb, IPSET_ATTR_IP, htonl(map->first_ip));
	NLA_PUT_NET32(skb, IPSET_ATTR_IP_TO, htonl(map->last_ip));
	if (map->netmask != 32)
		NLA_PUT_U8(skb, IPSET_ATTR_NETMASK, map->netmask);
	NLA_PUT_NET32(skb, IPSET_ATTR_TIMEOUT , htonl(map->timeout));
	NLA_PUT_NET32(skb, IPSET_ATTR_ELEMENTS, htonl(elements));
	NLA_PUT_NET32(skb, IPSET_ATTR_REFERENCES,
		      htonl(atomic_read(&set->ref) - 1));
	NLA_PUT_NET32(skb, IPSET_ATTR_MEMSIZE, htonl(map->memsize));
	ipset_nest_end(skb, nested);
	
	return 0;
nla_put_failure:
	return -EFAULT;
}

static int
bitmap_ip_timeout_list(struct ip_set *set,
		       struct sk_buff *skb, struct netlink_callback *cb)
{
	const struct bitmap_ip_timeout *map = set->data;
	struct nlattr *adt, *nested;
	uint32_t id, first = cb->args[2];
	unsigned long *table = map->members;
	
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
		NLA_PUT_NET32(skb, IPSET_ATTR_IP,
			      htonl(map->first_ip + id * map->hosts));
		if (map->netmask != 32)
			NLA_PUT_U8(skb, IPSET_ATTR_CIDR, map->netmask);
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

static const struct ip_set_type_variant bitmap_ip_timeout __read_mostly = {
	.kadt	= bitmap_ip_timeout_kadt,
	.uadt	= bitmap_ip_timeout_uadt,
	.destroy = bitmap_ip_timeout_destroy,
	.flush	= bitmap_ip_timeout_flush,
	.head	= bitmap_ip_timeout_head,
	.list	= bitmap_ip_timeout_list,
};

static void
bitmap_ip_timeout_gc(unsigned long ul_set)
{
	struct ip_set *set = (struct ip_set *) ul_set;
	struct bitmap_ip_timeout *map = set->data;
	unsigned long *table = map->members;
	uint32_t id;

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

static inline void
bitmap_ip_gc_init(struct ip_set *set)
{
	struct bitmap_ip_timeout *map = set->data;

	init_timer(&map->gc);
	map->gc.data = (unsigned long) set;
	map->gc.function = bitmap_ip_timeout_gc;
	map->gc.expires = jiffies + IPSET_GC_PERIOD(map->timeout) * HZ;
	add_timer(&map->gc);
}

/* Create bitmap:ip type of sets */

static const struct nla_policy
bitmap_ip_create_policy[IPSET_ATTR_CREATE_MAX+1] __read_mostly = {
	[IPSET_ATTR_IP]		= { .type = NLA_U32 },
	[IPSET_ATTR_IP_TO]	= { .type = NLA_U32 },
	[IPSET_ATTR_CIDR]	= { .type = NLA_U8 },
	[IPSET_ATTR_NETMASK]	= { .type = NLA_U8  },
	[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
};

static bool
init_map_ip(struct ip_set *set, struct bitmap_ip *map,
	    uint32_t first_ip, uint32_t last_ip,
	    uint32_t elements, uint32_t hosts, uint8_t netmask)
{
	map->members = ip_set_alloc(map->memsize, GFP_KERNEL, &set->flags);
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
		 uint32_t flags)
{
	struct nlattr *tb[IPSET_ATTR_CREATE_MAX];
	uint32_t first_ip, last_ip, hosts, elements;
	uint8_t netmask = 32;

	if (nla_parse(tb, IPSET_ATTR_CREATE_MAX, head, len,
		      bitmap_ip_create_policy))
		return -IPSET_ERR_PROTOCOL;
	
	if (tb[IPSET_ATTR_IP])
		first_ip = ip_set_get_h32(tb[IPSET_ATTR_IP]);
	else
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_IP_TO]) {
		last_ip = ip_set_get_h32(tb[IPSET_ATTR_IP_TO]);
		if (first_ip > last_ip) {
			uint32_t tmp = first_ip;
			
			first_ip = last_ip;
			last_ip = tmp;
		}
	} else if (tb[IPSET_ATTR_CIDR]) {
		uint8_t cidr = nla_get_u8(tb[IPSET_ATTR_CIDR]);
		
		if (cidr >= 32)
			return -IPSET_ERR_INVALID_CIDR;
		last_ip = first_ip | ~HOSTMASK(cidr);
	} else
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_NETMASK]) {
		netmask = nla_get_u8(tb[IPSET_ATTR_NETMASK]);
		
		if (netmask > 32)
			return -IPSET_ERR_INVALID_NETMASK;

		first_ip &= HOSTMASK(netmask);
		last_ip |= ~HOSTMASK(netmask);
	}
	
	if (netmask == 32) {
		hosts = 1;
		elements = last_ip - first_ip + 1;
	} else {
		uint8_t mask_bits;
		uint32_t mask;

		mask = range_to_mask(first_ip, last_ip, &mask_bits);

		if ((!mask && (first_ip || last_ip != 0xFFFFFFFF))
		    || netmask <= mask_bits)
			return -IPSET_ERR_BITMAP_RANGE;

		D("mask_bits %u, netmask %u", mask_bits, netmask);
		hosts = 2 << (32 - netmask - 1);
		elements = 2 << (netmask - mask_bits - 1);
	}
	if (elements > IPSET_BITMAP_MAX_RANGE + 1) {
		return -IPSET_ERR_BITMAP_RANGE_SIZE;
	}
	D("hosts %u, elements %u", hosts, elements);

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

		map->timeout = ip_set_get_h32(tb[IPSET_ATTR_TIMEOUT]);
		set->flags |= IP_SET_FLAG_TIMEOUT;
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

static struct ip_set_type bitmap_ip_type = {
	.name		= "bitmap:ip",
	.protocol	= IPSET_PROTOCOL,
	.features	= IPSET_TYPE_IP,
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
