/* Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module implementing an IP set type: the hash:ip type */

#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <asm/uaccess.h>
#include <asm/bitops.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/pfxlen.h>

#include <linux/netfilter.h>
#include <linux/netfilter/ip_set.h>
#include <linux/netfilter/ip_set_timeout.h>
#include <linux/netfilter/ip_set_hash.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
MODULE_DESCRIPTION("hash:ip type of IP sets");
MODULE_ALIAS("ip_set_hash:ip");

/* Member elements without timeout */
struct ip4_elem {
	uint32_t ip;
};

struct ip6_elem {
	union nf_inet_addr ip;
};

/* Member elements with timeout support */
struct ip4_elem_timeout {
	uint32_t ip;
	unsigned long timeout;
};

struct ip6_elem_timeout {
	union nf_inet_addr ip;
	unsigned long timeout;
};

/* The hash:ip type structure */
struct hash_ip {
	void *members;			/* the set members */
	uint32_t hashsize;		/* hash size */
	uint32_t maxelem;		/* max number of elements/hashsize */
	uint8_t probes;			/* max number of probes  */
	uint8_t resize;			/* resize factor in percent */
	uint8_t netmask;		/* netmask */
	uint32_t timeout;		/* timeout value */
	uint32_t elements;		/* number of elements */
	struct timer_list gc;		/* garbage collector */
	size_t elem_size;		/* size of element */
	initval_t initval[0];		/* initvals for jhash_1word */
};

static inline void *
hash_ip_elem(const struct hash_ip *map, uint32_t id)
{
	return (void *)((char *)map->members + id * map->elem_size);
}

static inline unsigned long
get_ip4_elem_timeout(const struct ip4_elem *elem)
{
	return ((const struct ip4_elem_timeout *)elem)->timeout;
}

static inline unsigned long
get_ip6_elem_timeout(const struct ip6_elem *elem)
{
	return ((const struct ip6_elem_timeout *)elem)->timeout;
}

static inline uint32_t
ip4_hash(struct ip4_elem *elem, initval_t initval, uint32_t hashsize)
{
	return jhash_1word(elem->ip, initval) % hashsize;
}

static inline uint32_t
ip6_hash(struct ip6_elem *elem, initval_t initval, uint32_t hashsize)
{
	return jhash2((u32 *)&elem->ip, 4, initval) % hashsize;
}

static inline bool
ip4_cmp(struct ip4_elem *ip1, struct ip4_elem *ip2)
{
	return ip1->ip == ip2->ip;
}

static inline bool
ip6_cmp(struct ip6_elem *ip1, struct ip6_elem *ip2)
{
	return ipv6_addr_cmp(&ip1->ip.in6, &ip2->ip.in6);
}

static inline bool
ip4_null(struct ip4_elem *elem)
{
	return elem->ip == 0;
}

static inline bool
ip6_null(struct ip6_elem *elem)
{
	return ipv6_addr_any(&elem->ip.in6);
}

static inline void
ip4_cpy(struct ip4_elem *dst, const struct ip4_elem *src)
{
	dst->ip = src->ip;
}

static inline void
ip6_cpy(struct ip6_elem *dst, const struct ip6_elem *src)
{
	ipv6_addr_copy(&dst->ip.in6, &src->ip.in6);
}

/* Zero valued IP addresses (network order) cannot be stored */
static inline void
ip4_zero_out(struct ip4_elem *elem)
{
	elem->ip = 0;
}

static inline void
ip6_zero_out(struct ip6_elem *elem)
{
	ipv6_addr_set(&elem->ip.in6, 0, 0, 0, 0);
}

static inline void
ip6_netmask(union nf_inet_addr *ip, uint8_t prefix)
{
	ip->ip6[0] &= NETMASK6(prefix)[0];
	ip->ip6[1] &= NETMASK6(prefix)[1];
	ip->ip6[2] &= NETMASK6(prefix)[2];
	ip->ip6[3] &= NETMASK6(prefix)[3];
}

/* The type variant functions: generic ones */

static void
hash_ip_destroy(struct ip_set *set)
{
	struct hash_ip *map = set->data;

	/* gc might be running: del_timer_sync can't be used */
	if (set->flags & IP_SET_FLAG_TIMEOUT)
		while (!del_timer(&map->gc))
			msleep(IPSET_DESTROY_TIMER_SLEEP);

	ip_set_free(map->members, set->flags);
	kfree(map);
	
	set->data = NULL;
}

#define hash_ip4_destroy	hash_ip_destroy
#define hash_ip6_destroy	hash_ip_destroy

static void
hash_ip_flush(struct ip_set *set)
{
	struct hash_ip *map = set->data;
	
	memset(map->members, 0, map->hashsize * map->elem_size);
	map->elements = 0;
}

#define hash_ip4_flush		hash_ip_flush
#define hash_ip6_flush		hash_ip_flush

/* IPv4 variant */

#define PF	4
#include "ip_set_hash_ip_src.c"
#undef PF

static int
hash_ip4_kadt(struct ip_set *set, const struct sk_buff *skb,
	      enum ipset_adt adt, uint8_t pf, const uint8_t *flags)
{
	struct hash_ip *map = set->data;
	bool with_timeout = set->flags & IP_SET_FLAG_TIMEOUT;
	uint32_t ip;
	
	if (pf != AF_INET)
		return -EINVAL;

	ip4addrptr(skb, flags, &ip);
	ip &= NETMASK(map->netmask);
	if (ip == 0)
		return -EINVAL;

	switch (adt) {
	case IPSET_TEST:
		return hash_ip4_test(map, with_timeout,
				     (struct ip4_elem *)&ip);
	case IPSET_ADD:
		return hash_ip4_add(map, with_timeout,
				    (struct ip4_elem *)&ip, map->timeout);
	case IPSET_DEL:
		return hash_ip4_del(map, with_timeout, (struct ip4_elem *)&ip);
	default:
		BUG();
	}
	return 0;
}

static const struct nla_policy
hash_ip4_adt_policy[IPSET_ATTR_ADT_MAX + 1] __read_mostly = {
	[IPSET_ATTR_IP]		= { .type = NLA_U32 },
	[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
};

static int
hash_ip4_uadt(struct ip_set *set, struct nlattr *head, int len,
	      enum ipset_adt adt, uint32_t *lineno, uint32_t flags)
{
	struct hash_ip *map = set->data;
	struct nlattr *tb[IPSET_ATTR_ADT_MAX];
	bool with_timeout = set->flags & IP_SET_FLAG_TIMEOUT;
	uint32_t ip, timeout = map->timeout;

	if (nla_parse(tb, IPSET_ATTR_ADT_MAX, head, len,
		      hash_ip4_adt_policy))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_IP])
		ip = ip_set_get_n32(tb[IPSET_ATTR_IP]);
	else
		return -IPSET_ERR_PROTOCOL;

	ip &= NETMASK(map->netmask);
	if (ip == 0)
		return -IPSET_ERR_HASH_ELEM;

	if (tb[IPSET_ATTR_TIMEOUT]) {
		if (!with_timeout)
			return -IPSET_ERR_TIMEOUT;
		timeout = ip_set_get_h32(tb[IPSET_ATTR_TIMEOUT]);
	}

	switch (adt) {
	case IPSET_TEST:
		return hash_ip4_test(map, with_timeout,
				     (struct ip4_elem *)&ip);
	case IPSET_ADD:
		return hash_ip4_add(map, with_timeout,
				    (struct ip4_elem *)&ip, timeout);
	case IPSET_DEL:
		return hash_ip4_del(map, with_timeout,
				    (struct ip4_elem *)&ip);
	default:
		BUG();
	}

	return 0;
}

/* IPv6 variants */

#define PF	6
#include "ip_set_hash_ip_src.c"
#undef PF

static int
hash_ip6_kadt(struct ip_set *set, const struct sk_buff *skb,
	      enum ipset_adt adt, uint8_t pf, const uint8_t *flags)
{
	struct hash_ip *map = set->data;
	bool with_timeout = set->flags & IP_SET_FLAG_TIMEOUT;
	union nf_inet_addr ip;

	if (pf != AF_INET6)
		return -EINVAL;

	ip6addrptr(skb, flags, &ip.in6);
	ip6_netmask(&ip, map->netmask);
	if (ipv6_addr_any(&ip.in6))
		return -EINVAL;

	switch (adt) {
	case IPSET_TEST:
		return hash_ip6_test(map, with_timeout,
				     (struct ip6_elem *)&ip);
	case IPSET_ADD:
		return hash_ip6_add(map, with_timeout,
				    (struct ip6_elem *)&ip, map->timeout);
	case IPSET_DEL:
		return hash_ip6_del(map, with_timeout,
				    (struct ip6_elem *)&ip);
	default:
		BUG();
	}
	return 0;
}

static const struct nla_policy
hash_ip6_adt_policy[IPSET_ATTR_ADT_MAX + 1] __read_mostly = {
	[IPSET_ATTR_IP]		= { .type = NLA_BINARY,
				    .len = sizeof(struct in6_addr) },
	[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
};

static int
hash_ip6_uadt(struct ip_set *set, struct nlattr *head, int len,
	      enum ipset_adt adt, uint32_t *lineno, uint32_t flags)
{
	struct hash_ip *map = set->data;
	struct nlattr *tb[IPSET_ATTR_ADT_MAX];
	union nf_inet_addr *ip;
	bool with_timeout = set->flags & IP_SET_FLAG_TIMEOUT;
	uint32_t timeout = map->timeout;

	if (nla_parse(tb, IPSET_ATTR_ADT_MAX, head, len,
		      hash_ip6_adt_policy))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_IP])
		ip = nla_data(tb[IPSET_ATTR_IP]);
	else
		return -IPSET_ERR_PROTOCOL;

	ip6_netmask(ip, map->netmask);
	if (ipv6_addr_any(&ip->in6))
		return -IPSET_ERR_HASH_ELEM;

	if (tb[IPSET_ATTR_TIMEOUT]) {
		if (!with_timeout)
			return -IPSET_ERR_TIMEOUT;
		timeout = ip_set_get_h32(tb[IPSET_ATTR_TIMEOUT]);
	}

	switch (adt) {
	case IPSET_TEST:
		return hash_ip6_test(map, with_timeout,
				     (struct ip6_elem *)ip);
	case IPSET_ADD:
		return hash_ip6_add(map, with_timeout,
				    (struct ip6_elem *)ip, timeout);
	case IPSET_DEL:
		return hash_ip6_del(map, with_timeout,
				    (struct ip6_elem *)ip);
	default:
		BUG();
	}
	
	return 0;
}

/* Create hash:ip type of sets */

static const struct nla_policy
hash_ip_create_policy[IPSET_ATTR_CREATE_MAX+1] __read_mostly = {
	[IPSET_ATTR_HASHSIZE]	= { .type = NLA_U32 },
	[IPSET_ATTR_MAXELEM]	= { .type = NLA_U32 },
	[IPSET_ATTR_PROBES]	= { .type = NLA_U8 },
	[IPSET_ATTR_RESIZE]	= { .type = NLA_U8  },
	[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
};

static bool
init_map_ip(struct ip_set *set, struct hash_ip *map, uint32_t maxelem,
	    uint32_t probes, uint32_t resize, uint8_t netmask, uint8_t family)
{
	map->members = ip_set_alloc(map->hashsize * map->elem_size,
				    GFP_KERNEL, &set->flags);
	if (!map->members)
		return false;

	map->maxelem = maxelem;
	map->probes = probes;
	map->resize = resize;
	map->netmask = netmask;

	set->data = map;
	set->family = family;
	
	return true;
}

static int
hash_ip_create(struct ip_set *set, struct nlattr *head, int len,
		 uint32_t flags)
{
	struct nlattr *tb[IPSET_ATTR_CREATE_MAX];
	uint32_t hashsize, maxelem;
	uint8_t probes, resize, netmask, family, i;
	struct hash_ip *map;

	if (nla_parse(tb, IPSET_ATTR_CREATE_MAX, head, len,
		      hash_ip_create_policy))
		return -IPSET_ERR_PROTOCOL;

	hashsize = IPSET_DEFAULT_HASHSIZE;
	maxelem = IPSET_DEFAULT_MAXELEM;
	probes = IPSET_DEFAULT_PROBES;
	resize = IPSET_DEFAULT_RESIZE;
	family = AF_INET;

	if (tb[IPSET_ATTR_HASHSIZE])
		hashsize = ip_set_get_h32(tb[IPSET_ATTR_HASHSIZE]);

	if (tb[IPSET_ATTR_MAXELEM])
		maxelem = ip_set_get_h32(tb[IPSET_ATTR_MAXELEM]);

	if (tb[IPSET_ATTR_PROBES])
		probes = nla_get_u8(tb[IPSET_ATTR_PROBES]);

	if (tb[IPSET_ATTR_RESIZE])
		resize = nla_get_u8(tb[IPSET_ATTR_RESIZE]);

	if (tb[IPSET_ATTR_FAMILY])
		family = nla_get_u8(tb[IPSET_ATTR_FAMILY]);
	if (!(family == AF_INET || family == AF_INET6))
		return -IPSET_ERR_INVALID_FAMILY;
	netmask = family == AF_INET ? 32 : 128;

	if (tb[IPSET_ATTR_NETMASK]) {
		netmask = nla_get_u8(tb[IPSET_ATTR_NETMASK]);
		
		if ((family == AF_INET && netmask > 32)
		    || (family == AF_INET6 && netmask > 128))
			return -IPSET_ERR_INVALID_NETMASK;
	}

	map = kzalloc(sizeof(*map) + probes * sizeof(initval_t), GFP_KERNEL);
	if (!map)
		return -ENOMEM;
		
	map->hashsize = hashsize;
	if (tb[IPSET_ATTR_TIMEOUT]) {
		map->elem_size = family == AF_INET
					? sizeof(struct ip4_elem_timeout)
					: sizeof(struct ip6_elem_timeout);

		if (!init_map_ip(set, map, maxelem, probes, resize, netmask, 
				 family)) {
			kfree(map);
			return -ENOMEM;
		}

		map->timeout = ip_set_get_h32(tb[IPSET_ATTR_TIMEOUT]);
		set->flags |= IP_SET_FLAG_TIMEOUT;
		
		if (family == AF_INET)
			hash_ip4_gc_init(set);
		else
			hash_ip6_gc_init(set);
	} else {
		map->elem_size = family == AF_INET
					? sizeof(struct ip4_elem)
					: sizeof(struct ip6_elem);

		if (!init_map_ip(set, map, maxelem, probes, resize, netmask,
				 family)) {
			kfree(map);
			return -ENOMEM;
		}
	}
	for (i = 0; i < map->probes; i++)
		get_random_bytes(((initval_t *) map->initval)+i,
				 sizeof(initval_t));
	
	set->variant = family == AF_INET ? &hash_ip4 : &hash_ip6;
	D("create %s hashsize %u maxelem %u probes %u resize %u",
	   set->name, map->hashsize, map->maxelem, map->probes, map->resize);
	   
	return 0;
}

static struct ip_set_type hash_ip_type = {
	.name		= "hash:ip",
	.protocol	= IPSET_PROTOCOL,
	.features	= IPSET_TYPE_IP,
	.family		= AF_UNSPEC,
	.revision	= 0,
	.create		= hash_ip_create,
	.me		= THIS_MODULE,
};

static int __init
hash_ip_init(void)
{
	return ip_set_type_register(&hash_ip_type);
}

static void __exit
hash_ip_fini(void)
{
	ip_set_type_unregister(&hash_ip_type);
}

module_init(hash_ip_init);
module_exit(hash_ip_fini);
