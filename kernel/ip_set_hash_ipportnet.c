/* Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module implementing an IP set type: the hash:ip,port,net type */

#include <linux/netfilter/ipset/ip_set_kernel.h>
#include <linux/netfilter/ipset/jhash.h>
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

#include <linux/netfilter.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_timeout.h>
#include <linux/netfilter/ipset/ip_set_getport.h>
#include <linux/netfilter/ipset/ip_set_hash.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>");
MODULE_DESCRIPTION("hash:ip,port,net type of IP sets");
MODULE_ALIAS("ip_set_hash:ip,port,net");

/* Type specific function prefix */
#define TYPE		hash_ipportnet

static bool
hash_ipportnet_same_set(const struct ip_set *a, const struct ip_set *b);

#define hash_ipportnet4_same_set	hash_ipportnet_same_set
#define hash_ipportnet6_same_set	hash_ipportnet_same_set

/* The type variant functions: IPv4 */

/* Member elements without timeout */
struct hash_ipportnet4_elem {
	u32 ip;
	u32 ip2;
	u16 port;
	u8 cidr;
	u8 proto;
};

/* Member elements with timeout support */
struct hash_ipportnet4_telem {
	u32 ip;
	u32 ip2;
	u16 port;
	u8 cidr;
	u8 proto;
	unsigned long timeout;
};

static inline bool
hash_ipportnet4_data_equal(const struct hash_ipportnet4_elem *ip1,
			   const struct hash_ipportnet4_elem *ip2)
{
	return ip1->ip == ip2->ip
	       && ip1->ip2 == ip2->ip2
	       && ip1->cidr == ip2->cidr
	       && ip1->port == ip2->port
	       && ip1->proto == ip2->proto;
}

static inline bool
hash_ipportnet4_data_isnull(const struct hash_ipportnet4_elem *elem)
{
	return elem->proto == 0;
}

static inline void
hash_ipportnet4_data_copy(struct hash_ipportnet4_elem *dst,
			  const struct hash_ipportnet4_elem *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static inline void
hash_ipportnet4_data_swap(struct hash_ipportnet4_elem *dst,
			  struct hash_ipportnet4_elem *src)
{
	struct hash_ipportnet4_elem tmp;

	memcpy(&tmp, dst, sizeof(tmp));
	memcpy(dst, src, sizeof(tmp));
	memcpy(src, &tmp, sizeof(tmp));
}

static inline void
hash_ipportnet4_data_netmask(struct hash_ipportnet4_elem *elem, u8 cidr)
{
	elem->ip2 &= NETMASK(cidr);
	elem->cidr = cidr;
}

static inline void
hash_ipportnet4_data_zero_out(struct hash_ipportnet4_elem *elem)
{
	elem->proto = 0;
}

static inline bool
hash_ipportnet4_data_list(struct sk_buff *skb,
			  const struct hash_ipportnet4_elem *data)
{
	NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP, data->ip);
	NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP2, data->ip2);
	NLA_PUT_NET16(skb, IPSET_ATTR_PORT, data->port);
	NLA_PUT_U8(skb, IPSET_ATTR_CIDR2, data->cidr);
	NLA_PUT_U8(skb, IPSET_ATTR_PROTO, data->proto);
	return 0;

nla_put_failure:
	return 1;
}

static inline bool
hash_ipportnet4_data_tlist(struct sk_buff *skb,
			   const struct hash_ipportnet4_elem *data)
{
	const struct hash_ipportnet4_telem *tdata =
		(const struct hash_ipportnet4_telem *)data;

	NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP, tdata->ip);
	NLA_PUT_IPADDR4(skb, IPSET_ATTR_IP2, tdata->ip2);
	NLA_PUT_NET16(skb, IPSET_ATTR_PORT, tdata->port);
	NLA_PUT_U8(skb, IPSET_ATTR_CIDR2, data->cidr);
	NLA_PUT_U8(skb, IPSET_ATTR_PROTO, data->proto);
	NLA_PUT_NET32(skb, IPSET_ATTR_TIMEOUT,
		      htonl(ip_set_timeout_get(tdata->timeout)));

	return 0;

nla_put_failure:
	return 1;
}

#define IP_SET_HASH_WITH_PROTO
#define IP_SET_HASH_WITH_NETS

#define PF		4
#define HOST_MASK	32
#include <linux/netfilter/ipset/ip_set_chash.h>

static int
hash_ipportnet4_kadt(struct ip_set *set, const struct sk_buff *skb,
		     enum ipset_adt adt, u8 pf, u8 dim, u8 flags)
{
	struct chash *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_ipportnet4_elem data =
		{ .cidr = h->nets[0].cidr || HOST_MASK };

	if (data.cidr == 0)
		return -EINVAL;
	if (adt == IPSET_TEST)
		data.cidr = HOST_MASK;

	if (!get_ip4_port(skb, flags & IPSET_DIM_TWO_SRC,
			  &data.port, &data.proto))
		return -EINVAL;

	ip4addrptr(skb, flags & IPSET_DIM_ONE_SRC, &data.ip);
	ip4addrptr(skb, flags & IPSET_DIM_THREE_SRC, &data.ip2);
	data.ip2 &= NETMASK(data.cidr);

	return adtfn(set, &data, GFP_ATOMIC, h->timeout);
}

static const struct nla_policy
hash_ipportnet_adt_policy[IPSET_ATTR_ADT_MAX + 1] __read_mostly = {
	[IPSET_ATTR_IP]		= { .type = NLA_NESTED },
	[IPSET_ATTR_IP2]	= { .type = NLA_NESTED },
	[IPSET_ATTR_PORT]	= { .type = NLA_U16 },
	[IPSET_ATTR_CIDR2]	= { .type = NLA_U8 },
	[IPSET_ATTR_PROTO]	= { .type = NLA_U8 },
	[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
	[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
};

static int
hash_ipportnet4_uadt(struct ip_set *set, struct nlattr *head, int len,
		     enum ipset_adt adt, u32 *lineno, u32 flags)
{
	struct chash *h = set->data;
	struct nlattr *tb[IPSET_ATTR_ADT_MAX+1];
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_ipportnet4_elem data = { .cidr = HOST_MASK };
	u32 timeout = h->timeout;
	int ret;

	if (nla_parse(tb, IPSET_ATTR_ADT_MAX, head, len,
		      hash_ipportnet_adt_policy))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	ret = ip_set_get_ipaddr4(tb, IPSET_ATTR_IP, &data.ip);
	if (ret)
		return ret;

	ret = ip_set_get_ipaddr4(tb, IPSET_ATTR_IP2, &data.ip2);
	if (ret)
		return ret;

	if (tb[IPSET_ATTR_CIDR2])
		data.cidr = nla_get_u8(tb[IPSET_ATTR_CIDR2]);

	if (!data.cidr)
		return -IPSET_ERR_INVALID_CIDR;

	data.ip2 &= NETMASK(data.cidr);

	if (tb[IPSET_ATTR_PORT])
		data.port = ip_set_get_n16(tb[IPSET_ATTR_PORT]);
	else
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_PROTO]) {
		data.proto = nla_get_u8(tb[IPSET_ATTR_PROTO]);
		
		if (data.proto == 0)
			return -IPSET_ERR_INVALID_PROTO;
	} else
		return -IPSET_ERR_MISSING_PROTO;

	switch (data.proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_ICMP:
		break;
	default:
		data.port = 0;
		break;
	}

	if (tb[IPSET_ATTR_TIMEOUT]) {
		if (!with_timeout(h->timeout))
			return -IPSET_ERR_TIMEOUT;
		timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
	}

	ret = adtfn(set, &data, GFP_ATOMIC, timeout);

	return ip_set_eexist(ret, flags) ? 0 : ret;
}

static bool
hash_ipportnet_same_set(const struct ip_set *a, const struct ip_set *b)
{
	struct chash *x = a->data;
	struct chash *y = b->data;
	
	/* Resizing changes htable_bits, so we ignore it */
	return x->maxelem == y->maxelem
	       && x->timeout == y->timeout
	       && x->array_size == y->array_size
	       && x->chain_limit == y->chain_limit;
}

/* The type variant functions: IPv6 */

struct hash_ipportnet6_elem {
	union nf_inet_addr ip;
	union nf_inet_addr ip2;
	u16 port;
	u8 cidr;
	u8 proto;
};

struct hash_ipportnet6_telem {
	union nf_inet_addr ip;
	union nf_inet_addr ip2;
	u16 port;
	u8 cidr;
	u8 proto;
	unsigned long timeout;
};

static inline bool
hash_ipportnet6_data_equal(const struct hash_ipportnet6_elem *ip1,
			   const struct hash_ipportnet6_elem *ip2)
{
	return ipv6_addr_cmp(&ip1->ip.in6, &ip2->ip.in6) == 0
	       && ipv6_addr_cmp(&ip1->ip2.in6, &ip2->ip2.in6) == 0
	       && ip1->cidr == ip2->cidr
	       && ip1->port == ip2->port
	       && ip1->proto == ip2->proto;
}

static inline bool
hash_ipportnet6_data_isnull(const struct hash_ipportnet6_elem *elem)
{
	return elem->proto == 0;
}

static inline void
hash_ipportnet6_data_copy(struct hash_ipportnet6_elem *dst,
			  const struct hash_ipportnet6_elem *src)
{
	memcpy(dst, src, sizeof(*dst));
}

static inline void
hash_ipportnet6_data_swap(struct hash_ipportnet6_elem *dst,
			 struct hash_ipportnet6_elem *src)
{
	struct hash_ipportnet6_elem tmp;
	
	memcpy(&tmp, dst, sizeof(tmp));
	memcpy(dst, src, sizeof(tmp));
	memcpy(src, &tmp, sizeof(tmp));
}

static inline void
hash_ipportnet6_data_zero_out(struct hash_ipportnet6_elem *elem)
{
	elem->proto = 0;
}

static inline void
ip6_netmask(union nf_inet_addr *ip, u8 prefix)
{
	ip->ip6[0] &= NETMASK6(prefix)[0];
	ip->ip6[1] &= NETMASK6(prefix)[1];
	ip->ip6[2] &= NETMASK6(prefix)[2];
	ip->ip6[3] &= NETMASK6(prefix)[3];
}

static inline void
hash_ipportnet6_data_netmask(struct hash_ipportnet6_elem *elem, u8 cidr)
{
	ip6_netmask(&elem->ip2, cidr);
	elem->cidr = cidr;
}

static inline bool
hash_ipportnet6_data_list(struct sk_buff *skb,
			  const struct hash_ipportnet6_elem *data)
{
	NLA_PUT_IPADDR6(skb, IPSET_ATTR_IP, &data->ip);
	NLA_PUT_IPADDR6(skb, IPSET_ATTR_IP2, &data->ip2);
	NLA_PUT_NET16(skb, IPSET_ATTR_PORT, data->port);
	NLA_PUT_U8(skb, IPSET_ATTR_CIDR2, data->cidr);
	NLA_PUT_U8(skb, IPSET_ATTR_PROTO, data->proto);
	return 0;

nla_put_failure:
	return 1;
}

static inline bool
hash_ipportnet6_data_tlist(struct sk_buff *skb,
			   const struct hash_ipportnet6_elem *data)
{
	const struct hash_ipportnet6_telem *e = 
		(const struct hash_ipportnet6_telem *)data;
	
	NLA_PUT_IPADDR6(skb, IPSET_ATTR_IP, &e->ip);
	NLA_PUT_IPADDR6(skb, IPSET_ATTR_IP2, &data->ip2);
	NLA_PUT_NET16(skb, IPSET_ATTR_PORT, data->port);
	NLA_PUT_U8(skb, IPSET_ATTR_CIDR2, data->cidr);
	NLA_PUT_U8(skb, IPSET_ATTR_PROTO, data->proto);
	NLA_PUT_NET32(skb, IPSET_ATTR_TIMEOUT,
		      htonl(ip_set_timeout_get(e->timeout)));
	return 0;

nla_put_failure:
	return 1;
}

#undef PF
#undef HOST_MASK

#define PF		6
#define HOST_MASK	128
#include <linux/netfilter/ipset/ip_set_chash.h>

static int
hash_ipportnet6_kadt(struct ip_set *set, const struct sk_buff *skb,
		     enum ipset_adt adt, u8 pf, u8 dim, u8 flags)
{
	struct chash *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_ipportnet6_elem data =
		{ .cidr = h->nets[0].cidr || HOST_MASK };

	if (data.cidr == 0)
		return -EINVAL;
	if (adt == IPSET_TEST)
		data.cidr = HOST_MASK;

	if (!get_ip6_port(skb, flags & IPSET_DIM_TWO_SRC,
			  &data.port, &data.proto))
		return -EINVAL;

	ip6addrptr(skb, flags & IPSET_DIM_ONE_SRC, &data.ip.in6);
	ip6addrptr(skb, flags & IPSET_DIM_THREE_SRC, &data.ip2.in6);
	ip6_netmask(&data.ip2, data.cidr);

	return adtfn(set, &data, GFP_ATOMIC, h->timeout);
}

static int
hash_ipportnet6_uadt(struct ip_set *set, struct nlattr *head, int len,
		     enum ipset_adt adt, u32 *lineno, u32 flags)
{
	struct chash *h = set->data;
	struct nlattr *tb[IPSET_ATTR_ADT_MAX+1];
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_ipportnet6_elem data = { .cidr = HOST_MASK };
	u32 timeout = h->timeout;
	int ret;

	if (nla_parse(tb, IPSET_ATTR_ADT_MAX, head, len,
		      hash_ipportnet_adt_policy))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	ret = ip_set_get_ipaddr6(tb, IPSET_ATTR_IP, &data.ip);
	if (ret)
		return ret;

	ret = ip_set_get_ipaddr6(tb, IPSET_ATTR_IP2, &data.ip2);
	if (ret)
		return ret;

	if (tb[IPSET_ATTR_CIDR2])
		data.cidr = nla_get_u8(tb[IPSET_ATTR_CIDR2]);

	if (!data.cidr)
		return -IPSET_ERR_INVALID_CIDR;

	ip6_netmask(&data.ip2, data.cidr);

	if (tb[IPSET_ATTR_PORT])
		data.port = ip_set_get_n16(tb[IPSET_ATTR_PORT]);
	else
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_PROTO]) {
		data.proto = nla_get_u8(tb[IPSET_ATTR_PROTO]);

		if (data.proto == 0)
			return -IPSET_ERR_INVALID_PROTO;
	} else
		return -IPSET_ERR_MISSING_PROTO;

	switch (data.proto) {
	case IPPROTO_UDP:
	case IPPROTO_TCP:
	case IPPROTO_ICMPV6:
		break;
	default:
		data.port = 0;
		break;
	}

	if (tb[IPSET_ATTR_TIMEOUT]) {
		if (!with_timeout(h->timeout))
			return -IPSET_ERR_TIMEOUT;
		timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
	}

	ret = adtfn(set, &data, GFP_ATOMIC, timeout);

	return ip_set_eexist(ret, flags) ? 0 : ret;
}

/* Create hash:ip type of sets */

static const struct nla_policy
hash_ipportnet_create_policy[IPSET_ATTR_CREATE_MAX+1] __read_mostly = {
	[IPSET_ATTR_HASHSIZE]	= { .type = NLA_U32 },
	[IPSET_ATTR_MAXELEM]	= { .type = NLA_U32 },
	[IPSET_ATTR_PROBES]	= { .type = NLA_U8 },
	[IPSET_ATTR_RESIZE]	= { .type = NLA_U8  },
	[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
};

static int
hash_ipportnet_create(struct ip_set *set, struct nlattr *head,
		     int len, u32 flags)
{
	struct nlattr *tb[IPSET_ATTR_CREATE_MAX+1];
	struct chash *h;
	u32 hashsize = IPSET_DEFAULT_HASHSIZE, maxelem = IPSET_DEFAULT_MAXELEM;
	u8 hbits;

	if (!(set->family == AF_INET || set->family == AF_INET6))
		return -IPSET_ERR_INVALID_FAMILY;

	if (nla_parse(tb, IPSET_ATTR_CREATE_MAX, head, len,
		      hash_ipportnet_create_policy))
		return -IPSET_ERR_PROTOCOL;

	if (tb[IPSET_ATTR_HASHSIZE]) {
		hashsize = ip_set_get_h32(tb[IPSET_ATTR_HASHSIZE]);
		if (hashsize < IPSET_MIMINAL_HASHSIZE)
			hashsize = IPSET_MIMINAL_HASHSIZE;
	}

	if (tb[IPSET_ATTR_MAXELEM])
		maxelem = ip_set_get_h32(tb[IPSET_ATTR_MAXELEM]);

	h = kzalloc(sizeof(*h)
		    + sizeof(struct chash_nets)
		      * (set->family == AF_INET ? 32 : 128), GFP_KERNEL);	h = kzalloc(sizeof(*h), GFP_KERNEL);
	if (!h)
		return -ENOMEM;

	h->maxelem = maxelem;
	h->array_size = CHASH_DEFAULT_ARRAY_SIZE;
	h->chain_limit = CHASH_DEFAULT_CHAIN_LIMIT;
	get_random_bytes(&h->initval, sizeof(h->initval));
	h->timeout = IPSET_NO_TIMEOUT;

	hbits = htable_bits(hashsize);
	h->table = ip_set_alloc(
			sizeof(struct htable)
			+ jhash_size(hbits) * sizeof(struct slist),
			GFP_KERNEL);
	if (!h->table) {
		kfree(h);
		return -ENOMEM;
	}
	h->table->htable_bits = hbits;

	set->data = h;

	if (tb[IPSET_ATTR_TIMEOUT]) {
		h->timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
		
		set->variant = set->family == AF_INET
			? &hash_ipportnet4_tvariant
			: &hash_ipportnet6_tvariant;

		if (set->family == AF_INET)
			hash_ipportnet4_gc_init(set);
		else
			hash_ipportnet6_gc_init(set);
	} else {
		set->variant = set->family == AF_INET
			? &hash_ipportnet4_variant : &hash_ipportnet6_variant;
	}
	
	pr_debug("create %s hashsize %u (%u) maxelem %u: %p(%p)",
		 set->name, jhash_size(h->table->htable_bits),
		 h->table->htable_bits, h->maxelem, set->data, h->table);
	   
	return 0;
}

static struct ip_set_type hash_ipportnet_type = {
	.name		= "hash:ip,port,net",
	.protocol	= IPSET_PROTOCOL,
	.features	= IPSET_TYPE_IP | IPSET_TYPE_PORT | IPSET_TYPE_IP2,
	.dimension	= IPSET_DIM_THREE,
	.family		= AF_UNSPEC,
	.revision	= 0,
	.create		= hash_ipportnet_create,
	.me		= THIS_MODULE,
};

static int __init
hash_ipportnet_init(void)
{
	return ip_set_type_register(&hash_ipportnet_type);
}

static void __exit
hash_ipportnet_fini(void)
{
	ip_set_type_unregister(&hash_ipportnet_type);
}

module_init(hash_ipportnet_init);
module_exit(hash_ipportnet_fini);
