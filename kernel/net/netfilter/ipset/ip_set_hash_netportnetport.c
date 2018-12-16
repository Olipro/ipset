/* Copyright (C) 2003-2013 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

/* Kernel module implementing an IP set type: the hash:net,port,net,port type */

#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/tcp.h>

#include <linux/netfilter.h>
#include <linux/netfilter/ipset/pfxlen.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_getport.h>
#include <linux/netfilter/ipset/ip_set_hash.h>

#define IPSET_TYPE_REV_MIN	0
#define IPSET_TYPE_REV_MAX	0

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oliver Smith <oliver@uptheinter.net>");
IP_SET_MODULE_DESC("hash:net,port,net,port", IPSET_TYPE_REV_MIN,
					     IPSET_TYPE_REV_MAX);
MODULE_ALIAS("ip_set_hash:net,port,net,port");

/* Type specific function prefix */
#define HTYPE		hash_netportnetport
#define IP_SET_HASH_WITH_PROTO
#define IP_SET_HASH_WITH_NETS
#define IPSET_NET_COUNT 2

/* IPv4 variant */

/* Member elements */
struct hash_netportnetport4_elem {
	union {
		__be32 ip[2];
		__be64 ipcmp;
	};
	union {
		__be16 port[2];
		__be32 portcmp;
	};
	union {
		u8 cidr[2];
		u16 ccmp;
	};
	u16 padding;
	u8 nomatch;
	u8 proto;
};

/* Common functions */

static inline bool
hash_netportnetport4_data_equal(const struct hash_netportnetport4_elem *ip1,
			    const struct hash_netportnetport4_elem *ip2,
			    u32 *multi)
{
	return ip1->ipcmp == ip2->ipcmp &&
	       ip1->ccmp == ip2->ccmp &&
	       ip1->portcmp == ip2->portcmp &&
	       ip1->proto == ip2->proto;
}

static inline int
hash_netportnetport4_do_data_match(const struct hash_netportnetport4_elem *elem)
{
	return elem->nomatch ? -ENOTEMPTY : 1;
}

static inline void
hash_netportnetport4_data_set_flags(struct hash_netportnetport4_elem *elem,
				    u32 flags)
{
	elem->nomatch = !!((flags >> 16) & IPSET_FLAG_NOMATCH);
}

static inline void
hash_netportnetport4_data_reset_flags(struct hash_netportnetport4_elem *elem,
				      u8 *flags)
{
	swap(*flags, elem->nomatch);
}

static inline void
hash_netportnetport4_data_reset_elem(struct hash_netportnetport4_elem *elem,
				 struct hash_netportnetport4_elem *orig)
{
	elem->ip[1] = orig->ip[1];
}

static inline void
hash_netportnetport4_data_netmask(struct hash_netportnetport4_elem *elem,
			      u8 cidr, bool inner)
{
	if (inner) {
		elem->ip[1] &= ip_set_netmask(cidr);
		elem->cidr[1] = cidr;
	} else {
		elem->ip[0] &= ip_set_netmask(cidr);
		elem->cidr[0] = cidr;
	}
}

static bool
hash_netportnetport4_data_list(struct sk_buff *skb,
			   const struct hash_netportnetport4_elem *data)
{
	u32 flags = data->nomatch ? IPSET_FLAG_NOMATCH : 0;

	if (nla_put_ipaddr4(skb, IPSET_ATTR_IP, data->ip[0]) ||
	    nla_put_ipaddr4(skb, IPSET_ATTR_IP2, data->ip[1]) ||
	    nla_put_net16(skb, IPSET_ATTR_PORT, data->port[0]) ||
	    nla_put_net16(skb, IPSET_ATTR_PORT2, data->port[1]) ||
	    nla_put_u8(skb, IPSET_ATTR_CIDR, data->cidr[0]) ||
	    nla_put_u8(skb, IPSET_ATTR_CIDR2, data->cidr[1]) ||
	    nla_put_u8(skb, IPSET_ATTR_PROTO, data->proto) ||
	    (flags &&
	     nla_put_net32(skb, IPSET_ATTR_CADT_FLAGS, htonl(flags))))
		goto nla_put_failure;
	return false;

nla_put_failure:
	return true;
}

static inline void
hash_netportnetport4_data_next(struct hash_netportnetport4_elem *next,
			   const struct hash_netportnetport4_elem *d)
{
	next->ipcmp = d->ipcmp;
	next->portcmp = d->portcmp;
}

#define MTYPE		hash_netportnetport4
#define HOST_MASK	32
#include "ip_set_hash_gen.h"

static void
hash_netportnetport4_init(struct hash_netportnetport4_elem *e)
{
	e->cidr[0] = HOST_MASK;
	e->cidr[1] = HOST_MASK;
}

static int
hash_netportnetport4_kadt(struct ip_set *set, const struct sk_buff *skb,
		      const struct xt_action_param *par,
		      enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	const struct hash_netportnetport4 *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_netportnetport4_elem e = { };
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);

	e.cidr[0] = INIT_CIDR(h->nets[0].cidr[0], HOST_MASK);
	e.cidr[1] = INIT_CIDR(h->nets[0].cidr[1], HOST_MASK);
	if (adt == IPSET_TEST)
		e.ccmp = (HOST_MASK << (sizeof(e.cidr[0]) * 8)) | HOST_MASK;

	if (!ip_set_get_ip4_port(skb, opt->flags & IPSET_DIM_TWO_SRC,
				 &e.port[0], &e.proto))
		return -EINVAL;
	if (!ip_set_get_ip4_port(skb, opt->flags & IPSET_DIM_FOUR_SRC,
				 &e.port[1], &e.proto))
		return -EINVAL;

	ip4addrptr(skb, opt->flags & IPSET_DIM_ONE_SRC, &e.ip[0]);
	ip4addrptr(skb, opt->flags & IPSET_DIM_THREE_SRC, &e.ip[1]);
	e.ip[0] &= ip_set_netmask(e.cidr[0]);
	e.ip[1] &= ip_set_netmask(e.cidr[1]);

	return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
}

static int
hash_netportnetport4_uadt(struct ip_set *set, struct nlattr *tb[],
		      enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	const struct hash_netportnetport4 *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_netportnetport4_elem e = { };
	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
	u32 ip = 0, ip_to = 0, p = 0, p2 = 0, port, port_to, port2, port2_to;
	u32 ip2_from = 0, ip2_to = 0, ip2;
	bool with_ports = false;
	int ret;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	hash_netportnetport4_init(&e);
	if (unlikely(!tb[IPSET_ATTR_IP] || !tb[IPSET_ATTR_IP2] ||
		     !ip_set_attr_netorder(tb, IPSET_ATTR_PORT) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PORT_TO) ||
		     !ip_set_attr_netorder(tb, IPSET_ATTR_PORT2) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PORT2_TO) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS)))
		return -IPSET_ERR_PROTOCOL;

	ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP], &ip);
	if (ret)
		return ret;

	ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP2], &ip2_from);
	if (ret)
		return ret;

	ret = ip_set_get_extensions(set, tb, &ext);
	if (ret)
		return ret;

	if (tb[IPSET_ATTR_CIDR]) {
		e.cidr[0] = nla_get_u8(tb[IPSET_ATTR_CIDR]);
		if (e.cidr[0] > HOST_MASK)
			return -IPSET_ERR_INVALID_CIDR;
	}

	if (tb[IPSET_ATTR_CIDR2]) {
		e.cidr[1] = nla_get_u8(tb[IPSET_ATTR_CIDR2]);
		if (e.cidr[1] > HOST_MASK)
			return -IPSET_ERR_INVALID_CIDR;
	}

	e.port[0] = nla_get_be16(tb[IPSET_ATTR_PORT]);
	e.port[1] = nla_get_be16(tb[IPSET_ATTR_PORT2]);

	if (tb[IPSET_ATTR_PROTO]) {
		e.proto = nla_get_u8(tb[IPSET_ATTR_PROTO]);
		with_ports = ip_set_proto_with_ports(e.proto);

		if (e.proto == 0)
			return -IPSET_ERR_INVALID_PROTO;
	} else {
		return -IPSET_ERR_MISSING_PROTO;
	}

	if (!(with_ports || e.proto == IPPROTO_ICMP))
		e.portcmp = 0;

	if (tb[IPSET_ATTR_CADT_FLAGS]) {
		u32 cadt_flags = ip_set_get_h32(tb[IPSET_ATTR_CADT_FLAGS]);

		if (cadt_flags & IPSET_FLAG_NOMATCH)
			flags |= (IPSET_FLAG_NOMATCH << 16);
	}

	with_ports = with_ports && (tb[IPSET_ATTR_PORT_TO] ||
				   tb[IPSET_ATTR_PORT2_TO]);
	if (adt == IPSET_TEST ||
	    !(tb[IPSET_ATTR_IP_TO] || with_ports || tb[IPSET_ATTR_IP2_TO])) {
		e.ip[0] = htonl(ip & ip_set_hostmask(e.cidr[0]));
		e.ip[1] = htonl(ip2_from & ip_set_hostmask(e.cidr[1]));
		ret = adtfn(set, &e, &ext, &ext, flags);
		return ip_set_enomatch(ret, flags, adt, set) ? -ret :
		       ip_set_eexist(ret, flags) ? 0 : ret;
	}

	ip_to = ip;
	if (tb[IPSET_ATTR_IP_TO]) {
		ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP_TO], &ip_to);
		if (ret)
			return ret;
		if (ip > ip_to)
			swap(ip, ip_to);
		if (unlikely(ip + UINT_MAX == ip_to))
			return -IPSET_ERR_HASH_RANGE;
	} else {
		ip_set_mask_from_to(ip, ip_to, e.cidr[0]);
	}

	port_to = port = ntohs(e.port[0]);
	if (tb[IPSET_ATTR_PORT_TO]) {
		port_to = ip_set_get_h16(tb[IPSET_ATTR_PORT_TO]);
		if (port > port_to)
			swap(port, port_to);
	}

	port2_to = port2 = ntohs(e.port[1]);
	if (tb[IPSET_ATTR_PORT2_TO]) {
		port2_to = ip_set_get_h16(tb[IPSET_ATTR_PORT2_TO]);
		if (port2 > port2_to)
			swap(port2, port2_to);
	}

	ip2_to = ip2_from;
	if (tb[IPSET_ATTR_IP2_TO]) {
		ret = ip_set_get_hostipaddr4(tb[IPSET_ATTR_IP2_TO], &ip2_to);
		if (ret)
			return ret;
		if (ip2_from > ip2_to)
			swap(ip2_from, ip2_to);
		if (unlikely(ip2_from + UINT_MAX == ip2_to))
			return -IPSET_ERR_HASH_RANGE;
	} else {
		ip_set_mask_from_to(ip2_from, ip2_to, e.cidr[1]);
	}

	if (retried) {
		ip = ntohl(h->next.ip[0]);
		p = ntohs(h->next.port[0]);
		p2 = ntohs(h->next.port[1]);
		ip2 = ntohl(h->next.ip[1]);
	} else {
		p = port;
		p2 = port2;
		ip2 = ip2_from;
	}

	do {
		e.ip[0] = htonl(ip);
		ip = ip_set_range_to_cidr(ip, ip_to, &e.cidr[0]);
		for (; p <= port_to; p++) {
			e.port[0] = htons(p);
			for (; p2 <= port2_to; p2++) {
				e.port[1] = htons(p2);
				do {
					e.ip[1] = htonl(ip2);
					ip2 = ip_set_range_to_cidr(ip2, ip2_to,
								   &e.cidr[1]);
					ret = adtfn(set, &e, &ext, &ext, flags);
					if (ret && !ip_set_eexist(ret, flags))
						return ret;

					ret = 0;
				} while (ip2++ < ip2_to);
				ip2 = ip2_from;
			}
			p2 = port2;
		}
		p = port;
	} while (ip++ < ip_to);
	return ret;
}

/* IPv6 variant */

struct hash_netportnetport6_elem {
	union nf_inet_addr ip[2];
	union {
		__be16 port[2];
		__be32 portcmp;
	};
	union {
		u8 cidr[2];
		u16 ccmp;
	};
	u16 padding;
	u8 nomatch;
	u8 proto;
};

/* Common functions */

static inline bool
hash_netportnetport6_data_equal(const struct hash_netportnetport6_elem *ip1,
			    const struct hash_netportnetport6_elem *ip2,
			    u32 *multi)
{
	return ipv6_addr_equal(&ip1->ip[0].in6, &ip2->ip[0].in6) &&
	       ipv6_addr_equal(&ip1->ip[1].in6, &ip2->ip[1].in6) &&
	       ip1->ccmp == ip2->ccmp &&
	       ip1->portcmp == ip2->portcmp &&
	       ip1->proto == ip2->proto;
}

static inline int
hash_netportnetport6_do_data_match(const struct hash_netportnetport6_elem *elem)
{
	return elem->nomatch ? -ENOTEMPTY : 1;
}

static inline void
hash_netportnetport6_data_set_flags(struct hash_netportnetport6_elem *elem,
				    u32 flags)
{
	elem->nomatch = !!((flags >> 16) & IPSET_FLAG_NOMATCH);
}

static inline void
hash_netportnetport6_data_reset_flags(struct hash_netportnetport6_elem *elem,
				      u8 *flags)
{
	swap(*flags, elem->nomatch);
}

static inline void
hash_netportnetport6_data_reset_elem(struct hash_netportnetport6_elem *elem,
				 struct hash_netportnetport6_elem *orig)
{
	elem->ip[1] = orig->ip[1];
}

static inline void
hash_netportnetport6_data_netmask(struct hash_netportnetport6_elem *elem,
			      u8 cidr, bool inner)
{
	if (inner) {
		ip6_netmask(&elem->ip[1], cidr);
		elem->cidr[1] = cidr;
	} else {
		ip6_netmask(&elem->ip[0], cidr);
		elem->cidr[0] = cidr;
	}
}

static bool
hash_netportnetport6_data_list(struct sk_buff *skb,
			   const struct hash_netportnetport6_elem *data)
{
	u32 flags = data->nomatch ? IPSET_FLAG_NOMATCH : 0;

	if (nla_put_ipaddr6(skb, IPSET_ATTR_IP, &data->ip[0].in6) ||
	    nla_put_ipaddr6(skb, IPSET_ATTR_IP2, &data->ip[1].in6) ||
	    nla_put_net16(skb, IPSET_ATTR_PORT, data->port[0]) ||
	    nla_put_net16(skb, IPSET_ATTR_PORT2, data->port[1]) ||
	    nla_put_u8(skb, IPSET_ATTR_CIDR, data->cidr[0]) ||
	    nla_put_u8(skb, IPSET_ATTR_CIDR2, data->cidr[1]) ||
	    nla_put_u8(skb, IPSET_ATTR_PROTO, data->proto) ||
	    (flags &&
	     nla_put_net32(skb, IPSET_ATTR_CADT_FLAGS, htonl(flags))))
		goto nla_put_failure;
	return false;

nla_put_failure:
	return true;
}

static inline void
hash_netportnetport6_data_next(struct hash_netportnetport6_elem *next,
			   const struct hash_netportnetport6_elem *d)
{
	next->portcmp = d->portcmp;
}

#undef MTYPE
#undef HOST_MASK

#define MTYPE		hash_netportnetport6
#define HOST_MASK	128
#define IP_SET_EMIT_CREATE
#include "ip_set_hash_gen.h"

static void
hash_netportnetport6_init(struct hash_netportnetport6_elem *e)
{
	e->cidr[0] = HOST_MASK;
	e->cidr[1] = HOST_MASK;
}

static int
hash_netportnetport6_kadt(struct ip_set *set, const struct sk_buff *skb,
		      const struct xt_action_param *par,
		      enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	const struct hash_netportnetport6 *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_netportnetport6_elem e = { };
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);

	e.cidr[0] = INIT_CIDR(h->nets[0].cidr[0], HOST_MASK);
	e.cidr[1] = INIT_CIDR(h->nets[0].cidr[1], HOST_MASK);
	if (adt == IPSET_TEST)
		e.ccmp = (HOST_MASK << (sizeof(u8) * 8)) | HOST_MASK;

	if (!ip_set_get_ip6_port(skb, opt->flags & IPSET_DIM_TWO_SRC,
				 &e.port[0], &e.proto))
		return -EINVAL;
	if (!ip_set_get_ip6_port(skb, opt->flags & IPSET_DIM_FOUR_SRC,
				 &e.port[1], &e.proto))
		return -EINVAL;

	ip6addrptr(skb, opt->flags & IPSET_DIM_ONE_SRC, &e.ip[0].in6);
	ip6addrptr(skb, opt->flags & IPSET_DIM_THREE_SRC, &e.ip[1].in6);
	ip6_netmask(&e.ip[0], e.cidr[0]);
	ip6_netmask(&e.ip[1], e.cidr[1]);

	return adtfn(set, &e, &ext, &opt->ext, opt->cmdflags);
}

static int
hash_netportnetport6_uadt(struct ip_set *set, struct nlattr *tb[],
		      enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	const struct hash_netportnetport6 *h = set->data;
	ipset_adtfn adtfn = set->variant->adt[adt];
	struct hash_netportnetport6_elem e = { };
	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
	u32 port, port_to, port2, port2_to, p2;
	bool with_ports = false;
	int ret;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	hash_netportnetport6_init(&e);
	if (unlikely(!tb[IPSET_ATTR_IP] || !tb[IPSET_ATTR_IP2] ||
		     !ip_set_attr_netorder(tb, IPSET_ATTR_PORT) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PORT_TO) ||
		     !ip_set_attr_netorder(tb, IPSET_ATTR_PORT2) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_PORT2_TO) ||
		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS)))
		return -IPSET_ERR_PROTOCOL;
	if (unlikely(tb[IPSET_ATTR_IP_TO] || tb[IPSET_ATTR_IP2_TO]))
		return -IPSET_ERR_HASH_RANGE_UNSUPPORTED;

	ret = ip_set_get_ipaddr6(tb[IPSET_ATTR_IP], &e.ip[0]);
	if (ret)
		return ret;

	ret = ip_set_get_ipaddr6(tb[IPSET_ATTR_IP2], &e.ip[1]);
	if (ret)
		return ret;

	ret = ip_set_get_extensions(set, tb, &ext);
	if (ret)
		return ret;

	if (tb[IPSET_ATTR_CIDR]) {
		e.cidr[0] = nla_get_u8(tb[IPSET_ATTR_CIDR]);
		if (e.cidr[0] > HOST_MASK)
			return -IPSET_ERR_INVALID_CIDR;
	}

	if (tb[IPSET_ATTR_CIDR2]) {
		e.cidr[1] = nla_get_u8(tb[IPSET_ATTR_CIDR2]);
		if (e.cidr[1] > HOST_MASK)
			return -IPSET_ERR_INVALID_CIDR;
	}

	ip6_netmask(&e.ip[0], e.cidr[0]);
	ip6_netmask(&e.ip[1], e.cidr[1]);

	e.port[0] = nla_get_be16(tb[IPSET_ATTR_PORT]);
	e.port[1] = nla_get_be16(tb[IPSET_ATTR_PORT2]);

	if (tb[IPSET_ATTR_PROTO]) {
		e.proto = nla_get_u8(tb[IPSET_ATTR_PROTO]);
		with_ports = ip_set_proto_with_ports(e.proto);

		if (e.proto == 0)
			return -IPSET_ERR_INVALID_PROTO;
	} else {
		return -IPSET_ERR_MISSING_PROTO;
	}

	if (!(with_ports || e.proto == IPPROTO_ICMPV6))
		e.portcmp = 0;

	if (tb[IPSET_ATTR_CADT_FLAGS]) {
		u32 cadt_flags = ip_set_get_h32(tb[IPSET_ATTR_CADT_FLAGS]);

		if (cadt_flags & IPSET_FLAG_NOMATCH)
			flags |= (IPSET_FLAG_NOMATCH << 16);
	}

	if (adt == IPSET_TEST || !with_ports || (!tb[IPSET_ATTR_PORT_TO] &&
						!tb[IPSET_ATTR_PORT2_TO])) {
		ret = adtfn(set, &e, &ext, &ext, flags);
		return ip_set_enomatch(ret, flags, adt, set) ? -ret :
		       ip_set_eexist(ret, flags) ? 0 : ret;
	}

	port = ntohs(e.port[0]);
	port_to = tb[IPSET_ATTR_PORT_TO] ?
			ip_set_get_h16(tb[IPSET_ATTR_PORT_TO])
			: port;
	port2 = ntohs(e.port[1]);
	port2_to = tb[IPSET_ATTR_PORT2_TO] ?
			ip_set_get_h16(tb[IPSET_ATTR_PORT2_TO])
			: port2;

	if (port > port_to)
		swap(port, port_to);
	if (port2 > port2_to)
		swap(port2, port2_to);

	for (; port <= port_to; port++) {
		e.port[0] = htons(port);
		for (p2 = port2; p2 <= port2_to; p2++) {
			e.port[1] = htons(p2);
			ret = adtfn(set, &e, &ext, &ext, flags);

			if (ret == -EAGAIN && !ip_set_eexist(ret, flags))
				return ret;

			ret = 0;
		}
	}
	return ret;
}

static struct ip_set_type hash_netportnetport_type __read_mostly = {
	.name		= "hash:net,port,net,port",
	.protocol	= IPSET_PROTOCOL,
	.features	= IPSET_TYPE_IP | IPSET_TYPE_PORT | IPSET_TYPE_PORT2 |
			  IPSET_TYPE_IP2 | IPSET_TYPE_NOMATCH,
	.dimension	= IPSET_DIM_FOUR,
	.family		= NFPROTO_UNSPEC,
	.revision_min	= IPSET_TYPE_REV_MIN,
	.revision_max	= IPSET_TYPE_REV_MAX,
	.create		= hash_netportnetport_create,
	.create_policy	= {
		[IPSET_ATTR_HASHSIZE]	= { .type = NLA_U32 },
		[IPSET_ATTR_MAXELEM]	= { .type = NLA_U32 },
		[IPSET_ATTR_PROBES]	= { .type = NLA_U8 },
		[IPSET_ATTR_RESIZE]	= { .type = NLA_U8  },
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_CADT_FLAGS]	= { .type = NLA_U32 },
	},
	.adt_policy	= {
		[IPSET_ATTR_IP]		= { .type = NLA_NESTED },
		[IPSET_ATTR_IP_TO]	= { .type = NLA_NESTED },
		[IPSET_ATTR_IP2]	= { .type = NLA_NESTED },
		[IPSET_ATTR_IP2_TO]	= { .type = NLA_NESTED },
		[IPSET_ATTR_PORT]	= { .type = NLA_U16 },
		[IPSET_ATTR_PORT_TO]	= { .type = NLA_U16 },
		[IPSET_ATTR_PORT2]      = { .type = NLA_U16 },
		[IPSET_ATTR_PORT2_TO]   = { .type = NLA_U16},
		[IPSET_ATTR_CIDR]	= { .type = NLA_U8 },
		[IPSET_ATTR_CIDR2]	= { .type = NLA_U8 },
		[IPSET_ATTR_PROTO]	= { .type = NLA_U8 },
		[IPSET_ATTR_CADT_FLAGS]	= { .type = NLA_U32 },
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
		[IPSET_ATTR_COMMENT]	= { .type = NLA_NUL_STRING,
					    .len  = IPSET_MAX_COMMENT_SIZE },
		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
	},
	.me		= THIS_MODULE,
};

static int __init
hash_netportnetport_init(void)
{
	return ip_set_type_register(&hash_netportnetport_type);
}

static void __exit
hash_netportnetport_fini(void)
{
	rcu_barrier();
	ip_set_type_unregister(&hash_netportnetport_type);
}

module_init(hash_netportnetport_init);
module_exit(hash_netportnetport_fini);
