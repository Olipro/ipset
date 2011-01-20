#ifndef _IP_SET_GETPORT_H
#define _IP_SET_GETPORT_H

#ifdef __KERNEL__
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/ip.h>

#define IPSET_INVALID_PORT	65536

/* We must handle non-linear skbs */
static inline bool
get_port(const struct sk_buff *skb, int protocol, unsigned int protooff,
	 bool src, __be16 *port, u8 *proto)
{
	switch (protocol) {
	case IPPROTO_TCP: {
		struct tcphdr _tcph;
		const struct tcphdr *th;

		th = skb_header_pointer(skb, protooff, sizeof(_tcph), &_tcph);
		if (th == NULL)
			/* No choice either */
			return false;

		*port = src ? th->source : th->dest;
		break;
	}
	case IPPROTO_UDP: {
		struct udphdr _udph;
		const struct udphdr *uh;

		uh = skb_header_pointer(skb, protooff, sizeof(_udph), &_udph);
		if (uh == NULL)
			/* No choice either */
			return false;

		*port = src ? uh->source : uh->dest;
		break;
	}
	case IPPROTO_ICMP: {
		struct icmphdr _icmph;
		const struct icmphdr *ic;

		ic = skb_header_pointer(skb, protooff, sizeof(_icmph), &_icmph);
		if (ic == NULL)
			return false;

		*port = (__force __be16)((ic->type << 8) & ic->code);
		break;
	}
	case IPPROTO_ICMPV6: {
		struct icmp6hdr _icmph;
		const struct icmp6hdr *ic;

		ic = skb_header_pointer(skb, protooff, sizeof(_icmph), &_icmph);
		if (ic == NULL)
			return false;

		*port = (__force __be16)((ic->icmp6_type << 8) & ic->icmp6_code);
		break;
	}
	default:
		break;
	}
	*proto = protocol;

	return true;
}

static inline bool
get_ip4_port(const struct sk_buff *skb, bool src, __be16 *port, u8 *proto)
{
	const struct iphdr *iph = ip_hdr(skb);
	unsigned int protooff = ip_hdrlen(skb);
	int protocol = iph->protocol;

	/* See comments at tcp_match in ip_tables.c */
	if (protocol <= 0 || (ntohs(iph->frag_off) & IP_OFFSET))
		return false;

	return get_port(skb, protocol, protooff, src, port, proto);
}

static inline bool
get_ip6_port(const struct sk_buff *skb, bool src, __be16 *port, u8 *proto)
{
	unsigned int protooff = 0;
	int protocol;
	unsigned short fragoff;

	protocol = ipv6_find_hdr(skb, &protooff, -1, &fragoff);
	if (protocol <= 0 || fragoff)
		return false;

	return get_port(skb, protocol, protooff, src, port, proto);
}

static inline bool
get_ip_port(const struct sk_buff *skb, u8 pf, bool src, __be16 *port)
{
	bool ret;
	u8 proto;

	switch (pf) {
	case AF_INET:
		ret = get_ip4_port(skb, src, port, &proto);
	case AF_INET6:
		ret = get_ip6_port(skb, src, port, &proto);
	default:
		return false;
	}
	if (!ret)
		return ret;
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		return true;
	default:
		return false;
	}
}
#endif /* __KERNEL__ */

#endif /*_IP_SET_GETPORT_H*/
