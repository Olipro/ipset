#ifndef _IP_SET_GETPORT_H
#define _IP_SET_GETPORT_H

#ifdef __KERNEL__
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/ip.h>

#define IPSET_INVALID_PORT	65536

/* We must handle non-linear skbs */
static uint32_t
get_port(uint8_t pf, const struct sk_buff *skb, const uint8_t *flags)
{
	unsigned short protocol;
	unsigned int protoff;
	int fragoff;
	
	switch (pf) {
	case AF_INET: {
		const struct iphdr *iph = ip_hdr(skb);

		protocol = iph->protocol;
		fragoff = ntohs(iph->frag_off) & IP_OFFSET;
		protoff = ip_hdrlen(skb);
		break;
	}
	case AF_INET6: {
		int protohdr;
		unsigned short frag_off;
		
		protohdr = ipv6_find_hdr(skb, &protoff, -1, &frag_off);
		if (protohdr < 0)
			return IPSET_INVALID_PORT;

		protocol = protohdr;
		fragoff = frag_off;
		break;
	}
	default:
		return IPSET_INVALID_PORT;
	}

	/* See comments at tcp_match in ip_tables.c */
	if (fragoff)
		return IPSET_INVALID_PORT;

	switch (protocol) {
	case IPPROTO_TCP: {
		struct tcphdr _tcph;
		const struct tcphdr *th;
		
		th = skb_header_pointer(skb, protoff, sizeof(_tcph), &_tcph);
		if (th == NULL)
			/* No choice either */
			return IPSET_INVALID_PORT;
	     	
	     	return flags[0] & IPSET_SRC ? th->source : th->dest;
	    }
	case IPPROTO_UDP: {
		struct udphdr _udph;
		const struct udphdr *uh;

		uh = skb_header_pointer(skb, protoff, sizeof(_udph), &_udph);
		if (uh == NULL)
			/* No choice either */
			return IPSET_INVALID_PORT;
	     	
	     	return flags[0] & IPSET_SRC ? uh->source : uh->dest;
	    }
	default:
		return IPSET_INVALID_PORT;
	}
}
#endif				/* __KERNEL__ */

#endif /*_IP_SET_GETPORT_H*/
