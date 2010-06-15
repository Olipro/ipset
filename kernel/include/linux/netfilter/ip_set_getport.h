#ifndef _IP_SET_GETPORT_H
#define _IP_SET_GETPORT_H

#ifdef __KERNEL__
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/ip.h>

#define IPSET_INVALID_PORT	65536

/* We must handle non-linear skbs */
static bool
get_port(u8 pf, const struct sk_buff *skb, bool src, u16 *port)
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
			return false;

		protocol = protohdr;
		fragoff = frag_off;
		break;
	}
	default:
		return false;
	}

	/* See comments at tcp_match in ip_tables.c */
	if (fragoff)
		return false;

	switch (protocol) {
	case IPPROTO_TCP: {
		struct tcphdr _tcph;
		const struct tcphdr *th;
		
		th = skb_header_pointer(skb, protoff, sizeof(_tcph), &_tcph);
		if (th == NULL)
			/* No choice either */
			return false;
	     	
	     	*port = src ? th->source : th->dest;
	     	break;
	    }
	case IPPROTO_UDP: {
		struct udphdr _udph;
		const struct udphdr *uh;

		uh = skb_header_pointer(skb, protoff, sizeof(_udph), &_udph);
		if (uh == NULL)
			/* No choice either */
			return false;
	     	
	     	*port = src ? uh->source : uh->dest;
	     	break;
	    }
	default:
		return false;
	}
	return true;
}
#endif /* __KERNEL__ */

#endif /*_IP_SET_GETPORT_H*/
