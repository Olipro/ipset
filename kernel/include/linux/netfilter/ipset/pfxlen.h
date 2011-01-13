#ifndef _PFXLEN_H
#define _PFXLEN_H

#include <asm/byteorder.h>
#include <linux/netfilter.h> 

/* Prefixlen maps, by Jan Engelhardt  */
extern const union nf_inet_addr prefixlen_netmask_map[];
extern const union nf_inet_addr prefixlen_hostmask_map[];

#define NETMASK(n)	prefixlen_netmask_map[n].ip
#define NETMASK6(n)	prefixlen_netmask_map[n].ip6
#define HOSTMASK(n)	prefixlen_hostmask_map[n].ip
#define HOSTMASK6(n)	prefixlen_hostmask_map[n].ip6

#endif /*_PFXLEN_H */
