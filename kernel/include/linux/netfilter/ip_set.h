#ifndef _IP_SET_H
#define _IP_SET_H

/* Copyright (C) 2000-2002 Joakim Axelsson <gozem@linux.nu>
 *                         Patrick Schaaf <bof@bof.de>
 *                         Martin Josefsson <gandalf@wlug.westbo.se>
 * Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.  
 */

#if 1
#define IP_SET_DEBUG
#endif

/* The protocol version */
#define IPSET_PROTOCOL		5

/* The max length of strings: set and type identifiers */
#define IPSET_MAXNAMELEN	32

/* Message types and commands */
enum ipset_cmd {
	IPSET_CMD_NONE,
	IPSET_CMD_CREATE,	/* Create a new (empty) set */
	IPSET_CMD_DESTROY,	/* Remove a (empty) set */
	IPSET_CMD_FLUSH,	/* Remove all elements from a set */
	IPSET_CMD_RENAME,	/* Rename a set */
	IPSET_CMD_SWAP,		/* Swap two sets */
	IPSET_CMD_LIST,		/* List sets */
	IPSET_CMD_SAVE,		/* Save sets */
	IPSET_CMD_ADD,		/* Add an element to a set */
	IPSET_CMD_DEL,		/* Delete an element from a set */
	IPSET_CMD_TEST,		/* Test an element in a set */
	IPSET_CMD_HEADER,	/* Get set header data only */
	IPSET_CMD_TYPE,		/* Get set type */
	IPSET_CMD_PROTOCOL,	/* Return protocol version */
	IPSET_MSG_MAX,		/* Netlink message commands */

	/* Commands in userspace: */
	IPSET_CMD_RESTORE = IPSET_MSG_MAX, /* Enter restore mode */	
	IPSET_CMD_HELP,		/* Get help */
	IPSET_CMD_VERSION,	/* Get program version */

	IPSET_CMD_MAX,

	IPSET_CMD_COMMIT = IPSET_CMD_MAX, /* Commit buffered commands */
};

/* Attributes at command level */
enum {
	IPSET_ATTR_UNSPEC,
	IPSET_ATTR_PROTOCOL,	/* Protocol version */
	IPSET_ATTR_SETNAME,	/* Name of the set */
	IPSET_ATTR_TYPENAME,	/* Typename */
	IPSET_ATTR_SETNAME2 = IPSET_ATTR_TYPENAME, /* rename/swap */
	IPSET_ATTR_REVISION,	/* Settype revision */
	IPSET_ATTR_FAMILY,	/* Settype family */
	IPSET_ATTR_DATA,	/* Nested attributes */
	IPSET_ATTR_ADT,		/* Multiple data containers */
	IPSET_ATTR_LINENO,	/* Restore lineno */
	IPSET_ATTR_PROTOCOL_MIN,/* Minimal supported version number */
	IPSET_ATTR_REVISION_MIN = IPSET_ATTR_PROTOCOL_MIN, /* type rev min */
	__IPSET_ATTR_CMD_MAX,
};
#define IPSET_ATTR_CMD_MAX	(__IPSET_ATTR_CMD_MAX - 1)

/* CADT specific attributes */
enum {
	IPSET_ATTR_IP = IPSET_ATTR_UNSPEC + 1,
	IPSET_ATTR_IP_FROM = IPSET_ATTR_IP,
	IPSET_ATTR_IP_TO,
	IPSET_ATTR_CIDR,
	IPSET_ATTR_PORT,
	IPSET_ATTR_PORT_FROM = IPSET_ATTR_PORT,
	IPSET_ATTR_PORT_TO,
	IPSET_ATTR_TIMEOUT,
	IPSET_ATTR_FLAGS,
	/* IPSET_ATTR_LINENO */
	/* Reserve empty slots */
	IPSET_ATTR_CADT_MAX = 16,
	/* Create-only specific attributes */
	IPSET_ATTR_GC,
	IPSET_ATTR_HASHSIZE,
	IPSET_ATTR_MAXELEM,
	IPSET_ATTR_NETMASK,
	IPSET_ATTR_PROBES,
	IPSET_ATTR_RESIZE,
	IPSET_ATTR_SIZE,
	/* Kernel-only */
	IPSET_ATTR_ELEMENTS,
	IPSET_ATTR_REFERENCES,
	IPSET_ATTR_MEMSIZE,
	
	__IPSET_ATTR_CREATE_MAX,
};
#define IPSET_ATTR_CREATE_MAX	(__IPSET_ATTR_CREATE_MAX - 1)

/* ADT specific attributes */
enum {
	IPSET_ATTR_ETHER = IPSET_ATTR_CADT_MAX + 1,
	IPSET_ATTR_NAME,
	IPSET_ATTR_NAMEREF,
	IPSET_ATTR_IP2,
	IPSET_ATTR_CIDR2,
	__IPSET_ATTR_ADT_MAX,
};
#define IPSET_ATTR_ADT_MAX	(__IPSET_ATTR_ADT_MAX - 1)

/* Error codes */
enum ipset_errno {
	IPSET_ERR_PRIVATE = 128,
	IPSET_ERR_PROTOCOL,
	IPSET_ERR_FIND_TYPE,
	IPSET_ERR_MAX_SETS,
	IPSET_ERR_BUSY,
	IPSET_ERR_EXIST_SETNAME2,
	IPSET_ERR_TYPE_MISMATCH,
	IPSET_ERR_EXIST,
	IPSET_ERR_INVALID_CIDR,
	IPSET_ERR_INVALID_NETMASK,
	IPSET_ERR_INVALID_FAMILY,
	IPSET_ERR_TIMEOUT,

	IPSET_ERR_TYPE_SPECIFIC = 160,
};
	                                
enum ipset_data_flags {
	IPSET_FLAG_BIT_EXIST	= 0,
	IPSET_FLAG_EXIST	= (1 << IPSET_FLAG_BIT_EXIST),
	
	IPSET_FLAG_BIT_BEFORE	= 2,
	IPSET_FLAG_BEFORE	= (1 << IPSET_FLAG_BIT_BEFORE),
};

/* Commands with settype-specific attributes */
enum ipset_adt {
	IPSET_ADD,
	IPSET_DEL,
	IPSET_TEST,
	IPSET_CREATE,
	IPSET_CADT_MAX,
};

#ifndef __KERNEL__
#ifdef IP_SET_DEBUG
#include <stdio.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#define D(format, args...)	do {				\
	fprintf(stderr, "%s: %s: ", __FILE__, __FUNCTION__);	\
	fprintf(stderr, format "\n" , ## args);			\
} while (0)
static inline void
dump_nla(struct  nlattr *nla[], int maxlen)
{
	int i;
	
	for (i = 0; i < maxlen; i++)
		D("nla[%u] does%s exist", i, !nla[i] ? " NOT" : "");
}

#else
#define D(format, args...)
#define dump_nla(nla, maxlen)
#endif
#endif /* !__KERNEL__ */

#ifdef __KERNEL__
#include <linux/ipv6.h>
#include <linux/netlink.h>
#include <net/netlink.h>

/* Sets are identified by an index in kernel space. Tweak with ip_set_id_t
 * and IPSET_INVALID_ID if you want to increase the max number of sets.
 */
typedef uint16_t ip_set_id_t;

#define IPSET_INVALID_ID		65535

/* Option flags for kernel operations */
enum ip_set_kopt {
	/* Bit 0 is reserved */
	IPSET_SRC_FLAG = 1,
	IPSET_SRC = (1 << IPSET_SRC_FLAG),
	IPSET_DST_FLAG = 2,
	IPSET_DST = (1 << IPSET_DST_FLAG),
	IPSET_INV_FLAG = 3,
	IPSET_INV = (1 << IPSET_INV_FLAG),
};

/* Set features */
enum ip_set_feature {
	IPSET_TYPE_IP_FLAG = 0,
	IPSET_TYPE_IP = (1 << IPSET_TYPE_IP_FLAG),
	IPSET_TYPE_PORT_FLAG = 1,
	IPSET_TYPE_PORT = (1 << IPSET_TYPE_PORT_FLAG),
	IPSET_TYPE_MAC_FLAG = 2,
	IPSET_TYPE_MAC = (1 << IPSET_TYPE_MAC_FLAG),
	IPSET_TYPE_IP2_FLAG = 3,
	IPSET_TYPE_IP2 = (1 << IPSET_TYPE_IP2_FLAG),
	IPSET_TYPE_NAME_FLAG = 4,
	IPSET_TYPE_NAME = (1 << IPSET_TYPE_NAME_FLAG),
};

static inline int
bitmap_bytes(uint32_t a, uint32_t b)
{
	return 4 * ((((b - a + 8) / 8) + 3) / 4);
}

#define ip_set_printk(format, args...) 				\
	do {							\
		printk("%s: %s: ", __FILE__, __FUNCTION__);	\
		printk(format "\n" , ## args);			\
	} while (0)

#if defined(IP_SET_DEBUG)
#define D(format, args...) 					\
	do {							\
		printk("%s: %s (DBG): ", __FILE__, __FUNCTION__);\
		printk(format "\n" , ## args);			\
	} while (0)

static inline void
dump_nla(const struct nlattr * const nla[], int maxlen)
{
	int i;
	
	for (i = 0; i < maxlen; i++)
		printk("nlattr[%u] does%s exist\n", i, nla[i] ? "" : " NOT");
}
#else
#define D(format, args...)
#define dump_nla(nla, maxlen)
#endif

struct ip_set;

/* Set type, variant-specific part */
struct ip_set_type_variant {
	/* Kernelspace: test/add/del entries */
	int (*kadt)(struct ip_set *set, const struct sk_buff * skb,
		    enum ipset_adt adt, uint8_t pf, const uint8_t *flags);

	/* Userspace: test/add/del entries */
	int (*uadt)(struct ip_set *set, struct nlattr *head, int len,
		    enum ipset_adt adt, uint32_t *lineno, uint32_t flags);

	/* When adding entries and set is full, try to resize the set */
	int (*resize)(struct ip_set *set, uint8_t retried);
	/* Destroy the set */
	void (*destroy)(struct ip_set *set);
	/* Flush the elements */
	void (*flush)(struct ip_set *set);

	/* List set header data */
	int (*head)(struct ip_set *set, struct sk_buff *skb);
	/* List elements */
	int (*list)(struct ip_set *set, struct sk_buff *skb,
		    struct netlink_callback *cb);
};

/* Flags for the set type variants */
enum ip_set_type_flags {
	IP_SET_FLAG_VMALLOC_BIT = 0,
	IP_SET_FLAG_VMALLOC = (1 << IP_SET_FLAG_VMALLOC_BIT),
	IP_SET_FLAG_TIMEOUT_BIT = 1,
	IP_SET_FLAG_TIMEOUT = (1 << IP_SET_FLAG_TIMEOUT_BIT),
};

/* The core set type structure */
struct ip_set_type {
	struct list_head list;

	/* Typename */
	char name[IPSET_MAXNAMELEN];
	/* Protocol version */
	uint8_t protocol;
	/* Set features to control swapping */
	uint8_t features;
	/* Supported family: may be AF_UNSPEC for both AF_INET/AF_INET6 */
	uint8_t family;
	/* Type revision */
	uint8_t revision;

	/* Create set */
	int (*create)(struct ip_set *set,
		      struct nlattr *head, int len, uint32_t flags);

	/* Set this to THIS_MODULE if you are a module, otherwise NULL */
	struct module *me;
};

extern int ip_set_type_register(struct ip_set_type *set_type);
extern void ip_set_type_unregister(struct ip_set_type *set_type);

/* A generic IP set */
struct ip_set {
	/* The name of the set */
	char name[IPSET_MAXNAMELEN];
	/* Lock protecting the set data */
	rwlock_t lock;
	/* References to the set */
	atomic_t ref;
	/* The core set type */
	const struct ip_set_type *type;
	/* The type variant doing the real job */
	const struct ip_set_type_variant *variant;
	/* The actual INET family */
	uint8_t family;
	/* Set type flags, filled/modified by create/resize */
	uint8_t flags;
	/* The type specific data */
	void *data;
};

/* register and unregister set references */
extern ip_set_id_t ip_set_get_byname(const char name[IPSET_MAXNAMELEN]);
extern void ip_set_put_byindex(ip_set_id_t index);

/* API for iptables set match, and SET target */
extern int ip_set_add(ip_set_id_t id, const struct sk_buff *skb,
		      uint8_t family, const uint8_t *flags);
extern int ip_set_del(ip_set_id_t id, const struct sk_buff *skb,
		      uint8_t family, const uint8_t *flags);
extern int ip_set_test(ip_set_id_t id, const struct sk_buff *skb,
		       uint8_t family, const uint8_t *flags);

/* Allocate members */
static inline void *
ip_set_alloc(size_t size, gfp_t gfp_mask, uint8_t *flags)
{
	void *members = kzalloc(size, gfp_mask);
	
	if (members) {
		*flags &= ~IP_SET_FLAG_VMALLOC;
		D("allocated with kmalloc %p", members);
		return members;
	}
	
	members = __vmalloc(size, gfp_mask | __GFP_ZERO, PAGE_KERNEL);
	if (!members)
		return NULL;
	*flags |= IP_SET_FLAG_VMALLOC;
	D("allocated with vmalloc %p", members);
	
	return members;
}

static inline void
ip_set_free(void *members, uint8_t flags)
{
	D("free with %s %p", flags & IP_SET_FLAG_VMALLOC ? "vmalloc" : "kmalloc",
	  members);
	if (flags & IP_SET_FLAG_VMALLOC)
		vfree(members);
	else
		kfree(members);
}

/* Useful converters */
static inline uint32_t
ip_set_get_h32(const struct nlattr *attr)
{
	uint32_t value = nla_get_u32(attr);
	
	return attr->nla_type & NLA_F_NET_BYTEORDER ? ntohl(value) : value;
}

static inline uint16_t
ip_set_get_h16(const struct nlattr *attr)
{
	uint16_t value = nla_get_u16(attr);
	
	return attr->nla_type & NLA_F_NET_BYTEORDER ? ntohs(value) : value;
}

static inline uint32_t
ip_set_get_n32(const struct nlattr *attr)
{
	uint32_t value = nla_get_u32(attr);
	
	return attr->nla_type & NLA_F_NET_BYTEORDER ? value : htonl(value);
}

static inline uint16_t
ip_set_get_n16(const struct nlattr *attr)
{
	uint16_t value = nla_get_u16(attr);
	
	return attr->nla_type & NLA_F_NET_BYTEORDER ? value : htons(value);
}

#define ipset_nest_start(skb, attr) nla_nest_start(skb, attr | NLA_F_NESTED)
#define ipset_nest_end(skb, start)  nla_nest_end(skb, start)	

#define NLA_PUT_NET32(skb, type, value)	\
	NLA_PUT_BE32(skb, type | NLA_F_NET_BYTEORDER, value)

#define NLA_PUT_NET16(skb, type, value)	\
	NLA_PUT_BE16(skb, type | NLA_F_NET_BYTEORDER, value)

/* Get address from skbuff */
static inline uint32_t
ip4addr(const struct sk_buff *skb, const uint8_t *flags)
{
	return flags[0] & IPSET_SRC ? ip_hdr(skb)->saddr
				    : ip_hdr(skb)->daddr;
}

static inline void
ip4addrptr(const struct sk_buff *skb, const uint8_t *flags, uint32_t *addr)
{
	*addr = flags[0] & IPSET_SRC ? ip_hdr(skb)->saddr
				     : ip_hdr(skb)->daddr;
}

static inline void
ip6addrptr(const struct sk_buff *skb, const uint8_t *flags,
	   struct in6_addr *addr)
{
	memcpy(addr, flags[0] & IPSET_SRC ? &ipv6_hdr(skb)->saddr
					  : &ipv6_hdr(skb)->daddr,
	       sizeof(*addr));
}

#define pack_ip_port(map, ip, port) \
	(port + ((ip - ((map)->first_ip)) << 16))

#endif	/* __KERNEL__ */

#endif /*_IP_SET_H */
