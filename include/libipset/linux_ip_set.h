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

#endif /* __IP_SET_H */
