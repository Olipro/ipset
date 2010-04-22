/* Copyright 2007-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#ifndef LIBIPSET_TYPES_H
#define LIBIPSET_TYPES_H

#include <stdint.h>				/* uintxx_t */

#include <libipset/data.h>			/* enum ipset_opt */
#include <libipset/linux_ip_set.h>		/* IPSET_MAXNAMELEN */

#define AF_INET46		255

/* Family rules:
 * - AF_UNSPEC:	type is family-neutral
 * - AF_INET:	type supports IPv4 only
 * - AF_INET6:	type supports IPv6 only
 * - AF_INET46:	type supports both IPv4 and IPv6
 */

/* Set dimensions */
enum {
	IPSET_DIM_ONE,			/* foo */
	IPSET_DIM_TWO,			/* foo,bar */
	IPSET_DIM_THREE,		/* foo,bar,fie */
	IPSET_DIM_MAX,
};

/* Parser options */
enum {
	IPSET_NO_ARG = -1,
	IPSET_OPTIONAL_ARG,
	IPSET_MANDATORY_ARG,
	IPSET_MANDATORY_ARG2,
};

struct ipset_session;

typedef int (*ipset_parsefn)(struct ipset_session *s,
			     enum ipset_opt opt, const char *str);
typedef int (*ipset_printfn)(char *buf, unsigned int len,
			     const struct ipset_data *data, enum ipset_opt opt,
			     uint8_t env);

/* Parse and print type-specific arguments */
struct ipset_arg {
	const char *name[3];		/* option names */
	int has_arg;			/* mandatory/optional/no arg */
	enum ipset_opt opt;		/* argumentum type */
	ipset_parsefn parse;		/* parser function */
	ipset_printfn print;		/* printing function */
};

/* Type check against the kernel */
enum {
	IPSET_KERNEL_MISMATCH = -1,
	IPSET_KERNEL_CHECK_NEEDED,
	IPSET_KERNEL_OK,
};

/* Max sizes for aggregated ADD (and DEL) commands */
enum {
	IPSET_MAXSIZE_INET,
	IPSET_MAXSIZE_INET6,
	IPSET_MAXSIZE_MAX,
};

/* How element parts are parsed */
struct ipset_elem {
	ipset_parsefn parse;			/* elem parser function */
	ipset_printfn print;			/* elem print function */
	enum ipset_opt opt;			/* elem option */
};

/* The set types in userspace
 * we could collapse 'args' and 'mandatory' to two-element lists
 * but for the readability the full list is supported.
  */
struct ipset_type {
	char name[IPSET_MAXNAMELEN];			/* type name */
	char alias[IPSET_MAXNAMELEN];			/* name alias */
	uint8_t revision;				/* revision number */
	uint8_t family;					/* supported family */
	uint8_t dimension;				/* elem dimension */
	int8_t kernel_check;				/* kernel check */
	bool last_elem_optional;			/* last element optional */
	struct ipset_elem elem[IPSET_DIM_MAX];		/* parse elem */
	const struct ipset_arg *args[IPSET_CADT_MAX];	/* create/ADT args except elem */
	uint64_t mandatory[IPSET_CADT_MAX];		/* create/ADT mandatory flags */
	uint64_t full[IPSET_CADT_MAX];			/* full args flags */
	size_t maxsize[IPSET_MAXSIZE_MAX];		/* max sizes */
	const char *usage;				/* terse usage */

	struct ipset_type *next;
};

extern int ipset_cache_add(const char *name, const struct ipset_type *type);
extern int ipset_cache_del(const char *name);
extern int ipset_cache_rename(const char *from, const char *to);
extern int ipset_cache_swap(const char *from, const char *to);

extern const struct ipset_type * ipset_type_get(struct ipset_session *session,
						enum ipset_cmd cmd);
extern const struct ipset_type * ipset_type_check(struct ipset_session *session);

extern int ipset_type_add(struct ipset_type *type);
extern const struct ipset_type * ipset_types(void);
extern const char * ipset_typename_resolve(const char *str);

extern int ipset_types_init(void);
extern void ipset_types_fini(void);

/* The known set types: (typename, revision, family) is unique */
extern struct ipset_type ipset_bitmap_ip0;
extern struct ipset_type ipset_bitmap_ipmac0;
extern struct ipset_type ipset_bitmap_port0;
extern struct ipset_type ipset_hash_ip0;
extern struct ipset_type ipset_hash_net0;
extern struct ipset_type ipset_hash_ipport0;
extern struct ipset_type ipset_hash_ipportip0;
extern struct ipset_type ipset_hash_ipportnet0;
extern struct ipset_type ipset_tree_ip0;
extern struct ipset_type ipset_list_set0;

#endif /* LIBIPSET_TYPES_H */
