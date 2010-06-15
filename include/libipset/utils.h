/* Copyright 2007-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#ifndef LIBIPSET_UTILS_H
#define LIBIPSET_UTILS_H

#include <string.h>				/* strcmp */
#include <netinet/in.h>				/* struct in[6]_addr */

/* String equality tests */
#define STREQ(a,b)		(strcmp(a,b) == 0)
#define STRNEQ(a,b,n)		(strncmp(a,b,n) == 0)

/* Stringify tokens */
#define _STR(c)			#c
#define STR(c)			_STR(c)

/* Min/max */
#define MIN(a, b)		(a < b ? a : b)
#define MAX(a, b)		(a > b ? a : b)

#define UNUSED			__attribute__ ((unused))

static inline void
in4cpy(struct in_addr *dest, const struct in_addr *src)
{
	dest->s_addr = src->s_addr;
}

static inline void
in6cpy(struct in6_addr *dest, const struct in6_addr *src)
{
	memcpy(dest, src, sizeof(struct in6_addr));
}

#endif	/* LIBIPSET_UTILS_H */
