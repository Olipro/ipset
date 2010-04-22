/* Copyright 2007-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#ifndef LIBIPSET_UI_H
#define LIBIPSET_UI_H

/* Commands in userspace */
struct ipset_commands {
	const char *name[6];
	const char *help;
	int has_arg;
};

extern const struct ipset_commands ipset_commands[];

/* Environment option flags */
enum ipset_envopt {
	IPSET_ENV_BIT_SORTED	= 0,
	IPSET_ENV_SORTED	= (1 << IPSET_ENV_BIT_SORTED),
	IPSET_ENV_BIT_QUIET	= 1,
	IPSET_ENV_QUIET		= (1 << IPSET_ENV_BIT_QUIET),
	IPSET_ENV_BIT_RESOLVE	= 2,
	IPSET_ENV_RESOLVE	= (1 << IPSET_ENV_BIT_RESOLVE),
	IPSET_ENV_BIT_EXIST	= 3,
	IPSET_ENV_EXIST		= (1 << IPSET_ENV_BIT_EXIST),
};

struct ipset_session;
struct ipset_data;

/* Environment options */
struct ipset_envopts {
	int flag;
	int has_arg;
	const char *name[3];
	const char *help;
	int (*parse)(struct ipset_session *s, int flag, const char *str);
	int (*print)(char *buf, unsigned int len,
		     const struct ipset_data *data, int flag, uint8_t env);
};

extern const struct ipset_envopts ipset_envopts[];

#endif /* LIBIPSET_UI_H */
