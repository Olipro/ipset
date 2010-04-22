/* Copyright 2007-2008 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#ifndef LIBIPSET_ERRCODE_H
#define LIBIPSET_ERRCODE_H

#include <libipset/linux_ip_set.h>		/* enum ipset_cmd */

struct ipset_session;

struct ipset_errcode_table {
	int errcode;
	enum ipset_cmd cmd;
	const char *message;
};

extern int ipset_errcode(struct ipset_session *session, enum ipset_cmd cmd,
			 int errcode);

#endif /* LIBIPSET_ERRCODE_H */
