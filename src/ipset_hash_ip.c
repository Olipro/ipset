/* Copyright 2007-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#include <libipset/data.h>			/* IPSET_OPT_* */
#include <libipset/parse.h>			/* parser functions */
#include <libipset/print.h>			/* printing functions */
#include <libipset/types.h>			/* prototypes */

/* Parse commandline arguments */
static const struct ipset_arg hash_ip_create_args[] = {
	{ .name = { "hashsize", "--hashsize", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_HASHSIZE,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ .name = { "maxelem", "--maxleme", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_MAXELEM,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ .name = { "probes", "--probes", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_PROBES,
	  .parse = ipset_parse_uint8,		.print = ipset_print_number,
	},
	{ .name = { "resize", "--resize", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_RESIZE,
	  .parse = ipset_parse_uint8,		.print = ipset_print_number,
	},
	{ .name = { "netmask", "--netmask", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_NETMASK,
	  .parse = ipset_parse_netmask,		.print = ipset_print_number,
	},
	{ .name = { "timeout", "--timeout", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_TIMEOUT,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ },
};

static const struct ipset_arg hash_ip_add_args[] = {
	{ .name = { "timeout", "--timeout", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_TIMEOUT,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ },
}; 

static const char hash_ip_usage[] =
"create SETNAME hash:ip\n"
"               [hashsize VALUE] [maxelem VALUE]\n"
"               [probes VALUE] [resize VALUE]\n"
"               [netmask CIDR] [timeout VALUE]\n"
"add    SETNAME IP|IP/CIDR|FROM-TO [timeout VALUE]\n"
"del    SETNAME IP|IP/CIDR|FROM-TO\n"
"test   SETNAME IP\n";

struct ipset_type ipset_hash_ip0 = {
	.name = "hash:ip",
	.alias = "iphash",
	.revision = 0,
	.family = AF_INET46,
	.dimension = IPSET_DIM_ONE,
	.elem = { 
		[IPSET_DIM_ONE] = { 
			.parse = ipset_parse_ip,
			.print = ipset_print_ip,
			.opt = IPSET_OPT_IP
		},
	},
	.args = {
		[IPSET_CREATE] = hash_ip_create_args,
		[IPSET_ADD] = hash_ip_add_args,
	},
	.mandatory = {
		[IPSET_CREATE] = 0,
		[IPSET_ADD] = IPSET_FLAG(IPSET_OPT_IP),
		[IPSET_DEL] = IPSET_FLAG(IPSET_OPT_IP),
		[IPSET_TEST] = IPSET_FLAG(IPSET_OPT_IP),
	},
	.full = {
		[IPSET_CREATE] = IPSET_FLAG(IPSET_OPT_HASHSIZE)
			| IPSET_FLAG(IPSET_OPT_MAXELEM)
			| IPSET_FLAG(IPSET_OPT_PROBES)
			| IPSET_FLAG(IPSET_OPT_RESIZE)
			| IPSET_FLAG(IPSET_OPT_NETMASK)
			| IPSET_FLAG(IPSET_OPT_TIMEOUT),
		[IPSET_ADD] = IPSET_FLAG(IPSET_OPT_IP)
			| IPSET_FLAG(IPSET_OPT_IP_TO)
			| IPSET_FLAG(IPSET_OPT_TIMEOUT),
		[IPSET_DEL] = IPSET_FLAG(IPSET_OPT_IP)
			| IPSET_FLAG(IPSET_OPT_IP_TO),
		[IPSET_TEST] = IPSET_FLAG(IPSET_OPT_IP),
	},

	.usage = hash_ip_usage,
};
