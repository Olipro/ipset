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
static const struct ipset_arg tree_ip_create_args[] = {
	{ .name = { "gc", "--gc", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_GC,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ .name = { "timeout", "--timeout", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_TIMEOUT,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ },
}; 

static const struct ipset_arg tree_ip_add_args[] = {
	{ .name = { "timeout", "--timeout", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_TIMEOUT,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ },
}; 

static const char tree_ip_usage[] =
"create SETNAME tree:ip\n"
"               [gc VALUE] [timeout VALUE]\n"
"add    SETNAME IP|IP/CIDR|FROM-TO [timeout VALUE]\n"
"del    SETNAME IP|IP/CIDR|FROM-TO\n"
"test   SETNAME IP\n";

struct ipset_type ipset_tree_ip0 = {
	.name = "tree:ip",
	.alias = "iptree",
	.revision = 0,
	.family = AF_INET,
	.dimension = IPSET_DIM_ONE,
	.elem = { 
		[IPSET_DIM_ONE] = { 
			.parse = ipset_parse_ip,
			.print = ipset_print_ip,
			.opt = IPSET_OPT_IP
		},
	},
	.args = {
		[IPSET_CREATE] = tree_ip_create_args,
		[IPSET_ADD] = tree_ip_add_args,
	},
	.mandatory = {
		[IPSET_CREATE] = 0,
		[IPSET_ADD] = IPSET_FLAG(IPSET_OPT_IP),
		[IPSET_DEL] = IPSET_FLAG(IPSET_OPT_IP),
		[IPSET_TEST] = IPSET_FLAG(IPSET_OPT_IP),
	},
	.full = {
		[IPSET_CREATE] = IPSET_FLAG(IPSET_OPT_GC)
			| IPSET_FLAG(IPSET_OPT_TIMEOUT),
		[IPSET_ADD] = IPSET_FLAG(IPSET_OPT_IP)
			| IPSET_FLAG(IPSET_OPT_IP_TO)
			| IPSET_FLAG(IPSET_OPT_TIMEOUT),
		[IPSET_DEL] = IPSET_FLAG(IPSET_OPT_IP)
			| IPSET_FLAG(IPSET_OPT_IP_TO),
		[IPSET_TEST] = IPSET_FLAG(IPSET_OPT_IP),
	},

	.usage = tree_ip_usage,
};
