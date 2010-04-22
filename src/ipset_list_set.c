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
static const struct ipset_arg list_set_create_args[] = {
	{ .name = { "size", "--size", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_MAXELEM,
	  .parse = ipset_parse_uint32,		.print = ipset_print_ip,
	},
	{ .name = { "timeout", "--timeout", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_TIMEOUT,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ },
}; 

static const struct ipset_arg list_set_add_args[] = {
	{ .name = { "timeout", "--timeout", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.opt = IPSET_OPT_TIMEOUT,
	  .parse = ipset_parse_uint32,		.print = ipset_print_number,
	},
	{ },
}; 

static const char list_set_usage[] =
"create SETNAME list:set\n"
"               [size VALUE] [timeout VALUE]\n"
"add    SETNAME NAME[,before|after,NAME] [timeout VALUE]\n"
"del    SETNAME NAME\n"
"test   SETNAME NAME\n";

struct ipset_type ipset_list_set0 = {
	.name = "list:set",
	.alias = "setlist",
	.revision = 0,
	.family = AF_UNSPEC,
	.dimension = IPSET_DIM_ONE,
	.elem = { 
		[IPSET_DIM_ONE] = { 
			.parse = ipset_parse_name,
			.print = ipset_print_name,
			.opt = IPSET_OPT_NAME
		},
	},
	.args = {
		[IPSET_CREATE] = list_set_create_args,
		[IPSET_ADD] = list_set_add_args,
	},
	.mandatory = {
		[IPSET_CREATE] = 0,
		[IPSET_ADD] = IPSET_FLAG(IPSET_OPT_NAME),
		[IPSET_DEL] = IPSET_FLAG(IPSET_OPT_NAME),
		[IPSET_TEST] = IPSET_FLAG(IPSET_OPT_NAME),
	},
	.full = {
		[IPSET_CREATE] = IPSET_FLAG(IPSET_OPT_SIZE)
			| IPSET_FLAG(IPSET_OPT_TIMEOUT),
		[IPSET_ADD] = IPSET_FLAG(IPSET_OPT_NAME)
			| IPSET_FLAG(IPSET_OPT_BEFORE)
			| IPSET_FLAG(IPSET_OPT_NAMEREF)
			| IPSET_FLAG(IPSET_OPT_TIMEOUT),
		[IPSET_DEL] = IPSET_FLAG(IPSET_OPT_NAME),
		[IPSET_TEST] = IPSET_FLAG(IPSET_OPT_NAME),
	},

	.usage = list_set_usage,
};
