/* Copyright 2007-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#include <libipset/linux_ip_set.h>		/* IPSET_CMD_* */
#include <libipset/types.h>			/* IPSET_*_ARG */
#include <libipset/session.h>			/* ipset_envopt_parse */
#include <libipset/parse.h>			/* ipset_parse_family */
#include <libipset/print.h>			/* ipset_print_family */
#include <libipset/ui.h>			/* prototypes */

/* Commands and environment options */

const struct ipset_commands ipset_commands[] = {
	[IPSET_CMD_CREATE - 1] = {
		.name = { "create", "c",  "-N", "--create", NULL },
		.has_arg = IPSET_MANDATORY_ARG2,
		.help = "SETNAME TYPENAME [type-specific-options]\n"
			"        Create a new set",
	},
	[IPSET_CMD_DESTROY - 1] = {
		.name = { "destroy", "x", "-X", "--destroy", NULL },
		.has_arg = IPSET_OPTIONAL_ARG,
		.help = "[SETNAME]\n"
		        "        Destroy a named set or all sets",
	},
	[IPSET_CMD_FLUSH - 1] = {
		.name = { "flush", "f",   "-F", "--flush", NULL },
		.has_arg = IPSET_OPTIONAL_ARG,
		.help = "[SETNAME]\n"
		        "        Flush a named set or all sets",
	},
	[IPSET_CMD_RENAME - 1] = {
		.name = { "rename", "e",  "-E", "--rename", NULL },
		.has_arg = IPSET_MANDATORY_ARG2,
		.help = "FROM-SETNAME TO-SETNAME\n"
		        "        Rename two sets",
	},
	[IPSET_CMD_SWAP - 1] = {
		.name = { "swap", "w",    "-W", "--swap", NULL },
		.has_arg = IPSET_MANDATORY_ARG2,
		.help = "FROM-SETNAME TO-SETNAME\n"
		        "        Swap the contect of two existing sets",
	},
	[IPSET_CMD_LIST - 1] = {
		.name = { "list", "l",    "-L", "--list", NULL },
		.has_arg = IPSET_OPTIONAL_ARG,
		.help = "[SETNAME]\n"
		        "        List the entries of a named set or all sets",
	},
	[IPSET_CMD_SAVE - 1] = {
		.name = { "save", "s",    "-S", "--save", NULL },
		.has_arg = IPSET_OPTIONAL_ARG,
		.help = "[SETNAME]\n"
		        "        Save the named set or all sets to stdout",
	},
	[IPSET_CMD_ADD - 1] = {
		.name = { "add", "a",     "-A", "--add", NULL },
		.has_arg = IPSET_MANDATORY_ARG2,
		.help = "SETNAME ENTRY\n"
		        "        Add entry to a named set",
	},
	[IPSET_CMD_DEL - 1] = {
		.name = { "del", "d",     "-D", "--del", NULL },
		.has_arg = IPSET_MANDATORY_ARG2,
		.help = "SETNAME ENTRY\n"
		        "        Delete entry from a named set",
	},
	[IPSET_CMD_TEST - 1] = {
		.name = { "test", "t",    "-T", "--test", NULL },
		.has_arg = IPSET_MANDATORY_ARG2,
		.help = "SETNAME ENTRY\n"
		        "        Test if entry exists in the named set",
	},
	[IPSET_CMD_HELP - 1] = {
		.name = { "help", "h",    "-H", "-h", "--help", NULL },
		.has_arg = IPSET_OPTIONAL_ARG,
		.help = "[TYPENAME]\n"
		        "        Print help, and settype specific help",
	},
	[IPSET_CMD_RESTORE - 1] = {
		.name = { "restore", "r", "-R", "--restore", NULL },
		.has_arg = IPSET_NO_ARG,
		.help = "\n"
		        "        Restore a saved state",
	},
	[IPSET_CMD_VERSION - 1] = {
		.name = { "version", "v", "-V", "-v", "--version", NULL },
		.has_arg = IPSET_NO_ARG,
		.help = "\n"
		        "        Print version information",
	},
	[IPSET_CMD_MAX - 1] = { },
};

const struct ipset_envopts ipset_envopts[] = {
	{ .name = { "family", "--family", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.flag = IPSET_OPT_FAMILY,
	  .parse = ipset_parse_family,		.print = ipset_print_family,
	  .help = "inet|inet6\n"
	  	  "       Specify family when creating a set\n"
	  	  "       which supports multiple families.\n"
	  	  "       The default family is INET.",
	},
	{ .name = { "-o", "--output", NULL },
	  .has_arg = IPSET_MANDATORY_ARG,	.flag = IPSET_OPT_MAX,
	  .parse = ipset_parse_output,
	  .help = "plain|save|xml\n"
	  	  "       Specify output mode for listing sets.\n"
	  	  "       Default value for \"list\" command is mode \"plain\"\n"
	  	  "       and for \"save\" command is mode \"save\".",
	},
	{ .name = { "-s", "--sorted", NULL },
	  .parse = ipset_envopt_parse,
	  .has_arg = IPSET_NO_ARG,	.flag = IPSET_ENV_SORTED,
	  .help = "\n"
	          "        Print elements sorted (if supported by the set type).",
	},
	{ .name = { "-q", "--quiet", NULL },
	  .parse = ipset_envopt_parse,
	  .has_arg = IPSET_NO_ARG,	.flag = IPSET_ENV_QUIET,
	  .help = "\n"
	          "        Suppress any notice or warning message.",
	},
	{ .name = { "-r", "--resolve", NULL },
	  .parse = ipset_envopt_parse,
	  .has_arg = IPSET_NO_ARG,	.flag = IPSET_ENV_RESOLVE,
	  .help = "\n"
	          "        Try to resolve IP addresses in the output (slow!)",
	},
	{ .name = { "-x", "--exist", NULL },
	  .parse = ipset_envopt_parse,
	  .has_arg = IPSET_NO_ARG,	.flag = IPSET_ENV_EXIST,
	  .help = "\n"
	          "        Ignore errors when creating already created sets,\n"
	          "        when adding already existing elements\n"
		  "        or when deleting non-existing elements.",
	},
	/* Aliases */
	{ .name = { "-4", NULL },
	  .has_arg = IPSET_NO_ARG,		.flag = IPSET_OPT_FAMILY,
	  .parse = ipset_parse_family,
	},
	{ .name = { "-6", NULL },
	  .has_arg = IPSET_NO_ARG,		.flag = IPSET_OPT_FAMILY,
	  .parse = ipset_parse_family,
	},
	{ },
};
