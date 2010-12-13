/* Copyright 2000-2002 Joakim Axelsson (gozem@linux.nu)
 *                     Patrick Schaaf (bof@bof.de)
 * Copyright 2003-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#include <ctype.h>			/* isspace */
#include <stdarg.h>			/* va_* */
#include <stdbool.h>			/* bool */
#include <stdio.h>			/* fprintf, fgets */
#include <stdlib.h>			/* exit */
#include <string.h>			/* str* */

#include <config.h>

#include <libipset/debug.h>		/* D() */
#include <libipset/parse.h>		/* ipset_parse_* */
#include <libipset/session.h>		/* ipset_session_* */
#include <libipset/types.h>		/* struct ipset_type */
#include <libipset/ui.h>		/* core options, commands */
#include <libipset/utils.h>		/* STREQ */

static char program_name[] = PACKAGE;
static char program_version[] = PACKAGE_VERSION;

static struct ipset_session *session = NULL;
static uint32_t restore_line = 0;
static bool interactive = false;
static char cmdline[1024];
static char *newargv[255];
static int newargc = 0;

/* The known set types: (typename, revision, family) is unique */
extern struct ipset_type ipset_bitmap_ip0;
extern struct ipset_type ipset_bitmap_ipmac0;
extern struct ipset_type ipset_bitmap_port0;
extern struct ipset_type ipset_hash_ip0;
extern struct ipset_type ipset_hash_net0;
extern struct ipset_type ipset_hash_netport0;
extern struct ipset_type ipset_hash_ipport0;
extern struct ipset_type ipset_hash_ipportip0;
extern struct ipset_type ipset_hash_ipportnet0;
extern struct ipset_type ipset_list_set0;

enum exittype {
	NO_PROBLEM = 0,
	OTHER_PROBLEM,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM,
	SESSION_PROBLEM,
};

static int __attribute__((format(printf,2,3)))
exit_error(int status, const char *msg, ...)
{
	bool quiet = !interactive
		     && session
		     && ipset_envopt_test(session, IPSET_ENV_QUIET);

	if (status && msg && !quiet) {
		va_list args;

		fprintf(stderr, "%s v%s: ", program_name, program_version);
		va_start(args, msg);
		vfprintf(stderr, msg, args);
		va_end(args);
		if (status != SESSION_PROBLEM)
			fprintf(stderr, "\n");

		if (status == PARAMETER_PROBLEM)
			fprintf(stderr,
				"Try `%s help' for more information.\n",
				program_name);
	}
	/* Ignore errors in interactive mode */
	if (status && interactive) {
		if (session)
			ipset_session_report_reset(session);
		return -1;
	}

	if (session)
		ipset_session_fini(session);

	D("status: %u", status);
	exit(status > VERSION_PROBLEM ? OTHER_PROBLEM : status);
	/* Unreached */
	return -1;
}

static int
handle_error(void)
{
	if (ipset_session_warning(session)
	    && !ipset_envopt_test(session, IPSET_ENV_QUIET))
		fprintf(stderr, "Warning: %s\n",
			ipset_session_warning(session));
	if (ipset_session_error(session))
		return exit_error(SESSION_PROBLEM, "%s",
				  ipset_session_error(session));

	if (!interactive) {
		ipset_session_fini(session);
		exit(OTHER_PROBLEM);
	}

	ipset_session_report_reset(session);	
	return -1;
}

static void
help(void)
{
	const struct ipset_commands *c;
	const struct ipset_envopts *opt = ipset_envopts;
	
	printf("%s v%s\n\n"
	       "Usage: %s [options] COMMAND\n\nCommands:\n",
	       program_name, program_version, program_name);

	for (c = ipset_commands; c->cmd; c++) {
		printf("%s %s\n", c->name[0], c->help);
	}
	printf("\nOptions:\n");
	
	while (opt->flag) {
		if (opt->help)
			printf("%s %s\n", opt->name[0], opt->help);
		opt++;
	}
}

/* Build faked argv from parsed line */
static void
build_argv(char *buffer)
{
	char *ptr;
	int i;

	/* Reset */	
	for (i = 1; i < newargc; i++)
		newargv[i] = NULL;
	newargc = 1;

	ptr = strtok(buffer, " \t\n");
	newargv[newargc++] = ptr;
	while ((ptr = strtok(NULL, " \t\n")) != NULL) {
		if ((newargc + 1) < (int)(sizeof(newargv)/sizeof(char *)))
			newargv[newargc++] = ptr;
		else {
			exit_error(PARAMETER_PROBLEM,
				   "Line is too long to parse.");
			return;
		}
	}
}

/* Main parser function, workhorse */
int parse_commandline(int argc, char *argv[]);

/*
 * Performs a restore from stdin
 */
static int
restore(char *argv0)
{
	int ret = 0;
	char *c;
	
	/* Initialize newargv/newargc */
	newargc = 0;
	newargv[newargc++] = argv0;

	while (fgets(cmdline, sizeof(cmdline), stdin)) {
		restore_line++;
		c = cmdline;
		while (isspace(c[0]))
			c++;
		if (c[0] == '\0' || c[0] == '#')
			continue;
		else if (strcmp(c, "COMMIT\n") == 0) {
			ret = ipset_commit(session);
			if (ret < 0)
				handle_error();
			continue;
		}
		/* Build faked argv, argc */
		build_argv(c);
		
		/* Execute line */
		ret = parse_commandline(newargc, newargv);
		if (ret < 0)
			handle_error();
	}
	/* implicit "COMMIT" at EOF */
	ret = ipset_commit(session);
	if (ret < 0)
		handle_error();

	return ret;
}

static int
call_parser(int *argc, char *argv[], const struct ipset_arg *args)
{
	int i = 1, ret = 0;
	const struct ipset_arg *arg;
	const char *optstr;
	
	/* Currently CREATE and ADT may have got additional arguments */
	if (!args)
		goto done;
	for (arg = args; arg->opt; arg++) {
		for (i = 1; i < *argc; ) {
			D("argc: %u, i: %u: %s vs %s",
			  *argc, i, argv[i], arg->name[0]);
			if (!(ipset_match_option(argv[i], arg->name))) {
				i++;
				continue;
			}
			optstr = argv[i];
			/* Shift off matched option */
			D("match %s", arg->name[0]);
			ipset_shift_argv(argc, argv, i);
			D("argc: %u, i: %u", *argc, i);
			switch (arg->has_arg) {
			case IPSET_MANDATORY_ARG:
				if (i + 1 > *argc)
					return exit_error(PARAMETER_PROBLEM,
						"Missing mandatory argument "
						"of option `%s'",
						arg->name[0]);
				/* Fall through */
			case IPSET_OPTIONAL_ARG:
				if (i + 1 <= *argc) {
					ret = ipset_call_parser(session,
							arg->parse,
							optstr, arg->opt,
							argv[i]);
					if (ret < 0)
						return ret;
					ipset_shift_argv(argc, argv, i);
					break;
				}
				/* Fall through */
			default:
				ret = ipset_call_parser(session,
							arg->parse,
							optstr, arg->opt,
							optstr);
				if (ret < 0)
					return ret;
			}
		}
	}
done:
	if (i < *argc)
		return exit_error(PARAMETER_PROBLEM,
				  "Unknown argument: `%s'",
				  argv[i]);
	return ret;
}

static void
check_mandatory(const struct ipset_type *type, int cmd)
{
	uint64_t flags = ipset_data_flags(ipset_session_data(session));
	uint64_t mandatory = type->mandatory[cmd];
	const struct ipset_arg *arg = type->args[cmd];

	/* Range can be expressed by ip/cidr */
	if (flags & IPSET_FLAG(IPSET_OPT_CIDR))
		flags |= IPSET_FLAG(IPSET_OPT_IP_TO);

	mandatory &= ~flags;
	if (!mandatory)
		return;
	if (!arg) {
		exit_error(OTHER_PROBLEM,
			"There are missing mandatory flags "
			"but can't check them. "
			"It's a bug, please report the problem.");
		return;
	}

	for (; arg->opt; arg++)
		if (mandatory & IPSET_FLAG(arg->opt)) {
			exit_error(PARAMETER_PROBLEM,
				   "Mandatory option `%s' is missing",
				   arg->name[0]);
			return;
		}
}

static const struct ipset_type *
type_find(const char *name)
{
	const struct ipset_type *t = ipset_types();
	
	while (t) {
		if (ipset_match_typename(name, t))
			return t;
		t = t->next;
	}
	return NULL;
}

static inline int cmd2cmd(int cmd)
{
	switch(cmd) {
	case IPSET_CMD_ADD:
		return IPSET_ADD;
	case IPSET_CMD_DEL:
		return IPSET_DEL;
	case IPSET_CMD_TEST:
		return IPSET_TEST;
	case IPSET_CMD_CREATE:
		return IPSET_CREATE;
	default:
		return 0;
	}
}

/* Workhorse */
int
parse_commandline(int argc, char *argv[])
{
	int ret = 0;
	enum ipset_cmd cmd = IPSET_CMD_NONE;
	int i;
	char *arg0 = NULL, *arg1 = NULL, *c;
	const struct ipset_envopts *opt;
	const struct ipset_commands *command;
	const struct ipset_type *type;

	/* Initialize session */
	if (session == NULL) {
		session = ipset_session_init(printf);
		if (session == NULL)
			return exit_error(OTHER_PROBLEM,
				"Cannot initialize ipset session, aborting.");
	}

	/* Commandline parsing, somewhat similar to that of 'ip' */

	/* First: parse core options */
	for (opt = ipset_envopts; opt->flag; opt++) {
		for (i = 1; i < argc; ) {
			if (!ipset_match_envopt(argv[i], opt->name)) {
				i++;
				continue;
			}
			/* Shift off matched option */
			ipset_shift_argv(&argc, argv, i);
			switch (opt->has_arg) {
			case IPSET_MANDATORY_ARG:
				if (i + 1 > argc)
					return exit_error(PARAMETER_PROBLEM,
						"Missing mandatory argument "
						"to option %s",
						opt->name[0]);
				/* Fall through */
			case IPSET_OPTIONAL_ARG:
				if (i + 1 <= argc) {
					ret = opt->parse(session, opt->flag,
							 argv[i]);
					if (ret < 0)
						return handle_error();
					ipset_shift_argv(&argc, argv, i);
				}
				break;
			case IPSET_NO_ARG:
				ret = opt->parse(session, opt->flag,
						 opt->name[0]);
				if (ret < 0)
					return handle_error();
				break;
			default:
				break;
			}
		}
	}

	/* Second: parse command */
	for (command = ipset_commands;
	     command->cmd && cmd == IPSET_CMD_NONE;
	     command++) {
		for (i = 1; i < argc; ) {
			if (!ipset_match_cmd(argv[1], command->name)) {
				i++;
				continue;
			}
			if (restore_line != 0
			    && (command->cmd == IPSET_CMD_RESTORE
			    	|| command->cmd == IPSET_CMD_VERSION
			    	|| command->cmd == IPSET_CMD_HELP))
				return exit_error(PARAMETER_PROBLEM,
					"Command `%s' is invalid "
					"in restore mode.",
					command->name[0]);
				if (interactive
				    && command->cmd == IPSET_CMD_RESTORE) {
					printf("Restore command ignored "
					       "in interactive mode\n");
				return 0;
			}

			/* Shift off matched command arg */
			ipset_shift_argv(&argc, argv, i);
			cmd = command->cmd;
			switch (command->has_arg) {
			case IPSET_MANDATORY_ARG:
			case IPSET_MANDATORY_ARG2:
				if (i + 1 > argc)
					return exit_error(PARAMETER_PROBLEM,
						"Missing mandatory argument "
						"to command %s",
						command->name[0]);
				/* Fall through */
			case IPSET_OPTIONAL_ARG:
				arg0 = argv[i];
				if (i + 1 <= argc)
					/* Shift off first arg */
					ipset_shift_argv(&argc, argv, i);
				break;
			default:
				break;
			}
			if (command->has_arg == IPSET_MANDATORY_ARG2) {
				if (i + 1 > argc)
					return exit_error(PARAMETER_PROBLEM,
						"Missing second mandatory "
						"argument to command %s",
						command->name[0]);
				arg1 = argv[i];
				/* Shift off second arg */
				ipset_shift_argv(&argc, argv, i);
			}
			break;
		}
	}

	/* Third: catch interactive mode, handle help, version */
	switch (cmd) {
	case IPSET_CMD_NONE:
		if (interactive) {
			printf("No command specified\n");
			return 0;
		}
		if (argc > 1 && STREQ(argv[1], "-")) {
			interactive = true;
			printf("%s> ", program_name);
			/* Initialize newargv/newargc */
			newargv[newargc++] = program_name;
			while (fgets(cmdline, sizeof(cmdline), stdin)) {
				c = cmdline;
				while (isspace(c[0]))
					c++;
				if (c[0] == '\0' || c[0] == '#')
					continue;
				/* Build fake argv, argc */
				build_argv(c);
				/* Execute line: ignore errors */
				parse_commandline(newargc, newargv);
				printf("%s> ", program_name);
			}
			return exit_error(NO_PROBLEM, NULL);
		}
		if (argc > 1)
			return exit_error(PARAMETER_PROBLEM,
				"No command specified: unknown argument %s",
				argv[1]);
		return exit_error(PARAMETER_PROBLEM, "No command specified.");
	case IPSET_CMD_VERSION:
		printf("%s v%s.\n", program_name, program_version);
		if (interactive)
			return 0;
		return exit_error(NO_PROBLEM, NULL);
	case IPSET_CMD_HELP:
		help();

		if (interactive
		    || !ipset_envopt_test(session, IPSET_ENV_QUIET)) {
		    	if (arg0) {
				/* Type-specific help, without kernel checking */
				type = type_find(arg0);
				if (!type)
					return exit_error(PARAMETER_PROBLEM,
						"Unknown settype: `%s'", arg0);
				printf("\n%s type specific options:\n\n%s",
				       type->name, type->usage);
				if (type->usagefn)
					type->usagefn();
				if (type->family == AF_UNSPEC)
					printf("\nType %s is family neutral.\n",
					       type->name);
				else if (type->family == AF_INET46)
					printf("\nType %s supports INET "
					       "and INET6.\n",
					       type->name);
				else
					printf("\nType %s supports family "
					       "%s only.\n",
					       type->name,
					       type->family == AF_INET
						? "INET" : "INET6");
			} else {
				printf("\nSupported set types:\n");
				type = ipset_types();
				while (type) {
					printf("    %s\n", type->name);
					type = type->next;
				}
			} 
		}
		if (interactive)
			return 0;
		return exit_error(NO_PROBLEM, NULL);
	case IPSET_CMD_QUIT:
		return exit_error(NO_PROBLEM, NULL);
	default:
		break;
	}
	
	/* Forth: parse command args and issue the command */
	switch (cmd) {
	case IPSET_CMD_CREATE:
		/* Args: setname typename [type specific options] */
		ret = ipset_parse_setname(session, IPSET_SETNAME, arg0);
		if (ret < 0)
			return handle_error();

		ret = ipset_parse_typename(session, IPSET_OPT_TYPENAME, arg1);
		if (ret < 0)
			return handle_error();

		type = ipset_type_get(session, cmd);
		if (type == NULL)
			return handle_error();

		/* Parse create options */
		ret = call_parser(&argc, argv, type->args[IPSET_CREATE]);
		if (ret < 0)
			return handle_error();
		else if (ret)
			return ret;
		
		/* Check mandatory options */
		check_mandatory(type, IPSET_CREATE);
		
		break;
	case IPSET_CMD_DESTROY:
	case IPSET_CMD_FLUSH:
	case IPSET_CMD_LIST:
	case IPSET_CMD_SAVE:
		/* Args: [setname] */
		if (arg0) {
			ret = ipset_parse_setname(session,
						  IPSET_SETNAME, arg0);
			if (ret < 0)
				return handle_error();
		}
		break;

	case IPSET_CMD_RENAME:
	case IPSET_CMD_SWAP:
		/* Args: from-setname to-setname */
		ret = ipset_parse_setname(session, IPSET_SETNAME, arg0);
		if (ret < 0)
			return handle_error();
		ret = ipset_parse_setname(session, IPSET_OPT_SETNAME2, arg1);
		if (ret < 0)
			return handle_error();
		break;

	case IPSET_CMD_RESTORE:
		/* Restore mode */
		if (argc > 1)
			return exit_error(PARAMETER_PROBLEM,
				"Unknown argument %s", argv[1]);
		return restore(argv[0]);
	case IPSET_CMD_ADD:
	case IPSET_CMD_DEL:
	case IPSET_CMD_TEST:
		D("ADT: setname %s", arg0);
		/* Args: setname ip [options] */
		ret = ipset_parse_setname(session, IPSET_SETNAME, arg0);
		if (ret < 0)
			return handle_error();

		type = ipset_type_get(session, cmd);
		if (type == NULL)
			return handle_error();
		
		ret = ipset_parse_elem(session, type->last_elem_optional, arg1);
		if (ret < 0)
			return handle_error();
		
		/* Parse additional ADT options */
		ret = call_parser(&argc, argv, type->args[cmd2cmd(cmd)]);
		if (ret < 0)
			return handle_error();
		else if (ret)
			return ret;
		
		/* Check mandatory options */
		check_mandatory(type, cmd2cmd(cmd));
		
		break;
	default:
		break;
	}

	if (argc > 1)
		return exit_error(PARAMETER_PROBLEM,
			"Unknown argument %s", argv[1]);
	ret = ipset_cmd(session, cmd, restore_line);
	D("ret %d", ret);
	/* Special case for TEST and non-quiet mode */
	if (cmd == IPSET_CMD_TEST && ipset_session_warning(session)) {
		if (!ipset_envopt_test(session, IPSET_ENV_QUIET))
			fprintf(stderr, "%s", ipset_session_warning(session));
		ipset_session_report_reset(session);
	}
	if (ret < 0)
		handle_error();

	return ret;
}

int
main(int argc, char *argv[])
{
	/* Register types */
	ipset_type_add(&ipset_bitmap_ip0);
	ipset_type_add(&ipset_bitmap_ipmac0);
	ipset_type_add(&ipset_bitmap_port0);
	ipset_type_add(&ipset_hash_ip0);
	ipset_type_add(&ipset_hash_net0);
	ipset_type_add(&ipset_hash_netport0);
	ipset_type_add(&ipset_hash_ipport0);
	ipset_type_add(&ipset_hash_ipportip0);
	ipset_type_add(&ipset_hash_ipportnet0);
	ipset_type_add(&ipset_list_set0);

	return parse_commandline(argc, argv);
}
