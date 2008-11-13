/* Copyright 2007 Sven Wegener <sven.wegener@stealer.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <limits.h>			/* UINT_MAX */
#include <stdio.h>			/* *printf */
#include <string.h>			/* mem* */

#include "ipset.h"

#include <linux/netfilter_ipv4/ip_set_iptreemap.h>

#define OPT_CREATE_GC 0x1

static void
create_init(void *data)
{
	struct ip_set_req_iptreemap_create *mydata = data;

	mydata->gc_interval = 0;
}

static int
create_parse(int c, char *argv[] UNUSED, void *data, unsigned int *flags)
{
	struct ip_set_req_iptreemap_create *mydata = data;

	switch (c) {
		case 'g':
			string_to_number(optarg, 0, UINT_MAX, &mydata->gc_interval);

			*flags |= OPT_CREATE_GC;
		break;
		default:
			return 0;
		break;
	}

	return 1;
}

static void
create_final(void *data UNUSED, unsigned int flags UNUSED)
{
}

static const struct option create_opts[] = {
	{.name = "gc",	.has_arg = required_argument,	.val = 'g'},
	{0, 0, 0, 0},
};

static ip_set_ip_t
adt_parser(int cmd UNUSED, const char *arg, void *data)
{
	struct ip_set_req_iptreemap *mydata = data;
	ip_set_ip_t mask;

	char *saved = ipset_strdup(arg);
	char *ptr, *tmp = saved;

	if (strchr(tmp, '/')) {
		parse_ipandmask(tmp, &mydata->ip, &mask);
		mydata->end = mydata->ip | ~mask;
	} else {
		if ((ptr = strchr(tmp, ':')) != NULL && ++warn_once == 1)
			fprintf(stderr, "Warning: please use '-' separator token between IP range.\n"
			        "Next release won't support old separator token.\n");
		ptr = strsep(&tmp, "-:");
		parse_ip(ptr, &mydata->ip);

		if (tmp) {
			parse_ip(tmp, &mydata->end);
		} else {
			mydata->end = mydata->ip;
		}
	}

	ipset_free(saved);

	return 1;
}

static void
initheader(struct set *set, const void *data)
{
	const struct ip_set_req_iptreemap_create *header = data;
	struct ip_set_iptreemap *map = set->settype->header;

	map->gc_interval = header->gc_interval;
}

static void
printheader(struct set *set, unsigned int options UNUSED)
{
	struct ip_set_iptreemap *mysetdata = set->settype->header;

	if (mysetdata->gc_interval)
		printf(" gc: %u", mysetdata->gc_interval);

	printf("\n");
}

static void
printips_sorted(struct set *set UNUSED, void *data,
		size_t len, unsigned int options)
{
	struct ip_set_req_iptreemap *req;
	size_t offset = 0;

	while (len >= offset + sizeof(struct ip_set_req_iptreemap)) {
		req = data + offset;

		printf("%s", ip_tostring(req->ip, options));
		if (req->ip != req->end)
			printf("-%s", ip_tostring(req->end, options));
		printf("\n");

		offset += sizeof(struct ip_set_req_iptreemap);
	}
}

static void
saveheader(struct set *set, unsigned int options UNUSED)
{
	struct ip_set_iptreemap *mysetdata = set->settype->header;

	printf("-N %s %s", set->name, set->settype->typename);

	if (mysetdata->gc_interval)
		printf(" --gc %u", mysetdata->gc_interval);

	printf("\n");
}

static void
saveips(struct set *set UNUSED, void *data,
	size_t len, unsigned int options)
{
	struct ip_set_req_iptreemap *req;
	size_t offset = 0;

	while (len >= offset + sizeof(struct ip_set_req_iptreemap)) {
		req = data + offset;

		printf("-A %s %s", set->name, ip_tostring(req->ip, options));

		if (req->ip != req->end)
			printf("-%s", ip_tostring(req->end, options));

		printf("\n");

		offset += sizeof(struct ip_set_req_iptreemap);
	}
}

static void
usage(void)
{
	printf(
		"-N set iptreemap --gc interval\n"
		"-A set IP\n"
		"-D set IP\n"
		"-T set IP\n"
	);
}

static struct settype settype_iptreemap = {
	.typename = SETTYPE_NAME,
	.protocol_version = IP_SET_PROTOCOL_VERSION,

	.create_size = sizeof(struct ip_set_req_iptreemap_create),
	.create_init = &create_init,
	.create_parse = &create_parse,
	.create_final = &create_final,
	.create_opts = create_opts,

	.adt_size = sizeof(struct ip_set_req_iptreemap),
	.adt_parser = &adt_parser,

	.header_size = sizeof(struct ip_set_iptreemap),
	.initheader = &initheader,
	.printheader = &printheader,
	.printips = &printips_sorted,
	.printips_sorted = &printips_sorted,
	.saveheader = &saveheader,
	.saveips = &saveips,

	.bindip_tostring = &binding_ip_tostring,
	.bindip_parse = &parse_ip,

	.usage = &usage,
};

CONSTRUCTOR(iptreemap)
{
	settype_register(&settype_iptreemap);
}
