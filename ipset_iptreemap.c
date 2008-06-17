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

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/netfilter_ipv4/ip_set_iptreemap.h>

#include "ipset.h"

#define OPT_CREATE_GC 0x1

void
create_init(void *data)
{
	struct ip_set_req_iptreemap_create *mydata = (struct ip_set_req_iptreemap_create *) data;

	mydata->gc_interval = 0;
}

int
create_parse(int c, char *argv[], void *data, unsigned int *flags)
{
	struct ip_set_req_iptreemap_create *mydata = (struct ip_set_req_iptreemap_create *) data;

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

void
create_final(void *data, unsigned int flags)
{
}

static struct option create_opts[] = {
	{"gc", 1, 0, 'g'},
	{0}
};

ip_set_ip_t
adt_parser(unsigned int cmd, const char *optarg, void *data)
{
	struct ip_set_req_iptreemap *mydata = (struct ip_set_req_iptreemap *) data;
	ip_set_ip_t mask;

	char *saved = ipset_strdup(optarg);
	char *ptr, *tmp = saved;

	if (strchr(tmp, '/')) {
		parse_ipandmask(tmp, &mydata->start, &mask);
		mydata->end = mydata->start | ~mask;
	} else {
		ptr = strsep(&tmp, ":");
		parse_ip(ptr, &mydata->start);

		if (tmp) {
			parse_ip(tmp, &mydata->end);
		} else {
			mydata->end = mydata->start;
		}
	}

	return 1;
}

void
initheader(struct set *set, const void *data)
{
	struct ip_set_req_iptreemap_create *header = (struct ip_set_req_iptreemap_create *) data;
	struct ip_set_iptreemap *map = (struct ip_set_iptreemap *) set->settype->header;

	map->gc_interval = header->gc_interval;
}

void
printheader(struct set *set, unsigned int options)
{
	struct ip_set_iptreemap *mysetdata = (struct ip_set_iptreemap *) set->settype->header;

	if (mysetdata->gc_interval)
		printf(" gc: %u", mysetdata->gc_interval);

	printf("\n");
}

void
printips_sorted(struct set *set, void *data, size_t len, unsigned int options)
{
	struct ip_set_req_iptreemap *req;
	size_t offset = 0;

	while (len >= offset + sizeof(struct ip_set_req_iptreemap)) {
		req = (struct ip_set_req_iptreemap *) (data + offset);

		printf("%s", ip_tostring(req->start, options));
		if (req->start != req->end)
			printf(":%s", ip_tostring(req->end, options));
		printf("\n");

		offset += sizeof(struct ip_set_req_iptreemap);
	}
}

void
saveheader(struct set *set, unsigned int options)
{
	struct ip_set_iptreemap *mysetdata = (struct ip_set_iptreemap *) set->settype->header;

	printf("-N %s %s", set->name, set->settype->typename);

	if (mysetdata->gc_interval)
		printf(" --gc %u", mysetdata->gc_interval);

	printf("\n");
}

void
saveips(struct set *set, void *data, size_t len, unsigned int options)
{
	struct ip_set_req_iptreemap *req;
	size_t offset = 0;

	while (len >= offset + sizeof(struct ip_set_req_iptreemap)) {
		req = (struct ip_set_req_iptreemap *) (data + offset);

		printf("-A %s %s", set->name, ip_tostring(req->start, options));

		if (req->start != req->end)
			printf(":%s", ip_tostring(req->end, options));

		printf("\n");

		offset += sizeof(struct ip_set_req_iptreemap);
	}
}

void
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

void
_init(void)
{
	settype_register(&settype_iptreemap);
}
