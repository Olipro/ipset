/* Copyright 2004 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License as published by   
 * the Free Software Foundation; either version 2 of the License, or      
 * (at your option) any later version.                                    
 *                                                                         
 * This program is distributed in the hope that it will be useful,        
 * but WITHOUT ANY WARRANTY; without even the implied warranty of         
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          
 * GNU General Public License for more details.                           
 *                                                                         
 * You should have received a copy of the GNU General Public License      
 * along with this program; if not, write to the Free Software            
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */


#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/bitops.h>

#include <linux/netfilter_ipv4/ip_set_portmap.h>
#include "ipset.h"


#define BUFLEN 30;

#define OPT_CREATE_FROM    0x01U
#define OPT_CREATE_TO      0x02U

#define OPT_ADDDEL_PORT      0x01U

/* Initialize the create. */
void create_init(void *data)
{
	DP("create INIT");
	/* Nothing */
}

/* Function which parses command options; returns true if it ate an option */
int create_parse(int c, char *argv[], void *data, unsigned *flags)
{
	struct ip_set_req_portmap_create *mydata =
	    (struct ip_set_req_portmap_create *) data;

	DP("create_parse");

	switch (c) {
	case '1':
		parse_port(optarg, &mydata->from);

		*flags |= OPT_CREATE_FROM;

		DP("--from %x (%s)", mydata->from,
		   port_tostring(mydata->from, 0));

		break;

	case '2':
		parse_port(optarg, &mydata->to);

		*flags |= OPT_CREATE_TO;

		DP("--to %x (%s)", mydata->to,
		   port_tostring(mydata->to, 0));

		break;

	default:
		return 0;
	}

	return 1;
}

/* Final check; exit if not ok. */
void create_final(void *data, unsigned int flags)
{
	struct ip_set_req_portmap_create *mydata =
	    (struct ip_set_req_portmap_create *) data;

	if (flags == 0) {
		exit_error(PARAMETER_PROBLEM,
			   "Need to specify --from and --to\n");
	} else {
		/* --from --to */
		if ((flags & OPT_CREATE_FROM) == 0
		    || (flags & OPT_CREATE_TO) == 0)
			exit_error(PARAMETER_PROBLEM,
				   "Need to specify both --from and --to\n");
	}

	DP("from : %x to: %x  diff: %d", mydata->from, mydata->to,
	   mydata->to - mydata->from);

	if (mydata->from > mydata->to)
		exit_error(PARAMETER_PROBLEM,
			   "From can't be lower than to.\n", MAX_RANGE);

	if (mydata->to - mydata->from > MAX_RANGE)
		exit_error(PARAMETER_PROBLEM,
			   "Range to large. Max is %d ports in range\n",
			   MAX_RANGE);
}

/* Create commandline options */
static struct option create_opts[] = {
	{"from", 1, 0, '1'},
	{"to", 1, 0, '2'},
	{0}
};

/* Add, del, test parser */
ip_set_ip_t adt_parser(int cmd, const char *optarg,
		       void *data, const void *setdata)
{
	struct ip_set_req_portmap *mydata =
	    (struct ip_set_req_portmap *) data;
	struct ip_set_portmap *mysetdata =
	    (struct ip_set_portmap *) setdata;

	DP("portmap: %p %p", data, setdata);

	parse_port(optarg, &mydata->port);

	DP("from %s", port_tostring(mysetdata->first_port, 0));
	DP("to   %s", port_tostring(mysetdata->last_port, 0));
	DP("port %s", port_tostring(mydata->port, 0));

	if (mydata->port < mysetdata->first_port ||
	    mydata->port > mysetdata->last_port)
		exit_error(PARAMETER_PROBLEM, "Port '%s' is out of range\n",
			   port_tostring(mydata->port, 0));

	return mydata->port;	
}

ip_set_ip_t getportbyid(const void *setdata, ip_set_ip_t id)
{
	struct ip_set_portmap *mysetdata =
	    (struct ip_set_portmap *) setdata;

	return (mysetdata->first_port + id);
}

ip_set_ip_t sizeid(const void *setdata)
{
	struct ip_set_portmap *mysetdata =
	    (struct ip_set_portmap *) setdata;

	return (mysetdata->last_port - mysetdata->first_port + 1);
}

void initheader(void **setdata, void *data, size_t len)
{
	struct ip_set_req_portmap_create *header =
	    (struct ip_set_req_portmap_create *) data;

	DP("portmap: initheader() 1");

	if (len != sizeof(struct ip_set_req_portmap_create))
		exit_error(OTHER_PROBLEM,
			   "Portmap: incorrect size of header. "
			   "Got %d, wanted %d.", len,
			   sizeof(struct ip_set_req_portmap_create));

	*setdata = ipset_malloc(sizeof(struct ip_set_portmap));

	DP("portmap: initheader() 2");

	((struct ip_set_portmap *) *setdata)->first_port =
	    header->from;
	((struct ip_set_portmap *) *setdata)->last_port = header->to;

}

void initmembers(void *setdata, void *data, size_t len)
{
	struct ip_set_portmap *mysetdata =
	    (struct ip_set_portmap *) setdata;
	size_t size;

	DP("portmap: initmembers()");

	/* Check so we get the right amount of memberdata */
	size = bitmap_bytes(mysetdata->first_port, mysetdata->last_port);

	if (len != size)
		exit_error(OTHER_PROBLEM,
			   "Portmap: incorrect size of members. "
			   "Got %d, wanted %d.", len, size);

	mysetdata->members = data;
}

void killmembers(void **setdata)
{
	struct ip_set_portmap *mysetdata =
	    (struct ip_set_portmap *) *setdata;

	DP("portmap: killmembers()");

	if (mysetdata->members != NULL)
		ipset_free(&mysetdata->members);
	
	ipset_free(setdata);
}


void printheader(const void *setdata, unsigned options)
{
	struct ip_set_portmap *mysetdata =
	    (struct ip_set_portmap *) setdata;

	printf(" from: %s", port_tostring(mysetdata->first_port, options));
	printf(" to: %s\n", port_tostring(mysetdata->last_port, options));
}

void printports_sorted(const void *setdata, unsigned options)
{
	struct ip_set_portmap *mysetdata =
	    (struct ip_set_portmap *) setdata;

	u_int32_t addr = mysetdata->first_port;

	while (addr <= mysetdata->last_port) {
		if (test_bit(addr - mysetdata->first_port, mysetdata->members))
			printf("%s\n", port_tostring(addr, options));
		addr++;
	}
}

void saveheader(const void *setdata)
{
	return;
}

/* Print save for an IP */
void saveports(const void *setdata)
{
	return;
}

void usage(void)
{
	printf
	    ("-N set portmap --from PORT --to PORT\n"
	     "-A set PORT\n"
	     "-D set PORT\n"
	     "-T set PORT\n");
}

static struct settype settype_portmap = {
	.typename = SETTYPE_NAME,
	.typecode = IPSET_TYPE_PORT,
	.protocol_version = IP_SET_PROTOCOL_VERSION,

	/* Create */
	.create_size = sizeof(struct ip_set_req_portmap_create),
	.create_init = &create_init,
	.create_parse = &create_parse,
	.create_final = &create_final,
	.create_opts = create_opts,

	/* Add/del/test */
	.req_size = sizeof(struct ip_set_req_portmap),
	.adt_parser = &adt_parser,

	/* Get an IP address by id */
	.getipbyid = &getportbyid,
	.sizeid = &sizeid,

	/* Printing */
	.initheader = &initheader,
	.initmembers = &initmembers,
	.killmembers = &killmembers,
	.printheader = &printheader,
	.printips = &printports_sorted,	/* We only have sorted version */
	.printips_sorted = &printports_sorted,
	.saveheader = &saveheader,
	.saveips = &saveports,
	.usage = &usage,
	.hint = NULL,
};

void _init(void)
{
	settype_register(&settype_portmap);

}
