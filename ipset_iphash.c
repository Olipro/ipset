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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/bitops.h>
#include <asm/types.h>

#include <linux/netfilter_ipv4/ip_set_iphash.h>
#include <linux/netfilter_ipv4/ip_set_jhash.h>

#include "ipset.h"

#define BUFLEN 30;

#define OPT_CREATE_INITVAL    0x01U
#define OPT_CREATE_HASHSIZE   0x02U
#define OPT_CREATE_NETMASK    0x03U

#define OPT_HINT_TRY	      0x01U
#define OPT_HINT_NETMASK      0x02U

#define HINT_DEFAULT_TRY	8
#define HINT_DEFAULT_FACTOR	4

/* Initialize the create. */
void create_init(void *data)
{
	struct ip_set_req_iphash_create *mydata =
	    (struct ip_set_req_iphash_create *) data;

	DP("create INIT");
	
	mydata->initval = 0;
	mydata->netmask = 0xFFFFFFFF;
}

/* Function which parses command options; returns true if it ate an option */
int create_parse(int c, char *argv[], void *data, unsigned *flags)
{
	struct ip_set_req_iphash_create *mydata =
	    (struct ip_set_req_iphash_create *) data;
	char *end;
	unsigned int bits;

	DP("create_parse");

	switch (c) {
	case '1':
		errno = 0;
		mydata->initval = strtoul(optarg, &end, 0);
		if (*end == '\0' && end != optarg && errno != ERANGE) {

			*flags |= OPT_CREATE_INITVAL;

			DP("--initval 0x%x)", mydata->initval);
			break;
		}
		exit_error(PARAMETER_PROBLEM, "Invalid initval `%s' specified", optarg);
	case '2':

		if (string_to_number(optarg, 1, MAX_RANGE, &mydata->hashsize))
			exit_error(PARAMETER_PROBLEM, "Hashsize `%s' specified", optarg);

		*flags |= OPT_CREATE_HASHSIZE;

		DP("--hashsize %u", mydata->hashsize);
		
		break;

	case '3':

		if (string_to_number(optarg, 0, 32, &bits))
			exit_error(PARAMETER_PROBLEM, 
				  "Invalid netmask `%s' specified", optarg);
		
		if (bits != 0)
			mydata->netmask = 0xFFFFFFFF << (32 - bits);

		*flags |= OPT_CREATE_NETMASK;

		DP("--netmask %x", mydata->netmask);
		
		break;

	default:
		return 0;
	}

	return 1;
}

/* Final check; exit if not ok. */
void create_final(void *data, unsigned int flags)
{
	struct ip_set_req_iphash_create *mydata =
	    (struct ip_set_req_iphash_create *) data;

	if ((flags & OPT_CREATE_HASHSIZE) == 0)
		exit_error(PARAMETER_PROBLEM,
			   "Need to specify --hashsize\n");

	if (!mydata->initval) {
		srand(getpid() | time(NULL));
		mydata->initval = rand();
	}
	DP("initval: 0x%x hashsize %d", mydata->initval, mydata->hashsize);
}

/* Create commandline options */
static struct option create_opts[] = {
	{"initval", 1, 0, '1'},
	{"hashsize", 1, 0, '2'},
	{"netmask", 1, 0, '3'},
	{0}
};

/* Add, del, test parser */
ip_set_ip_t adt_parser(int cmd, const char *optarg, 
		       void *data, const void *setdata)
{
	struct ip_set_req_iphash *mydata =
	    (struct ip_set_req_iphash *) data;

	mydata->flags = 0;
	
	if (*optarg == '+') {
		if (cmd == ADT_ADD) {
			mydata->flags |= IPSET_ADD_OVERWRITE;
			optarg++;
		} else
			exit_error(PARAMETER_PROBLEM,
			   	   "The '!' overwrite flag can be used only "
			   	   "when adding an IP address to the set\n");
	}			
	parse_ip(optarg, &mydata->ip);

	return mydata->ip;	
};

ip_set_ip_t getipbyid(const void *setdata, ip_set_ip_t id)
{
	struct ip_set_iphash *mysetdata =
	    (struct ip_set_iphash *) setdata;

	return mysetdata->members[id];
}

ip_set_ip_t sizeid(const void *setdata)
{
	struct ip_set_iphash *mysetdata =
	    (struct ip_set_iphash *) setdata;

	return (mysetdata->hashsize);
}

void initheader(void **setdata, void *data, size_t len)
{
	struct ip_set_req_iphash_create *header =
	    (struct ip_set_req_iphash_create *) data;

	DP("iphash: initheader() 1");

	if (len != sizeof(struct ip_set_req_iphash_create))
		exit_error(OTHER_PROBLEM,
			   "Iphash: incorrect size of header. "
			   "Got %d, wanted %d.", len,
			   sizeof(struct ip_set_req_iphash_create));

	*setdata = ipset_malloc(sizeof(struct ip_set_iphash));

	DP("iphash: initheader() 2");

	((struct ip_set_iphash *) *setdata)->initval =
		header->initval;
	((struct ip_set_iphash *) *setdata)->hashsize =
		header->hashsize;
	((struct ip_set_iphash *) *setdata)->netmask =
		header->netmask;
}

void initmembers(void *setdata, void *data, size_t len)
{
	struct ip_set_iphash *mysetdata =
	    (struct ip_set_iphash *) setdata;
	size_t size;

	DP("iphash: initmembers()");

	/* Check so we get the right amount of memberdata */
	size = sizeof(ip_set_ip_t) * mysetdata->hashsize;

	if (len != size)
		exit_error(OTHER_PROBLEM,
			   "Iphash: incorrect size of members. "
			   "Got %d, wanted %d.", len, size);

	mysetdata->members = data;
}

void killmembers(void **setdata)
{
	struct ip_set_iphash *mysetdata =
	    (struct ip_set_iphash *) *setdata;

	DP("iphash: killmembers()");

	if (mysetdata->members != NULL)
		free(mysetdata->members);
		
	ipset_free(setdata);
}

unsigned int
mask_to_bits(ip_set_ip_t mask)
{
	unsigned int bits = 32;
	ip_set_ip_t maskaddr;
	
	if (mask == 0xFFFFFFFF)
		return bits;
	
	maskaddr = 0xFFFFFFFE;
	while (--bits >= 0 && maskaddr != mask)
		maskaddr <<= 1;
	
	return bits;
}
	
void printheader(const void *setdata, unsigned options)
{
	struct ip_set_iphash *mysetdata =
	    (struct ip_set_iphash *) setdata;

	printf(" initval: 0x%x", mysetdata->initval);
	printf(" hashsize: %d", mysetdata->hashsize);
	if (mysetdata->netmask == 0xFFFFFFFF)
		printf("\n");
	else
		printf(" netmask: %d\n", mask_to_bits(mysetdata->netmask));
}

void printips(const void *setdata, unsigned options)
{
	struct ip_set_iphash *mysetdata =
	    (struct ip_set_iphash *) setdata;
	ip_set_ip_t id;

	for (id = 0; id < mysetdata->hashsize; id++)
		if (mysetdata->members[id])
			printf("%s\n", ip_tostring(mysetdata->members[id], options));
}

void saveheader(const void *setdata)
{
	return;
}

/* Print save for an IP */
void saveips(const void *setdata)
{
	return;
}

void usage(void)
{
	printf
	    ("-N set iphash [--initval hash-initval] --hashsize hashsize [--netmask CIDR-netmask]\n"
	     "-A set [!]IP\n"
	     "-D set IP\n"
	     "-T set IP\n"
	     "-H iphash -i [--try number] [--factor number] [--netmask CIDR-netmask]\n");
}

struct ip_set_iphash_hint {
	unsigned int try;
	unsigned int factor;
	ip_set_ip_t netmask;
};

/* Initialize the hint. */
void hint_init(void *data)
{
	struct ip_set_iphash_hint *mydata = 
		(struct ip_set_iphash_hint *) data;

	DP("hint INIT");
	
	mydata->try = HINT_DEFAULT_TRY;
	mydata->factor = HINT_DEFAULT_FACTOR;
	mydata->netmask = 0xFFFFFFFF;
}

/* Function which parses command options; returns true if it ate an option */
int hint_parse(int c, char *argv[], void *data)
{
	struct ip_set_iphash_hint *mydata = 
		(struct ip_set_iphash_hint *) data;
	unsigned int bits;

	DP("hint_parse");

	switch (c) {
	case '1':
		if (string_to_number(optarg, 1, 32, &mydata->try))
			exit_error(PARAMETER_PROBLEM, 
				  "Invalid --try `%s' specified (out of range 1-32", optarg);
		
		DP("--try %i)", mydata->try);
		break;

	case '2':
		if (string_to_number(optarg, 1, 64, &mydata->factor))
			exit_error(PARAMETER_PROBLEM, 
				  "Invalid --factor `%s' specified (out of range 1-64", optarg);
		
		DP("--factor %i)", mydata->factor);
		break;

	case '3':

		if (string_to_number(optarg, 0, 32, &bits))
			exit_error(PARAMETER_PROBLEM, 
				  "Invalid netmask `%s' specified", optarg);
		
		if (bits != 0)
			mydata->netmask = 0xFFFFFFFF << (32 - bits);

		DP("--netmask %x", mydata->netmask);
		
		break;

	default:
		return 0;
	}

	return 1;
}

/* Hint commandline options */
static struct option hint_opts[] = {
	{"try", 1, 0, '1'},
	{"factor", 1, 0, '2'},
	{"netmask", 1, 0, '3'},
	{0}
};

int hint_try(const ip_set_ip_t *ip, ip_set_ip_t *test, ip_set_ip_t best,
	     ip_set_ip_t hashsize, unsigned int try, uint32_t *initval, int *found)
{
	ip_set_ip_t id, hash;
	int i = 0;

    next_try:
	while (i < try) {
		memset(test, 0, MAX_RANGE * sizeof(ip_set_ip_t));
		for (id = 0; id < best; id++) {
			hash = jhash_1word(ip[id], *initval) % hashsize;
			if (test[hash] != 0) {
				*initval = rand();
				i++;
				goto next_try;
			} else
				test[hash] = ip[id];
			DP("%i %x", hash, ip[id]);
		}
		printf("--initval 0x%08x --hashsize %d\n", *initval, hashsize);
		*found = 1;
		return 1;
	}
	return 0;	
}

void hint(const void *data, ip_set_ip_t *ip, ip_set_ip_t best)
{
	struct ip_set_iphash_hint *mydata = 
		(struct ip_set_iphash_hint *) data;
	uint32_t initval;
	ip_set_ip_t next, prev, curr;
	ip_set_ip_t test[MAX_RANGE];
	ip_set_ip_t id;
	int found = 0;
	
	curr = MAX_RANGE > mydata->factor * best ? mydata->factor * best : MAX_RANGE;
	prev = next = MAX_RANGE;

	srand(curr);
	initval = rand();

	for (id = 0; id < best; id++)
		ip[id] &= mydata->netmask;

	while (1) {
		DP("%u %u %u %u", prev, curr, next, best);

		if (hint_try(ip, test, best, curr, mydata->try, &initval, &found)) {
			if (curr == best)
				return;
			next = (curr + best)/2;
		} else {
			if (curr == prev){
				if (!found)
					printf("Cannot find good init values.\n");
				return;
			}
			next = (curr + prev)/2;
		}
		prev = curr;
		curr = next;
	}
}
static struct settype settype_iphash = {
	.typename = SETTYPE_NAME,
	.typecode = IPSET_TYPE_IP,
	.protocol_version = IP_SET_PROTOCOL_VERSION,

	/* Create */
	.create_size = sizeof(struct ip_set_req_iphash_create),
	.create_init = &create_init,
	.create_parse = &create_parse,
	.create_final = &create_final,
	.create_opts = create_opts,

	/* Add/del/test */
	.req_size = sizeof(struct ip_set_req_iphash),
	.adt_parser = &adt_parser,

	/* Get an IP address by id */
	.getipbyid = &getipbyid,
	.sizeid = &sizeid,

	/* Printing */
	.initheader = &initheader,
	.initmembers = &initmembers,
	.killmembers = &killmembers,
	.printheader = &printheader,
	.printips = &printips,		/* We only have the unsorted version */
	.printips_sorted = &printips,
	.saveheader = &saveheader,
	.saveips = &saveips,
	.usage = &usage,

	/* Hint */
	.hint_size = sizeof(struct ip_set_iphash_hint),
	.hint_init = &hint_init,
	.hint_parse = &hint_parse,
	.hint_opts = hint_opts,
	.hint = &hint,
};

void _init(void)
{
	settype_register(&settype_iphash);

}
