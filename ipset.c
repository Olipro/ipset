/* Copyright 2000-2004 Joakim Axelsson (gozem@linux.nu)
 *                     Patrick Schaaf (bof@bof.de)
 *                     Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
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
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <ctype.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdarg.h>
#include <netdb.h>
#include <dlfcn.h>
#include <asm/bitops.h>

#include "ipset.h"

/* The list of all sets */
static struct set *all_sets = NULL;

/* The list of loaded set types */
static struct settype *all_settypes = NULL;

/* Suppress output to stdout and stderr? */
static int option_quiet = 0;

/* Data from the command line: */
static char *set_name = NULL;			/* Name of the set */
static char *set_typename[IP_SET_LEVELS];	/* Set typenames */
static unsigned int set_typename_level = 0;	/* Size of set_typename */
static ip_set_ip_t set_ip[IP_SET_LEVELS];	/* IP addresses of child set */
static unsigned int set_level = 0;		/* Size of set_ip */
static unsigned int ip_level = 0;		/* Size of add/del/test addresses */

/* Max size of a set when hinting. */
#define MAX_HINT_SIZE	65536

#ifdef IP_SET_DEBUG
int option_debug = 0;
#endif

#define OPTION_OFFSET 256
static unsigned int global_option_offset = 0;

/* Now most of these command parsing functions are borrowed from iptables.c */

/* Commands */
#define CMD_NONE	0x0000U
#define CMD_CREATE	0x0001U		/* -N */
#define CMD_DESTROY	0x0002U		/* -X */
#define CMD_FLUSH	0x0004U		/* -F */
#define CMD_RENAME	0x0008U		/* -E */
#define CMD_SWAP	0x0010U		/* -W */
#define CMD_LIST	0x0020U		/* -L */
#define CMD_SAVE	0x0040U		/* -S */
#define CMD_RESTORE	0x0080U		/* -R */
#define CMD_ADD		0x0100U		/* -A */
#define CMD_DEL		0x0200U		/* -D */
#define CMD_TEST	0x0400U		/* -T */
#define CMD_HELP	0x0800U		/* -H */
#define CMD_VERSION	0x1000U		/* -V */
#define CMD_CREATE_CHILD 0x2000U	/* -N !!! */
#define NUMBER_OF_CMD 13
static const char cmdflags[] = { 
	'N', 'X', 'F', 'E', 'W', 'L', 'S', 'R', 
	'A', 'D', 'T', 'H', 'V',
};

/* Options */
#define OPT_NONE	0x0000U
#define OPT_NUMERIC	0x0001U		/* -n */
#define OPT_SORTED	0x0002U		/* -s */
#define OPT_QUIET	0x0004U		/* -q */
#define OPT_DEBUG	0x0008U		/* -z */
#define OPT_CHILDSETS	0x0010U		/* -c */
#define OPT_HINT	0x0020U		/* -i */
#define NUMBER_OF_OPT 6
static const char optflags[] =
    { 'n', 's', 'q', 'z', 'c', 'i' };

static struct option opts_long[] = {
	/* set operations */
	{"create",  1, 0, 'N'},
	{"destroy", 2, 0, 'X'},
	{"flush",   2, 0, 'F'},
	{"rename",  1, 0, 'E'},
	{"swap",    1, 0, 'W'},
	{"list",    2, 0, 'L'},

	{"save",    2, 0, 'S'},
	{"restore", 0, 0, 'R'},

	/* ip in set operations */
	{"add",     1, 0, 'A'},
	{"del",     1, 0, 'D'},
	{"test",    1, 0, 'T'},
	
	/* free options */
	{"numeric", 0, 0, 'n'},
	{"sorted",  0, 0, 's'},
	{"quiet",   0, 0, 'q'},
	{"childsets",0, 0, 'c'},
	{"hint",    0, 0, 'i'},

#ifdef IP_SET_DEBUG
	/* debug (if compiled with it) */
	{"debug",   0, 0, 'z'},
#endif

	/* version and help */
	{"version", 0, 0, 'V'},
	{"help",    2, 0, 'H'},

	/* end */
	{0}
};

static char opts_short[] =
    "-N:X::F::E:W:L::S::RA:D:T:nsqzciVh::H::";

/* Table of legal combinations of commands and options.  If any of the
 * given commands make an option legal, that option is legal (applies to
 * CMD_LIST and CMD_ZERO only).
 * Key:
 *  +  compulsory
 *  x  illegal
 *     optional
 */

static char commands_v_options[NUMBER_OF_CMD][NUMBER_OF_OPT] = {
	/*            -n   -s   -q   -z   -c   -i*/
	 /*CREATE*/  {'x', 'x', ' ', ' ', ' ', 'x'},
	 /*DESTROY*/ {'x', 'x', ' ', ' ', 'x', 'x'},
	 /*FLUSH*/   {'x', 'x', ' ', ' ', ' ', 'x'},
	 /*RENAME*/  {'x', 'x', ' ', ' ', 'x', 'x'},
	 /*SWAP*/    {'x', 'x', ' ', ' ', 'x', 'x'},
	 /*LIST*/    {' ', ' ', 'x', ' ', ' ', 'x'},
	 /*SAVE*/    {'x', 'x', ' ', ' ', 'x', 'x'},
	 /*RESTORE*/ {'x', 'x', ' ', ' ', 'x', 'x'},
	 /*ADD*/     {'x', 'x', ' ', ' ', 'x', 'x'},
	 /*DEL*/     {'x', 'x', ' ', ' ', 'x', 'x'},
	 /*TEST*/    {'x', 'x', ' ', ' ', 'x', 'x'},
	 /*HELP*/    {'x', 'x', 'x', ' ', 'x', ' '},
	 /*VERSION*/ {'x', 'x', 'x', ' ', 'x', 'x'},
};

void exit_tryhelp(int status)
{
	fprintf(stderr,
		"Try `%s -H' or '%s --help' for more information.\n",
		program_name, program_name);
	exit(status);
}

void exit_error(enum exittype status, char *msg, ...)
{
	va_list args;

	if (!option_quiet) {
		va_start(args, msg);
		fprintf(stderr, "%s v%s: ", program_name, program_version);
		vfprintf(stderr, msg, args);
		va_end(args);
		fprintf(stderr, "\n");
		if (status == PARAMETER_PROBLEM)
			exit_tryhelp(status);
		if (status == VERSION_PROBLEM)
			fprintf(stderr,
				"Perhaps %s or your kernel needs to be upgraded.\n",
				program_name);
	}

	exit(status);
}

void ipset_printf(char *msg, ...)
{
	va_list args;

	if (!option_quiet) {
		va_start(args, msg);
		vfprintf(stdout, msg, args);
		va_end(args);
		fprintf(stdout, "\n");
	}
}

static void generic_opt_check(int command, int options)
{
	int i, j, legal = 0;

	/* Check that commands are valid with options.  Complicated by the
	 * fact that if an option is legal with *any* command given, it is
	 * legal overall (ie. -z and -l).
	 */
	for (i = 0; i < NUMBER_OF_OPT; i++) {
		legal = 0;	/* -1 => illegal, 1 => legal, 0 => undecided. */

		for (j = 0; j < NUMBER_OF_CMD; j++) {
			if (!(command & (1 << j)))
				continue;

			if (!(options & (1 << i))) {
				if (commands_v_options[j][i] == '+')
					exit_error(PARAMETER_PROBLEM,
						   "You need to supply the `-%c' "
						   "option for this command\n",
						   optflags[i]);
			} else {
				if (commands_v_options[j][i] != 'x')
					legal = 1;
				else if (legal == 0)
					legal = -1;
			}
		}
		if (legal == -1)
			exit_error(PARAMETER_PROBLEM,
				   "Illegal option `-%c' with this command\n",
				   optflags[i]);
	}
}

static char opt2char(int option)
{
	const char *ptr;
	for (ptr = optflags; option > 1; option >>= 1, ptr++);

	return *ptr;
}

static char cmd2char(int option)
{
	const char *ptr;
	for (ptr = cmdflags; option > 1; option >>= 1, ptr++);

	return *ptr;
}

static void set_command(int *cmd, const int newcmd)
{
	if (*cmd != CMD_NONE)
		exit_error(PARAMETER_PROBLEM, "Can't use -%c with -%c\n",
			   cmd2char(newcmd), cmd2char(newcmd));
	*cmd = newcmd;
}

static void add_option(unsigned int *options, unsigned int option)
{
	if (*options & option)
		exit_error(PARAMETER_PROBLEM,
			   "multiple -%c flags not allowed",
			   opt2char(option));
	*options |= option;
}

void *ipset_malloc(size_t size)
{
	void *p;

	if (size == 0)
		return NULL;

	if ((p = malloc(size)) == NULL) {
		perror("ipset: malloc failed");
		exit(1);
	}
	return p;
}

void ipset_free(void **data)
{
	if (*data == NULL)
		return;

	free(*data);
	*data = NULL;
}

static struct option *merge_options(struct option *oldopts,
				    const struct option *newopts,
				    unsigned int *option_offset)
{
	unsigned int num_old, num_new, i;
	struct option *merge;

	for (num_old = 0; oldopts[num_old].name; num_old++);
	for (num_new = 0; newopts[num_new].name; num_new++);

	global_option_offset += OPTION_OFFSET;
	*option_offset = global_option_offset;

	merge = malloc(sizeof(struct option) * (num_new + num_old + 1));
	memcpy(merge, oldopts, num_old * sizeof(struct option));
	for (i = 0; i < num_new; i++) {
		merge[num_old + i] = newopts[i];
		merge[num_old + i].val += *option_offset;
	}
	memset(merge + num_old + num_new, 0, sizeof(struct option));

	return merge;
}

static char *ip_tohost(const struct in_addr *addr)
{
	struct hostent *host;

	DP("ip_tohost()");

	if ((host = gethostbyaddr((char *) addr,
				  sizeof(struct in_addr),
				  AF_INET)) != NULL) {
		DP("%s", host->h_name);
		return (char *) host->h_name;
	}

	return (char *) NULL;
}

static char *ip_tonetwork(const struct in_addr *addr)
{
	struct netent *net;

	DP("ip_tonetwork()");

	if ((net = getnetbyaddr((long) ntohl(addr->s_addr), 
				AF_INET)) != NULL)
		return (char *) net->n_name;

	return (char *) NULL;
}

/* Return a string representation of an IP address.
 * Please notice that a pointer to static char* area is returned.
 */
char *ip_tostring(ip_set_ip_t ip, unsigned options)
{
	struct in_addr addr;
	char *name;

	addr.s_addr = htonl(ip);

	if (!(options & OPT_NUMERIC)) {
		if ((name = ip_tohost(&addr)) != NULL ||
		    (name = ip_tonetwork(&addr)) != NULL)
			return name;
	}

	return inet_ntoa(addr);
}

/* Fills the 'ip' with the parsed ip or host in host byte order */
void parse_ip(const char *str, ip_set_ip_t * ip)
{
	struct hostent *host;
	struct in_addr addr;

	if (inet_aton(str, &addr) != 0) {
		*ip = ntohl(addr.s_addr);	/* We want host byte order */

#ifdef IP_SET_DEBUG
		{
			/*DEBUG*/ char *p = (char *) ip;
			DP("PARSE_IP %x %x %x %x %x %x", *ip, 0xC10BF8A6,
			   p[0], p[1], p[2], p[3]);
		}
#endif

		return;
	}

	host = gethostbyname(str);
	if (host != NULL) {
		if (host->h_addrtype != AF_INET ||
		    host->h_length != sizeof(struct in_addr))
			exit_error(PARAMETER_PROBLEM,
				   "host/network `%s' not an internet name",
				   str);
		if (host->h_addr_list[1] != 0)
			exit_error(PARAMETER_PROBLEM,
				   "host/network `%s' resolves to serveral ip-addresses. "
				   "Please specify one.", str);

		*ip = ntohl(((struct in_addr *) host->h_addr_list[0])->s_addr);

#ifdef IP_SET_DEBUG
		{
			/*DEBUG*/ char *p = (char *) ip;
			DP("PARSE_IP %x %x %x %x %x %x", *ip, 0xC10BF8A6,
			   p[0], p[1], p[2], p[3]);
		}
#endif

		return;
	}

	exit_error(PARAMETER_PROBLEM, "host/network `%s' not found", str);
}

/* Fills 'mask' with the parsed mask in host byte order */
void parse_mask(const char *str, ip_set_ip_t * mask)
{
	struct in_addr addr;
	unsigned int bits;

	DP("parse_mask %s", str);

	if (str == NULL) {
		/* no mask at all defaults to 32 bits */
		*mask = 0xFFFFFFFF;
		return;
	}
	if (strchr(str, '.') && inet_aton(str, &addr) != 0) {
		*mask = ntohl(addr.s_addr);	/* We want host byte order */
		return;
	}
	if (sscanf(str, "%d", &bits) != 1 || bits < 0 || bits > 32)
		exit_error(PARAMETER_PROBLEM,
			   "invalid mask `%s' specified", str);

	DP("bits: %d", bits);

	*mask = 0xFFFFFFFF << (32 - bits);
}

/* Combines parse_ip and parse_mask */
void
parse_ipandmask(const char *str, ip_set_ip_t * ip, ip_set_ip_t * mask)
{
	char buf[256];
	char *p;

	strncpy(buf, str, sizeof(buf) - 1);
	buf[255] = '\0';

	if ((p = strrchr(buf, '/')) != NULL) {
		*p = '\0';
		parse_mask(p + 1, mask);
	} else
		parse_mask(NULL, mask);

	/* if a null mask is given, the name is ignored, like in "any/0" */
	if (*mask == 0U)
		*ip = 0U;
	else
		parse_ip(buf, ip);

	DP("parse_ipandmask: %s ip: %08X (%s) mask: %08X",
	   str, *ip, ip_tostring(*ip, 0), *mask);

	/* Apply the netmask */
	*ip &= *mask;

	DP("parse_ipandmask: %s ip: %08X (%s) mask: %08X",
	   str, *ip, ip_tostring(*ip, 0), *mask);
}

/* Return a string representation of a port
 * Please notice that a pointer to static char* area is returned
 * and we assume TCP protocol.
 */
char *port_tostring(ip_set_ip_t port, unsigned options)
{
	struct servent *service;
	static char name[] = "65535";
	
	if (!(options & OPT_NUMERIC)
	    && (service = getservbyport(htons(port), "tcp")))
		return service->s_name;
	
	sprintf(name, "%u", port);
	return name;
}

int
string_to_number(const char *str, unsigned int min, unsigned int max,
		 ip_set_ip_t *port)
{
	long number;
	char *end;

	/* Handle hex, octal, etc. */
	errno = 0;
	number = strtol(str, &end, 0);
	if (*end == '\0' && end != str) {
		/* we parsed a number, let's see if we want this */
		if (errno != ERANGE && min <= number && number <= max) {
			*port = number;
			return 0;
		}
	}
	return -1;
}

static int
string_to_port(const char *str, ip_set_ip_t *port)
{
	struct servent *service;

	if ((service = getservbyname(str, "tcp")) != NULL) {
		*port = ntohs((unsigned short) service->s_port);
		return 0;
	}
	
	return -1;
}

/* Fills the 'ip' with the parsed port in host byte order */
void parse_port(const char *str, ip_set_ip_t *port)
{	
	if ((string_to_number(str, 0, 65535, port) != 0)
	    && (string_to_port(str, port) != 0))
		exit_error(PARAMETER_PROBLEM, "Invalid TCP port `%s' specified", str);
}

static struct settype *settype_find(const char *typename)
{
	struct settype *runner = all_settypes;

	DP("settype %s", typename);

	while (runner != NULL) {
		if (strncmp(runner->typename, typename, 
			    IP_SET_MAXNAMELEN) == 0)
			return runner;

		runner = runner->next;
	}

	return NULL;		/* not found */
}

static struct settype *settype_load(const char *typename)
{
	char path[sizeof(IPSET_LIB_DIR) + sizeof(IPSET_LIB_NAME) +
		  strlen(typename)];
	struct settype *settype;

	/* do some search in list */
	settype = settype_find(typename);
	if (settype != NULL)
		return settype;	/* found */

	/* Else we have to load it */
	sprintf(path, IPSET_LIB_DIR IPSET_LIB_NAME, typename);

	if (dlopen(path, RTLD_NOW)) {
		/* Found library. */

		settype = settype_find(typename);

		if (settype != NULL)
			return settype;
	}

	/* Can't load the settype */
	exit_error(PARAMETER_PROBLEM,
		   "Couldn't load settype `%s':%s\n",
		   typename, dlerror());

	return NULL;		/* Never executed, but keep compilers happy */
}

/* Register a new set type */
void settype_register(struct settype *settype)
{
	struct settype *chk;

	DP("register_settype '%s'\n", settype->typename);

	/* Check if this typename already exists */
	chk = settype_find(settype->typename);

	if (chk != NULL)
		exit_error(OTHER_PROBLEM,
			   "Set type '%s' already registred!\n",
			   settype->typename);

	/* Check version */
	if (settype->protocol_version != IP_SET_PROTOCOL_VERSION)
		exit_error(OTHER_PROBLEM,
			   "Set type is of wrong protocol version %u!"
			   " I'm am of version %u.\n", settype->typename,
			   settype->protocol_version,
			   IP_SET_PROTOCOL_VERSION);

	/* Insert first */
	settype->next = all_settypes;
	settype->data = ipset_malloc(settype->create_size);
	all_settypes = settype;

	DP("ip_set: register settype end '%s'\n", settype->typename);
}

static int kernel_getsocket(void)
{
	int sockfd = -1;

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0)
		exit_error(OTHER_PROBLEM,
			   "You need to be root to perform this command.");

	return sockfd;
}

static void kernel_error(int err)
{
	/* translate errnos, as returned by our *sockopt() functions */
	exit_error(OTHER_PROBLEM, "Error from kernel: %s", strerror(err));
}

static void kernel_sendto(void *data, size_t size)
{
	int res;
	int sockfd = kernel_getsocket();

	/* Send! */
	res = setsockopt(sockfd, SOL_IP, SO_IP_SET, data, size);

	DP("kernel_sendto() res=%d errno=%d\n", res, errno);

	if (res != 0)
		kernel_error(errno);
}

/* Used by addip and delip that has to handle the EEXIST error better */
static int kernel_sendto_handleexist(void *data, size_t size)
{
	int res;
	int sockfd = kernel_getsocket();

	/* Send! */
	res = setsockopt(sockfd, SOL_IP, SO_IP_SET, data, size);

	DP("kernel_sendto_handleexist() res=%d errno=%d\n", res, errno);

	if (res != 0 && errno == EEXIST)
		return -1;
	else if (res != 0)
		kernel_error(errno);

	return 0;		/* all ok */
}

static void kernel_getfrom(void *data, size_t * size)
{
	int res;
	int sockfd = kernel_getsocket();

	/* Send! */
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, data, size);

	DP("kernel_getfrom() res=%d errno=%d\n", res, errno);

	if (res != 0)
		kernel_error(errno);
}

static int get_protocolversion(void)
{
	struct ip_set_req_version req_version;
	size_t size = sizeof(struct ip_set_req_version);

	req_version.op = IP_SET_OP_VERSION;

	kernel_getfrom(&req_version, &size);

	DP("get_protocolversion() ver=%d", req_version.version);

	return req_version.version;
}

static void set_append(struct set *set)
{
	struct set *entry = all_sets;
	
	while (entry != NULL && entry->next != NULL)
		entry = entry->next;
	
	if (entry == NULL)
		all_sets = set;
	else
		entry->next = set;
}

static void get_sets(void)
{
	void *data = NULL;
	struct ip_set_req_listing_size req_list;
	int sockfd = kernel_getsocket();
	size_t size;
	size_t eaten = 0;
	int i, res;

	DP("get_sets()");
	for (i = 0; i < LIST_TRIES; i++) {
		req_list.op = IP_SET_OP_LISTING_SIZE;
		size = sizeof(req_list);
		kernel_getfrom(&req_list, &size);
		size = req_list.size;

		DP("got size: %d", size);

		if (req_list.size == 0)
			return;		/* No sets in kernel */

		data = ipset_malloc(size);
		((struct ip_set_req_base *) data)->op = IP_SET_OP_LISTING;

		/* Get! */
		res = getsockopt(sockfd, SOL_IP, SO_IP_SET, data, &size);
		DP("list_get getsockopt() res=%d errno=%d\n", res, errno);

		if (res == 0)
			goto got_sets;	/* all OK */
		else if (errno != ENOMEM)
			break;		/* Not a memory error */

		DP("not enough mem, looping again");
		free(data);
	}

	if (errno == ENOMEM)
		exit_error(OTHER_PROBLEM,
			   "Tried to list sets from kernel %d times"
			   " and failed. Please try again when the load on"
			   " the sets has gone down.", LIST_TRIES);
	else
		kernel_error(errno);

    got_sets:

	DP("get_sets() - size=%d data=%p", size, data);
	/* Handle the data */
	while (eaten < size) {
		struct ip_set_req_listing *header =
		    (struct ip_set_req_listing *) (data + eaten);
		struct set *set = ipset_malloc(sizeof(struct set));

		memset(set, 0, sizeof(struct set));
		
		DP("fillin %d %p", eaten, header);

#ifdef IP_SET_DEBUG
		/* DEBUG */
		{
			void *i;

			DP("SET DATA:");

			for (i = data + eaten;
			     i <
			     data + eaten +
			     sizeof(struct ip_set_req_listing); i += 4) {
				unsigned *j = (unsigned *) i;
				DP("%x", *j);
			}
		}
#endif

		/* Fill in data */
		DP("Processing set '%s'", header->name);
		strcpy(set->name, header->name);
		set->id = header->id;
		set->levels = header->levels;
		set->ref = header->ref;
		for (i = 0; i < set->levels; i++) {
			set->settype[i] = settype_load(header->typename[i]);
			set->private[i].adt = 
				ipset_malloc(set->settype[i]->req_size);
		}

		eaten += sizeof(struct ip_set_req_listing);

		DP("insert in list");
		set_append(set);
	}

	DP("free");

	free(data);

	DP("get_sets() eaten = %d, size = %d", eaten, size);

	if (eaten != size)
		exit_error(OTHER_PROBLEM,
			   "Desynched in listing of sets from kernel. "
			   "Read %d bytes. Worked %d bytes.", size, eaten);
}

struct set *set_find(const char *setname)
{
	struct set *set = all_sets;

	DP("%s", setname);

	while (set != NULL) {
		if (strcmp(setname, set->name) == 0)
			return set;
		set = set->next;
	}
	return NULL;
}

static struct set *set_checkname(const char *setname)
{
	char *saved = strdup(setname);
	char *ptr, *tmp = saved;
	struct set *set;
	int i;

	DP("%s", setname);

	/* Cleanup */
	if (set_name != NULL)
		free(set_name);
	
	for (i = 0; i < IP_SET_SETIP_LEVELS; i++)
		set_ip[i] = 0;
	set_level = 0;

	/* name[:ip,...] */
	ptr = strsep(&tmp, ":");
	if (strlen(ptr) > IP_SET_MAXNAMELEN - 1)
		exit_error(PARAMETER_PROBLEM,
			   "Setname '%s' in '%s' too long. Max %d characters.",
			   ptr, setname, IP_SET_MAXNAMELEN - 1);

	DP("%s (%s)", ptr, tmp);
	set = set_find(ptr);
	if (!set && tmp)
		exit_error(PARAMETER_PROBLEM,
			   "Set '%s' not found for '%s'\n",
			   ptr, setname);
	
	set_name = strdup(ptr);

	while (set_level < IP_SET_SETIP_LEVELS && tmp) {
		ptr = strsep(&tmp, ",");
		switch (set->settype[set_level]->typecode) {
		case IPSET_TYPE_IP:
			parse_ip(ptr, &set_ip[set_level++]);
			break;
		case IPSET_TYPE_PORT:
			parse_port(ptr, &set_ip[set_level++]);
			break;
		default:
			; /* Keep compilers happy */
		}		
		if (set->levels <= set_level)
			exit_error(PARAMETER_PROBLEM, 
				   "Subset definition is too deep for set '%s'\n",
				   set_name);
	}

	free(saved);
	return set;
}

static inline struct set *set_find_byname(const char *setname)
{
	struct set *set = set_checkname(setname);

	if (!set)
		exit_error(PARAMETER_PROBLEM, 
			   "Set '%s' not found\n", setname);
	return set;
}

static void set_checktype(const char *typename)
{
	char *saved = strdup(typename);
	char *ptr, *tmp = saved;
	int i;

	/* Cleanup */
	for (i = 0; i < IP_SET_LEVELS; i++)
		if (set_typename[i] != NULL)
			free(set_typename[i]);

	/* typename[,...] */
	set_typename_level = 0;
	while (set_typename_level < IP_SET_LEVELS && tmp) {
		ptr = strsep(&tmp, ",");
		DP("settype '%s', level %i", ptr, set_typename_level);
		if (strlen(ptr) > IP_SET_MAXNAMELEN - 1)
			exit_error(PARAMETER_PROBLEM,
				   "Typename '%s' in '%s' too long. Max %d characters.",
				   ptr, typename, IP_SET_MAXNAMELEN - 1);
		set_typename[set_typename_level++] = strdup(ptr);
	}
	DP("tmp '%s', level %i", tmp, set_typename_level);
	if (set_typename_level >= IP_SET_LEVELS || tmp)	
		exit_error(PARAMETER_PROBLEM,
			   "More than %d settypes in '%s'.",
			   IP_SET_LEVELS - 1 , typename);
	free(saved);
}

/* Get setid from kernel. */
static void
set_get_setid(struct set *set)
{
	struct ip_set_req_get req_get;
	size_t size = sizeof(struct ip_set_req_get);

	DP("set_get_setid()");

	req_get.op = IP_SET_OP_GETSET_BYNAME;
	strcpy(req_get.name, set->name);

	/* Result in the id-field */
	kernel_getfrom(&req_get, &size);

	if (size != sizeof(struct ip_set_req_get))
		exit_error(OTHER_PROBLEM,
			   "Incorrect return size from kernel."
			   "Should be %d but was %d.",
			   sizeof(struct ip_set_req_get), size);

	DP("set_get_setid() result=%u", req_get.id);

	if (req_get.id < 0)
		exit_error(OTHER_PROBLEM,
			   "Set %s cannot be found.",
			   set->name);

	set->id = req_get.id;
	set->ref = req_get.ref;
}

/* Send create set order to kernel */
static void
set_create(struct set *set)
{
	struct ip_set_req_create req_create;
	struct settype *settype = set->settype[0];
	size_t size;
	void *data;
	int i;

	DP("set_create()");

	req_create.op = IP_SET_OP_CREATE;
	strcpy(req_create.name, set->name);
	for (i = 0; i < set_typename_level; i++)
		strcpy(req_create.typename[i], set->settype[i]->typename);
	req_create.levels = set_typename_level;

	/* Final checks */
	settype->create_final(settype->data, settype->flags);

	/* Alloc memory for the data to send */
	size = sizeof(struct ip_set_req_create) + settype->create_size;
	data = ipset_malloc(size);

	/* Add up ip_set_req_create and the settype data */
	memcpy(data, &req_create, sizeof(struct ip_set_req_create));
	memcpy(data + sizeof(struct ip_set_req_create),
	       settype->data, settype->create_size);

#ifdef IP_SET_DEBUG
	/* DEBUG */
	{
		void *i;

		DP("CMD_CREATE");
		DP("OP %u", req_create.op);
		DP("Name: %s", req_create.name);
		DP("Typename: %s", req_create.typename[0]);
		DP("All data");

		for (i = data; i < data + size; i += 4) {
			unsigned *j = (unsigned *) i;
			DP("%x", *j);
		}
	}
#endif

	kernel_sendto(data, size);
	free(data);
	
	/* Get set id from kernel */
	set_get_setid(set);
	/* Success! */
	set_append(set);
}

/* Send create childset order to kernel */
static void
set_create_childset(const struct set *set, unsigned options)
{
	struct ip_set_req_sub req_sub;
	struct settype *settype = set->settype[set_level];
	size_t size;
	void *data;
	int i;

	DP("childset_create()");

	req_sub.op = IP_SET_OP_CREATE_CHILD;
	req_sub.id = set->id;
	for (i = 0; i < set_level; i++)
		req_sub.ip[i] = set_ip[i];
	req_sub.level = set_level;
	req_sub.childsets = options & OPT_CHILDSETS;

	/* Final checks */
	settype->create_final(settype->data, settype->flags);

	/* Alloc memory for the data to send */
	size = sizeof(struct ip_set_req_sub) + settype->create_size;
	data = ipset_malloc(size);

	/* Add up ip_set_req_sub and the settype data */
	memcpy(data, &req_sub, sizeof(struct ip_set_req_sub));
	memcpy(data + sizeof(struct ip_set_req_sub),
	       settype->data, settype->create_size);

#ifdef IP_SET_DEBUG
	/* DEBUG */
	{
		void *i;

		DP("CMD_CREATE_CHILD");
		DP("OP %u", req_sub.op);
		DP("Id: %u", req_sub.id);
		DP("All data");

		for (i = data; i < data + size; i += 4) {
			unsigned *j = (unsigned *) i;
			DP("%x", *j);
		}
	}
#endif

	kernel_sendto(data, size);
	free(data);
}

static void set_del(struct set *set)
{
	int i;
	
	for (i = 0; i < set->levels; i++) {
		if (set->private[i].setdata)
			set->settype[i]->killmembers(&set->private[i].setdata);
		ipset_free(&set->private[i].bitmap);
	}
		
	free(set);
}

/* Sends destroy order to kernel for one or all sets
 * All sets: set == NULL
 */
static void set_destroy(struct set *set)
{
	struct ip_set_req_std req_destroy;

	req_destroy.op = IP_SET_OP_DESTROY;

	if (set == NULL) {
		/* Do them all */
		
		while (all_sets != NULL) {
			set = all_sets;
			all_sets = set->next;
			req_destroy.id = set->id;
			req_destroy.level = 0;
			kernel_sendto(&req_destroy,
				      sizeof(struct ip_set_req_std));
			set_del(set);
		}
	} else {
		int i;
		
		DP("destroy %s", set->name);

		/* Only destroy one */
		req_destroy.id = set->id;
		for (i = 0; i < set_level; i++)
			req_destroy.ip[i] = set_ip[i];
		req_destroy.level = set_level;	
		kernel_sendto(&req_destroy,
			      sizeof(struct ip_set_req_std));
		if (set_level == 0) {
			if (set == all_sets)
				all_sets = set->next;
			else {
				struct set *entry = all_sets;
			
				while (entry && entry->next && entry->next != set)
					entry = entry->next;
				if (entry->next == set)
					entry->next = set->next;
			}				
			set_del(set);
		}
	}
}

/* Sends flush order to kernel for one or all sets
 * All sets: set = NULL
 */
static void set_flush(const struct set *set, unsigned options)
{
	struct ip_set_req_sub req_flush;

	DP("flush");

	req_flush.op = IP_SET_OP_FLUSH;

	if (set == NULL) {
		/* Do them all */
		struct set *entry = all_sets;
		
		while (entry != NULL) {
			req_flush.id = entry->id;
			req_flush.level = 0;
			req_flush.childsets = options & OPT_CHILDSETS;
			kernel_sendto(&req_flush,
				      sizeof(struct ip_set_req_sub));
			entry = entry->next;
		}
	} else {
		int i;

		/* Only one */
		req_flush.id = set->id;
		for (i = 0; i < set_level; i++)
			req_flush.ip[i] = set_ip[i];
		req_flush.level = set_level;	
		req_flush.childsets = options & OPT_CHILDSETS;
		kernel_sendto(&req_flush, sizeof(struct ip_set_req_sub));
	}
}

/* Sends rename order to kernel */
static void set_rename(struct set *set, const char *newname)
{
	struct ip_set_req_rename req_rename;

	DP("rename");

	req_rename.op = IP_SET_OP_RENAME;
	req_rename.id = set->id;
	strncpy(req_rename.newname, newname, IP_SET_MAXNAMELEN);

	DP("rename - send");
	kernel_sendto(&req_rename, sizeof(struct ip_set_req_rename));
	
	strncpy(set->name, newname, IP_SET_MAXNAMELEN);
}

/* Sends swap order to kernel for two sets */
static void set_swap(struct set *from, struct set *to)
{
	struct ip_set_req_swap req_swap;

	DP("swap");

	req_swap.op = IP_SET_OP_SWAP;
	req_swap.id = from->id;
	req_swap.to = to->id;

	DP("swap - send");
	kernel_sendto(&req_swap, sizeof(struct ip_set_req_swap));
	
	from->id = req_swap.to;
	to->id = req_swap.id;
}

static void *list_get(int opsize, int opget, ip_set_ip_t id,
		      int *size, ip_set_ip_t *ip, unsigned level)
{
	int res, i;
	struct ip_set_req_list req_list;
	struct ip_set_req_std *req_data;
	int sockfd = kernel_getsocket();
	void *data = NULL;

	req_list.op = opsize;
	req_list.id = id;
	req_list.level = level;
	for (i = 0; i < level; i++)
		req_list.ip[i] = ip[i];

	*size = sizeof(req_list);
	kernel_getfrom(&req_list, size);

	DP("got size: %d", req_list.size);

	if (req_list.size == 0)
		return data;

	*size = sizeof(struct ip_set_req_std) > req_list.size ?
		sizeof(struct ip_set_req_std) : req_list.size;

	data = ipset_malloc(*size);
	req_data = (struct ip_set_req_std *) data;
	req_data->op = opget;
	req_data->id = id;
	req_data->level = level;
	for (i = 0; i < level; i++)
		req_data->ip[i] = ip[i];

	/* Get! */
	res = getsockopt(sockfd, SOL_IP, SO_IP_SET, data, size);
	DP("list_get getsockopt() res=%d errno=%d\n", res, errno);

	if (res != 0)
		kernel_error(errno);

	/* All OK, return */
	return data;
}

static void list_getheaders(struct set *set, ip_set_ip_t *ip, unsigned level)
{
	void *data;
	size_t size;

	data = list_get(IP_SET_OP_LIST_HEADER_SIZE,
			IP_SET_OP_LIST_HEADER, 
			set->id, &size, ip, level);

	if (size == 0)
		exit_error(OTHER_PROBLEM,
			   "Kernel returned zero header size. "
			   "Something screwed up.");
			   
	/* Cleanup setdata */
	if (set->private[level].setdata)
		set->settype[level]->killmembers(&set->private[level].setdata);

	/* Handle the data */
	set->settype[level]->initheader(&set->private[level].setdata,
					data, size);

	ipset_free(&data);
}

static void list_getmembers(struct set *set, ip_set_ip_t *ip, unsigned level)
{
	void *data;
	size_t size;

	data = list_get(IP_SET_OP_LIST_MEMBERS_SIZE,
			IP_SET_OP_LIST_MEMBERS, 
			set->id, &size, ip, level);
			
	if (size == 0)
		exit_error(OTHER_PROBLEM,
			   "Kernel returned zero header size. "
			   "Something screwed up.");
			   
	/* Handle the data */
	set->settype[level]->initmembers(set->private[level].setdata,
					   data, size);

	/* Next list_getheaders or set_del frees the data */
}

static void list_getchildsets(struct set *set, ip_set_ip_t *ip, unsigned level)
{
	void *data;
	size_t size;

	data = list_get(IP_SET_OP_LIST_CHILDSETS_SIZE,
			IP_SET_OP_LIST_CHILDSETS, 
			set->id, &size, ip, level);

	/* Cleanup */
	ipset_free(&set->private[level].bitmap);
	set->private[level].bitmap = NULL;
	
	if (size == 0)
		return;	/* No child set */
		
	/* Handle the data */
	set->private[level].bitmap = data;

	/* Next list_getchildsets or set_del frees the data */
}

/* Print a child set */
static void set_list_childset(struct set *set,
			      unsigned options,
			      ip_set_ip_t *ip,
			      unsigned level)
{
	int i;
	ip_set_ip_t id;
	
	/* Load the set header, member and childset data */
	list_getheaders(set, ip, level);
	list_getmembers(set, ip, level);
	list_getchildsets(set, ip, level);

	/* Pretty print the childset */
	printf("Childset %s %s", 
	       set->private[level].bitmap != NULL ? "+" : "-",
	       set->name);
	for (i = 0; i < level; i++) {
		switch (set->settype[i]->typecode) {
		case IPSET_TYPE_IP:
			printf("%s%s", i == 0 ? ":" : ",",
				       ip_tostring(ip[i], options));
			break;
		case IPSET_TYPE_PORT:
			printf("%s%s", i == 0 ? ":" : ",",
				       port_tostring(ip[i], options));
			break;
		default:
			;
		}
	}
	printf("\n");

	/* Pretty print the type header */
	set->settype[level]->printheader(set->private[level].setdata, options);

	/* Pretty print all IPs */
	if (options & OPT_SORTED)
		set->settype[level]->printips_sorted(set->private[level].setdata, options);
	else
		set->settype[level]->printips(set->private[level].setdata, options);

	/* Pretty print all childsets. */
	if (!(set->private[level].bitmap != NULL && (options & OPT_CHILDSETS)))
		return;

	for (id = 0; 
	     id < set->settype[level]->sizeid(set->private[level].setdata);
	     id++) {
		if (test_bit(id, set->private[level].bitmap)) {
			ip[level] = set->settype[level]->getipbyid(
					set->private[level].setdata, id);
			set_list_childset(set, options, ip, level+1);
		}
	}
}

/* Help function to set_list() */
static void set_list_oneset(struct set *set,
			      unsigned options)
{
	int i;
	
	/* Pretty print the set */
	printf("Name %s\n", set->name);
	printf("Type %s", set->settype[0]->typename);
	for (i = 1; i < set->levels; i++)
		printf(",%s", set->settype[i]->typename);
	printf("\n");
	printf("References %d\n", set->ref);

	/* Pretty print the childset */
	set_list_childset(set, options, set_ip, set_level);

	printf("\n");		/* One newline between sets */
}

/* Print a set or all sets
 * All sets: set = NULL
 */
static void set_list(struct set *set, unsigned options)
{
	if (set == NULL) {
		set = all_sets;
		
		while (set != NULL) {
			set_list_oneset(set, options);
			set = set->next;
		}
	} else
		set_list_oneset(set, options);
}

/* Performs a save to stdout
 * All sets are marked with set.name[0] == '\0'
 * Area pointed by 'set' will be changed
 */
static void set_save(const struct set *set)
{
	DP("set_save() not yet implemented");
}

/* Performs a restore from stdin */
static void set_restore()
{
	DP("set_restore() not yet implemented");
}

static void parse_adt_ip(int cmd, struct set *set, const char *adt_ip)
{
	char *saved = strdup(adt_ip);
	char *ptr, *tmp = saved;

	ip_level = set_level;
			
	while (ip_level <= set->levels && tmp) {

		if (ip_level > set_level)
			list_getheaders(set, set_ip, ip_level);

		ptr = strsep(&tmp, ",");

		/* Call the parser function */
		set_ip[ip_level] = set->settype[ip_level]->adt_parser(
					cmd, ptr,
					set->private[ip_level].adt,
			 		set->private[ip_level].setdata);
		DP("%i: (%s)", ip_level, ip_tostring(set_ip[ip_level], 0));
		ip_level++;
	}

	if (tmp || ip_level > set->levels)
		exit_error(PARAMETER_PROBLEM,
			   "Specified (child) set and IP levels together"
			   " are deeper than %s set (%i).", 
			   set->name, set->levels);
			   
	free(saved);
}

/* Sends addip order to kernel for a set */
static void set_addip(struct set *set, const char *adt_ip)
{
	struct ip_set_req_std req_addip;
	size_t size, offset;
	void *data;
	int i;

	DP("set_addip() %p", set);

	list_getheaders(set, set_ip, set_level);

	parse_adt_ip(ADT_ADD, set, adt_ip);

	req_addip.op = IP_SET_OP_ADD_IP;
	req_addip.id = set->id;
	for (i = 0; i < set_level; i++)
		req_addip.ip[i] = set_ip[i];
	req_addip.level = set_level;

	DP("%i %i", set_level, ip_level);
	/* Alloc memory for the data to send */
	DP("alloc");
	size = sizeof(struct ip_set_req_std);
	for (i = set_level; i < ip_level; i++) {
		size += set->settype[i]->req_size;
		DP("i: %i, size: %u", i, size);
	}
	data = ipset_malloc(size);

	/* Add up req_addip and the settype data */
	DP("mem");
	memcpy(data, &req_addip, sizeof(struct ip_set_req_std));
	offset = sizeof(struct ip_set_req_std);
	for (i = set_level; i < ip_level; i++) {
		memcpy(data + offset,
		       set->private[i].adt,
		       set->settype[i]->req_size);
		offset += set->settype[i]->req_size;
	}

#ifdef IP_SET_DEBUG
	/* DEBUG */
	{
		void *i;

		DP("CMD_ADDIP");
		DP("OP %u", req_addip.op);
		DP("Id: %u", req_addip.id);
		DP("All data");

		for (i = data; i < data + size; i += 4) {
			unsigned *j = (unsigned *) i;
			DP("%x", *j);
		}
	}
#endif

	if (kernel_sendto_handleexist(data, size) == -1)
		/* Arghh, we can't get the commandline string anymore, oh well */
		exit_error(OTHER_PROBLEM, "Already added in set %s.",
			   set->name);
	free(data);
}

/* Sends delip order to kernel for a set */
static void set_delip(struct set *set, const char *adt_ip, unsigned options)
{
	struct ip_set_req_std req_delip;
	size_t size, offset;
	void *data;
	int i;

	DP("set_delip()");

	list_getheaders(set, set_ip, set_level);

	parse_adt_ip(ADT_DEL, set, adt_ip);

	req_delip.op = IP_SET_OP_DEL_IP;
	req_delip.id = set->id;
	for (i = 0; i < set_level; i++)
		req_delip.ip[i] = set_ip[i];
	req_delip.level = set_level;

	/* Alloc memory for the data to send */
	size = sizeof(struct ip_set_req_std);
	for (i = set_level; i < ip_level; i++)
		size += set->settype[i]->req_size;
	data = ipset_malloc(size);

	/* Add up req_sub and the settype data */
	memcpy(data, &req_delip, sizeof(struct ip_set_req_std));
	offset = sizeof(struct ip_set_req_std);
	for (i = set_level; i < ip_level; i++) {
		memcpy(data + offset,
		       set->private[i].adt,
		       set->settype[i]->req_size);
		offset += set->settype[i]->req_size;
	}

#ifdef IP_SET_DEBUG
	/* DEBUG */
	{
		void *i;

		DP("CMD_DELIP");
		DP("OP %u", req_delip.op);
		DP("Id: %u", req_delip.id);
		DP("All data");

		for (i = data; i < data + size; i += 4) {
			unsigned *j = (unsigned *) i;
			DP("%x", *j);
		}
	}
#endif

	if (kernel_sendto_handleexist(data, size) == -1)
		/* Arghh, we can't get the commandline string anymore, oh well */
		exit_error(OTHER_PROBLEM, "Doesn't exist in set %s.",
			   set->name);
	free(data);
}

/* Sends test order to kernel for a set */
static int
set_testip(struct set *set, const char *name, const char *adt_ip)
{
	int i, res;
	struct ip_set_req_test req_test;
	void *data;
	size_t size, offset;

	list_getheaders(set, set_ip, set_level);

	parse_adt_ip(ADT_TEST, set, adt_ip);

	req_test.op = IP_SET_OP_TEST_IP;
	req_test.id = set->id;
	for (i = 0; i < set_level; i++)
		req_test.ip[i] = set_ip[i];
	req_test.level = set_level;

	/* Alloc memory for the data to send */
	size = sizeof(struct ip_set_req_test);
	for (i = set_level; i < ip_level; i++)
		size += set->settype[i]->req_size;
	data = ipset_malloc(size);

	/* Add up req_test and the settype data */
	memcpy(data, &req_test, sizeof(struct ip_set_req_test));
	offset = sizeof(struct ip_set_req_test);
	for (i = set_level; i < ip_level; i++) {
		memcpy(data + offset,
		       set->private[i].adt,
		       set->settype[i]->req_size);
		offset += set->settype[i]->req_size;
	}
	/* Result in the op-field */
	kernel_getfrom(data, &size);

	if (size != sizeof(struct ip_set_req_test))
		exit_error(OTHER_PROBLEM,
			   "Incorrect return size from kernel."
			   "Should be %d but was %d.",
			   sizeof(struct ip_set_req_test), size);

	DP("set_testip() result=%x", req_test.op);

	if (((struct ip_set_req_test *)data)->reply > 0) {
		ipset_printf("%s is in set %s.", adt_ip, name);
		res = 0;	/* Return value for the program */
	} else {
		ipset_printf("%s is NOT in set %s.", adt_ip, name);
		res = 1;
	}

	free(data);
	return res;
}

/* Prints help
 * If settype is non null help for that type is printed as well
 */
static void set_help(const struct settype *settype)
{
#ifdef IP_SET_DEBUG
	char debughelp[] =
	       "  --debug      -z              Enable debugging\n\n";
#else
	char debughelp[] = "\n";
#endif

	printf("%s v%s\n\n"
	       "Usage: %s -N new-set settype [options]\n"
	       "       %s -[XFLSH] [set] [options]\n"
	       "       %s -[EW] from-set to-set\n"
	       "       %s -[ADT] set entry\n"
	       "       %s -R\n"
	       "       %s -h (print this help information)\n\n",
	       program_name, program_version, program_name, program_name,
	       program_name, program_name, program_name, program_name);

	printf("Commands:\n"
	       "Either long or short options are allowed.\n"
	       "  --create  -N setname settype0[,settype1,...] <options>\n"
	       "                    Create a new set\n"
	       "  --create  -N setname:IP[,IP...] settype <options>\n"
	       "                    Create childset at setname:IP[,IP...]\n"
	       "  --destroy -X [setname:IP,....]\n"
	       "                    Destroy a (child)set or all sets\n"
	       "  --flush   -F [setname:IP,...] [options]\n"
	       "                    Delete a (child)set or all sets\n"
	       "  --rename  -E from-set to-set\n"
	       "                    Rename from-set to to-set\n"
	       "  --swap    -W from-set to-set\n"
	       "                    Swap the content of two existing sets\n"
	       "  --list    -L [setname:IP,...] [options]\n"
	       "                    List the entries in a (child)set or all sets\n"
	       "  --save    -S [setname]\n"
	       "                    Save the set or all sets to stdout\n"
	       "  --restore -R\n"
	       "                    Restores from stdin a saved state\n"
	       "  --add     -A setname[:IP,...] entry[,entry...]\n"
	       "                    Add an entry to a (child)set\n"
	       "  --del     -D setname[:IP,...] entry[,entry...]\n"
	       "                    Deletes an entry from a (child)set\n"
	       "  --test    -T setname[:IP,...] entry[,entry...]\n"
	       "                    Tests if an entry exists in a (child)set.\n"
	       "  --help    -H [settype] [options]]\n"
	       "                    Prints this help, and settype specific help\n"
	       "  --version -V\n"
	       "                    Prints version information\n\n"
	       "Options:\n"
	       "  --sorted     -s   Numeric sort of the IPs in -L\n"
	       "  --numeric    -n   Numeric output of addresses in a -L\n"
	       "  --quiet      -q   Suppress any output to stdout and stderr.\n"
	       "  --childsets  -c   Operation valid for child sets\n"
	       "  --hint       -i   Hint best settype initialization parameters\n");
	printf(debughelp);

	if (settype != NULL) {
		printf("Type '%s' specific:\n", settype->typename);
		settype->usage();
	}
}

/* Hint various infos on a given settype */
static int
settype_hint(const struct settype *settype, unsigned options)
{
	char buffer[1024];
	ip_set_ip_t ip[MAX_HINT_SIZE];
	ip_set_ip_t id = 0;
	
	if (!settype->hint)
		return 0;
	
	while (fgets(buffer, sizeof(buffer), stdin) != NULL
	       && id < MAX_HINT_SIZE) {
		if (buffer[0] == '\n' || buffer[0] == '#')
			continue;
		switch (settype->typecode) {
		case IPSET_TYPE_IP:
			parse_ip(buffer, &ip[id++]);
			break;
		case IPSET_TYPE_PORT:
			parse_port(buffer, &ip[id++]);
			break;
		default:
			;
		}
	}
	if (id >= MAX_HINT_SIZE)
		exit_error(OTHER_PROBLEM,
			   "More than %ld entries, exiting.",
			   MAX_HINT_SIZE);
	if (id < 1)
		exit_error(OTHER_PROBLEM,
			   "No input, no hint.");

	settype->hint(settype->data, ip, id);
	
	return 0;
}

static void init_sets(void)
{
	int version;
	static int done = 0;
	
	if (done)
		return;
	
	version = get_protocolversion();
	if (version != IP_SET_PROTOCOL_VERSION)
		exit_error(OTHER_PROBLEM,
			   "Kernel ipset code is of protocol version %u."
			   "I'm of protocol version %u.\n"
			   "Please upgrade your kernel and/or ipset(8) utillity.",
			   version, IP_SET_PROTOCOL_VERSION);

	/* Get the list of existing sets from the kernel */
	get_sets();
	done = 1;
}

/* Main worker function */
int parse_commandline(int argc, char *argv[], int exec_restore)
{
	int res = 0;
	unsigned command = 0;
	unsigned options = 0;
	int c;

	struct set *set = NULL;
	struct set *set_to = NULL;		/* Used by -W */
	struct settype *settype = NULL;		/* Used by -H */
	char *name = NULL;			/* Used by -E */
	char *entries = NULL;			/* Used by -A, -D, -T */
	
	struct option *opts = opts_long;

	/* Suppress error messages: we may add new options if we
	   demand-load a protocol. */
	opterr = 0;

	while ((c = getopt_long(argc, argv, opts_short, opts, NULL)) != -1) {

		DP("commandline parsed: opt %c (%s)", c, argv[optind]);

		switch (c) {
			/*
			 * Command selection.
			 */
		case 'h':
		case 'H':{	/* Help */
				set_command(&command, CMD_HELP);
				
				if (optarg)
					set_checktype(optarg);
				else if (optind < argc
					 && argv[optind][0] != '-')
					set_checktype(argv[optind++]);

				if (!set_typename_level)
					break;
					
				if (set_typename_level != 1)
					exit_error(PARAMETER_PROBLEM,
						   "-%c requires one settype as argument",
						   cmd2char(CMD_HELP));
				
				settype = settype_load(set_typename[0]);

				/* Merge the hint options */
				if (settype->hint_parse) {
					opts = merge_options(opts,
						     settype->hint_opts,
						     &settype->option_offset);
								
					/* Reset space for settype create data */
					memset(settype->data, 0, settype->hint_size);

					/* Zero the flags */
					settype->flags = 0;

					DP("call hint_init");
					/* Call the settype hint_init */
					settype->hint_init(settype->data);
				}
				
				break;
			}

		case 'V':{	/* Version */
				/* Dont display kernel protocol version because 
				 * that might generate errors if the ipset module 
				 * is not loaded in.*/
				printf("%s v%s Protocol version %u.\n",
				       program_name, program_version,
				       IP_SET_PROTOCOL_VERSION);
				exit(0);
			}
			
		case 'N':{	/* Create */
				char *typename = NULL;
				int i;
				
				init_sets();
				
				DP("check setname");
				/* setname */
				set = set_checkname(optarg);
				
				if (set_level == 0) {
					/* New set to be created */

					DP(" new set, set_level == 0");

					if (set != NULL) 
						exit_error(OTHER_PROBLEM,
							   "Set %s already exists.",
							   set_name);
					set = ipset_malloc(sizeof(struct set));
					memset(set, 0, sizeof(struct set));
					
					set_command(&command, CMD_CREATE);

					/* typename */
					if (optind < argc
					    && argv[optind][0] != '-')
						typename = argv[optind++];
					else
						exit_error(PARAMETER_PROBLEM,
							   "-%c requires new-setname and settype",
							   cmd2char(CMD_CREATE));

					DP(" check typename");
					set_checktype(typename);
					
					strcpy(set->name, set_name);
					set->levels = set_typename_level;

					DP("load the settypes");
					for (i = 0; i < set_typename_level; i++)
						set->settype[i] = settype_load(set_typename[i]);

				} else {/* set_level != 0 */
					/* New childset to be created */

					DP(" new childset, set_level != 0");

					if (set == NULL) 
						exit_error(OTHER_PROBLEM,
							   "Set %s does not exist.",
							   set_name);
					set_command(&command, CMD_CREATE_CHILD);

					/* typename */
					if (optind < argc
					    && argv[optind][0] != '-')
						typename = argv[optind++];
					else
						exit_error(PARAMETER_PROBLEM,
							   "-%c requires new-setname and settype",
							   cmd2char(CMD_CREATE));

					DP(" check typename");
					set_checktype(typename);
					if (set_typename_level > 1)
						exit_error(PARAMETER_PROBLEM,
							   "-%c requires single settype specified",
							   cmd2char(CMD_CREATE));
					else if (set_level >= set->levels)
						exit_error(PARAMETER_PROBLEM,
							   "specified childset is deeper than "
							   "%s set itself.", set->name);
					else if (strcmp(typename, set->settype[set_level]->typename))
						exit_error(PARAMETER_PROBLEM,
							   "settype '%s' must be used instead of "
							   "'%s' in childset '%s'",
							   set->settype[set_level]->typename,
							   typename, optarg);
				}

				DP("merge options");
				/* Merge the create options */
				opts = merge_options(opts,
					     set->settype[set_level]->create_opts,
					     &set->settype[set_level]->option_offset);

				/* Reset space for settype create data */
				memset(set->settype[set_level]->data, 0,
				       set->settype[set_level]->create_size);

				/* Zero the flags */
				set->settype[set_level]->flags = 0;

				DP("call create_init");
				/* Call the settype create_init */
				set->settype[set_level]->create_init(
						set->settype[set_level]->data);

				break;
			}

		case 'X':{	/* Destroy */
				init_sets();
				
				set_command(&command, CMD_DESTROY);

				if (optarg)
					set = set_find_byname(optarg);
				else if (optind < argc
					   && argv[optind][0] != '-')
					set = set_find_byname(argv[optind++]);
				else
					set = NULL;	/* Mark to destroy all (empty) sets */

				if (set && set_level >= set->levels)
					exit_error(PARAMETER_PROBLEM,
						   "specified childset is deeper than "
						   "%s set itself.", set->name);
				break;
			}

		case 'F':{	/* Flush */
				init_sets();
				
				set_command(&command, CMD_FLUSH);

				DP("flush: %s", optarg);

				if (optarg)
					set = set_find_byname(optarg);
				else if (optind < argc
					   && argv[optind][0] != '-')
					set = set_find_byname(argv[optind++]);
				else
					set = NULL;	/* Mark to flush all */

				if (set && set_level >= set->levels)
					exit_error(PARAMETER_PROBLEM,
						   "specified childset is deeper than "
						   "%s set itself.", set->name);
				break;
			}

		case 'E':{	/* Rename */
				init_sets();
				
				set_command(&command, CMD_RENAME);

				set = set_find_byname(optarg);
				if (set_level)
					exit_error(PARAMETER_PROBLEM,
						   "childsets cannot be swapped");

				if (optind < argc
				    && argv[optind][0] != '-')
					name = argv[optind++];
				else
					exit_error(PARAMETER_PROBLEM,
						   "-%c requires a setname "
						   "and the new name for that set",
						   cmd2char(CMD_RENAME));
				if (strlen(name) > IP_SET_MAXNAMELEN - 1)
					exit_error(PARAMETER_PROBLEM,
						   "Setname '%s' is too long. Max %d characters.",
						   name, IP_SET_MAXNAMELEN - 1);

				/* Set with new name must not exist. */
				set_to = set_checkname(name);
				if (set_to)
					exit_error(PARAMETER_PROBLEM,
						   "Set already exists, cannot rename to %s",
						   name);
				if (set_level)
					exit_error(PARAMETER_PROBLEM,
						   "childsets cannot be swapped");

				break;
			}

		case 'W':{	/* Swap */
				char *name = NULL;

				init_sets();
				
				set_command(&command, CMD_SWAP);

				set = set_find_byname(optarg);
				if (set_level)
					exit_error(PARAMETER_PROBLEM,
						   "childsets cannot be swapped");

				if (optind < argc
				    && argv[optind][0] != '-')
					name = argv[optind++];
				else
					exit_error(PARAMETER_PROBLEM,
						   "-%c requires the names of two "
						   "existing sets",
						   cmd2char(CMD_SWAP));
				if (strlen(name) > IP_SET_MAXNAMELEN - 1)
					exit_error(PARAMETER_PROBLEM,
						   "Setname '%s' is too long. Max %d characters.",
						   name, IP_SET_MAXNAMELEN - 1);

				/* Both sets must exist. */
				set_to = set_find_byname(name);
				if (set_level)
					exit_error(PARAMETER_PROBLEM,
						   "childsets cannot be swapped");

				break;
			}

		case 'L':{	/* List */
				init_sets();
				
				set_command(&command, CMD_LIST);
				if (optarg)
					set = set_find_byname(optarg);
				else if (optind < argc
					   && argv[optind][0] != '-')
					set = set_find_byname(argv[optind++]);
				else
					set = NULL;	/* Mark all */

				if (set && set_level >= set->levels)
					exit_error(PARAMETER_PROBLEM,
						   "specified childset is deeper than "
						   "%s set itself.", set->name);
				break;
			}

		case 'S':{	/* Save */
				init_sets();
				
				set_command(&command, CMD_SAVE);
				if (optarg)
					set = set_find_byname(optarg);
				else if (optind < argc
					   && argv[optind][0] != '-')
					set = set_find_byname(argv[optind++]);
				else
					set = NULL;	/* Mark to save all */

				if (set && set_level >= set->levels)
					exit_error(PARAMETER_PROBLEM,
						   "specified childset is deeper than "
						   "%s set itself.", set->name);
				break;
			}

		case 'R':{	/* Restore */
				init_sets();
				
				set_command(&command, CMD_RESTORE);
				break;
			}

		case 'A':{	/* Add IP */
				init_sets();
				
				set_command(&command, CMD_ADD);

				set = set_find_byname(optarg);

				if (set_level >= set->levels)
					exit_error(PARAMETER_PROBLEM,
						   "specified childset is deeper than "
						   "%s set itself.", set->name);

				/* entries */
				if (optind < argc
				    && argv[optind][0] != '-')
					entries = argv[optind++];
				else
					exit_error(PARAMETER_PROBLEM,
						   "-%c requires setname and entries",
						   cmd2char(CMD_ADD));

				break;
			}

		case 'D':{	/* Del IP */
				init_sets();
				
				set_command(&command, CMD_DEL);

				set = set_find_byname(optarg);

				if (set_level >= set->levels)
					exit_error(PARAMETER_PROBLEM,
						   "specified childset is deeper than "
						   "%s set itself.", set->name);

				if (optind < argc
				    && argv[optind][0] != '-')
					entries = argv[optind++];
				else
					exit_error(PARAMETER_PROBLEM,
						   "-%c requires setname and entries",
						   cmd2char(CMD_DEL));

				break;
			}

		case 'T':{	/* Test IP */
				init_sets();
				
				set_command(&command, CMD_TEST);

				set = set_find_byname(optarg);
				name = optarg;

				if (set_level >= set->levels)
					exit_error(PARAMETER_PROBLEM,
						   "specified childset is deeper than "
						   "%s set itself.", set->name);

				if (optind < argc
				    && argv[optind][0] != '-')
					entries = argv[optind++];
				else
					exit_error(PARAMETER_PROBLEM,
						   "-%c requires setname and entries",
						   cmd2char(CMD_TEST));

				break;
			}

			/* options */

		case 'n':
			add_option(&options, OPT_NUMERIC);
			break;

		case 's':
			add_option(&options, OPT_SORTED);
			break;

		case 'q':
			add_option(&options, OPT_QUIET);
			option_quiet = 1;
			break;

#ifdef IP_SET_DEBUG
		case 'z':	/* debug */
			add_option(&options, OPT_DEBUG);
			option_debug = 1;
			break;
#endif

		case 'c':
			add_option(&options, OPT_CHILDSETS);
			break;

		case 'i':
			add_option(&options, OPT_HINT);
			break;

		case 1:	/* non option */
			printf("Bad argument `%s'\n", optarg);
			exit_tryhelp(2);
			break;	/*always good */

		default:{
				DP("default");

				switch (command) {
				case CMD_CREATE:
					res = set->settype[set_level]->create_parse(
					    		c - set->settype[set_level]->option_offset,
							argv,
							set->settype[set_level]->data,
							&set->settype[set_level]->flags);
					break;

				case CMD_CREATE_CHILD:
					res = set->settype[set_level]->create_parse(
					    		c - set->settype[set_level]->option_offset,
							argv,
							set->settype[set_level]->data,
							&set->settype[set_level]->flags);
					break;

				case CMD_HELP: {
					if (!(settype && settype->hint_parse))
						break;
							
					res = settype->hint_parse(
					    		c - settype->option_offset,
							argv,
							settype->data);
					break;
					}
				default:
					res = 0;	/* failed */
				}	/* switch (command) */


				if (!res)
					exit_error(PARAMETER_PROBLEM,
						   "Unknown arg `%s'",
						   argv[optind - 1]);

			}

			DP("next arg");
		}	/* switch */

	}	/* while( getopt_long() ) */


	if (optind < argc)
		exit_error(PARAMETER_PROBLEM,
			   "unknown arguments found on commandline");
	if (!command)
		exit_error(PARAMETER_PROBLEM, "no command specified");

	/* Check options */
	generic_opt_check(command == CMD_CREATE_CHILD ? CMD_CREATE : command, options);

	DP("cmd: %c", cmd2char(command));

	switch (command) {
	case CMD_CREATE:
		DP("CMD_CREATE");
		set_create(set);
		break;

	case CMD_CREATE_CHILD:
		DP("CMD_CREATE_CHILD");
		set_create_childset(set, options);
		break;

	case CMD_DESTROY:
		set_destroy(set);
		break;

	case CMD_FLUSH:
		set_flush(set, options);
		break;

	case CMD_RENAME:
		set_rename(set, name);
		break;

	case CMD_SWAP:
		set_swap(set, set_to);
		break;

	case CMD_LIST:
		set_list(set, options);
		break;

	case CMD_SAVE:
		set_save(set);
		break;

	case CMD_RESTORE:
		set_restore();
		break;

	case CMD_ADD:
		set_addip(set, entries);
		break;

	case CMD_DEL:
		set_delip(set, entries, options);
		break;

	case CMD_TEST:
		res = set_testip(set, name, entries);
		break;

	case CMD_HELP:
		if (options & OPT_HINT)
			res = settype_hint(settype, options);
		else
			set_help(settype);
		break;

	default:
		/* Will never happen */
		; /* Keep the compiler happy */

	}	/* switch( command ) */

	return res;
}


int main(int argc, char *argv[])
{
	return parse_commandline(argc, argv, 0);

}
