#ifndef __IPSET_H
#define __IPSET_H

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

#include <getopt.h>
#include <sys/types.h>
#include <netdb.h>

#include <linux/netfilter_ipv4/ip_set.h>

char program_name[] = "ipset";
char program_version[] = "1.0";

#define IPSET_LIB_NAME "/libipset_%s.so"
#define PROC_SYS_MODPROBE "/proc/sys/kernel/modprobe"

#define LIST_TRIES 5

/* FIXME: move this to Makefile ? */
#if 1
#define IP_SET_DEBUG
#endif

#ifdef IP_SET_DEBUG
extern int option_debug;
#define DP(format, args...) if (option_debug) 			\
	do {							\
		fprintf(stderr, "%s: %s (DBG): ", __FILE__, __FUNCTION__);\
		fprintf(stderr, format "\n" , ## args);			\
	} while (0)
#else
#define DP(format, args...)
#endif

enum exittype {
	OTHER_PROBLEM = 1,
	PARAMETER_PROBLEM,
	VERSION_PROBLEM
};

struct set_data {
	void *setdata;			/* Hook to set speficic data */
	void *bitmap;			/* Which elements has got a childset (bitmap) */
	void *adt;			/* Add/del/test data */
};

/* The simplistic view of an ipset */
struct set {
	struct set *next;

	char name[IP_SET_MAXNAMELEN];		/* Name of the set */
	unsigned id;				/* Pool id in kernel */
	unsigned levels;			/* Levels we may have in this set */
	unsigned ref;				/* References in kernel */
	struct settype *settype[IP_SET_LEVELS];	/* Pointer to set type functions */
	struct set_data private[IP_SET_LEVELS];	/* Hook to set specific data */
};

#define ADT_ADD		0
#define ADT_DEL		1
#define ADT_TEST	2

struct settype {
	struct settype *next;

	char typename[IP_SET_MAXNAMELEN];
	char typecode;

	int protocol_version;

	/*
	 * Create set
	 */

	/* Size of create data. Will be sent to kernel */
	size_t create_size;

	/* Initialize the create. */
	void (*create_init) (void *data);

	/* Function which parses command options; returns true if it ate an option */
	int (*create_parse) (int c, char *argv[], void *data,
			     unsigned *flags);

	/* Final check; exit if not ok. */
	void (*create_final) (void *data, unsigned int flags);

	/* Pointer to list of extra command-line options for create */
	struct option *create_opts;


	/*
	 * Add/del/test IP
	 */

	/* Size of data. Will be sent to kernel */
	size_t req_size;

	/* Function which parses command options */
	ip_set_ip_t (*adt_parser) (int cmd, const char *option, 
				   void *data, const void * setdata);

	/*
	 * Printing
	 */

	/* Set up the sets headerinfo with data coming from kernel */
	void (*initheader) (void ** setdata, void *data, size_t len);

	/* Set up the sets members with data coming from kernel */
	void (*initmembers) (void * setdata, void *data, size_t len);

	/* Remove the members memory usage */
	void (*killmembers) (void ** setdata);

	/* Pretty print the type-header */
	void (*printheader) (const void * setdata, unsigned options);

	/* Returns an IP address from the set */
	ip_set_ip_t (*getipbyid) (const void * setdata, ip_set_ip_t id);
	
	/* Return the size of the set in ids */
	ip_set_ip_t (*sizeid) (const void * setdata);
	
	/* Pretty print all IPs */
	void (*printips) (const void * setdata, unsigned options);

	/* Pretty print all IPs sorted */
	void (*printips_sorted) (const void * setdata,
				 unsigned options);

	/* Print save arguments for creating the set */
	void (*saveheader) (const void * setdata);

	/* Print save for all IPs */
	void (*saveips) (const void * setdata);

	/* Print usage */
	void (*usage) (void);

	/*
	 * Hint: size of data must be smaller than that of create!
	 */

	/* Size of hint data. Will *not* be sent to kernel */
	size_t hint_size;

	/* Initialize the hint data. */
	void (*hint_init) (void *data);

	/* Function which parses command options; returns true if it ate an option */
	int (*hint_parse) (int c, char *argv[], void *data);

	/* Pointer to list of extra command-line options for hinting */
	struct option *hint_opts;

	/* Hint initialization info */
	void (*hint) (const void *data, ip_set_ip_t * ip, ip_set_ip_t id);

	/* Internal data */
	unsigned int option_offset;
	unsigned int flags;
	void *data;
};

extern void settype_register(struct settype *settype);

/* extern void unregister_settype(set_type_t *set_type); */

extern void exit_error(enum exittype status, char *msg, ...);

extern char *ip_tostring(ip_set_ip_t ip, unsigned options);
extern void parse_ip(const char *str, ip_set_ip_t * ip);
extern void parse_mask(const char *str, ip_set_ip_t * mask);
extern void parse_ipandmask(const char *str, ip_set_ip_t * ip,
			    ip_set_ip_t * mask);
extern char *port_tostring(ip_set_ip_t port, unsigned options);
extern void parse_port(const char *str, ip_set_ip_t * port);
extern int string_to_number(const char *str, unsigned int min, unsigned int max,
		            ip_set_ip_t *port);

extern void *ipset_malloc(size_t size);
extern void ipset_free(void **data);

#endif	/* __IPSET_H */
