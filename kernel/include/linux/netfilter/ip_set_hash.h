#ifndef __IP_SET_HASH_H
#define __IP_SET_HASH_H

/* Bitmap type specific error codes */
enum {
	IPSET_ERR_HASH_FULL = IPSET_ERR_TYPE_SPECIFIC,
	IPSET_ERR_HASH_ELEM,
};

#ifdef __KERNEL__

#define initval_t uint32_t

#define IPSET_DEFAULT_HASHSIZE		1024
#define IPSET_DEFAULT_MAXELEM		65536
#define IPSET_DEFAULT_PROBES		4
#define IPSET_DEFAULT_RESIZE		50

#endif /* __KERNEL__ */
	
#endif /* __IP_SET_HASH_H */
