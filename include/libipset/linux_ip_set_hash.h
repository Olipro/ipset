#ifndef __IP_SET_HASH_H
#define __IP_SET_HASH_H

/* Bitmap type specific error codes */
enum {
	IPSET_ERR_HASH_FULL = IPSET_ERR_TYPE_SPECIFIC,
	IPSET_ERR_HASH_ELEM,
	IPSET_ERR_INVALID_PROTO,
	IPSET_ERR_MISSING_PROTO,
};

#endif /* __IP_SET_HASH_H */
