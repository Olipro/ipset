#ifndef __IP_SET_BITMAP_H
#define __IP_SET_BITMAP_H

/* Bitmap type specific error codes */
enum {
	IPSET_ERR_BITMAP_RANGE = IPSET_ERR_TYPE_SPECIFIC,
	IPSET_ERR_BITMAP_RANGE_SIZE,
};

#ifdef __KERNEL__
#define IPSET_BITMAP_MAX_RANGE	0x0000FFFF

/* Common functions */

static inline uint32_t
range_to_mask(uint32_t from, uint32_t to, uint8_t *bits)
{
	uint32_t mask = 0xFFFFFFFE;
	
	*bits = 32;
	while (--(*bits) > 0 && mask && (to & mask) != from)
		mask <<= 1;
		
	return mask;
}

#endif /* __KERNEL__ */
	
#endif /* __IP_SET_BITMAP_H */
