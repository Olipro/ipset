#ifndef _IP_SET_TIMEOUT_H
#define _IP_SET_TIMEOUT_H

/* Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.  
 */

#ifdef __KERNEL__

/* How often should the gc be run at a minimum */
#define IPSET_GC_TIME			(3 * 60)

/* Timeout period depending on the timeout value of the given set */
#define IPSET_GC_PERIOD(timeout) \
	max_t(uint32_t, (timeout)/10, IPSET_GC_TIME)

/* How much msec to sleep before retrying to destroy gc timer */
#define IPSET_DESTROY_TIMER_SLEEP	10

/* Timing out etries: unset and permanent */
#define IPSET_ELEM_UNSET	0
#define IPSET_ELEM_PERMANENT	UINT_MAX/2

#ifdef IP_SET_BITMAP_TIMEOUT
static inline bool
ip_set_timeout_test(unsigned long timeout)
{
	return timeout != IPSET_ELEM_UNSET
	       && (timeout == IPSET_ELEM_PERMANENT
	           || time_after(timeout, jiffies));
}

static inline bool
ip_set_timeout_expired(unsigned long timeout)
{
	return timeout != IPSET_ELEM_UNSET
	       && timeout != IPSET_ELEM_PERMANENT
	       && time_before(timeout, jiffies);
}

static inline unsigned long
ip_set_timeout_set(uint32_t timeout)
{
	unsigned long t;
	
	if (!timeout)
		return IPSET_ELEM_PERMANENT;
	
	t = timeout * HZ + jiffies;
	if (t == IPSET_ELEM_UNSET || t == IPSET_ELEM_PERMANENT)
		t++;
	
	return t;
}

static inline uint32_t
ip_set_timeout_get(unsigned long timeout)
{
	return timeout == IPSET_ELEM_PERMANENT ? 0 : (timeout - jiffies)/HZ;
}

#else

static inline bool
ip_set_timeout_test(unsigned long timeout)
{
	return timeout == IPSET_ELEM_UNSET || time_after(timeout, jiffies);
}

static inline bool
ip_set_timeout_expired(unsigned long timeout)
{
	return timeout != IPSET_ELEM_UNSET && time_before(timeout, jiffies);
}

static inline unsigned long
ip_set_timeout_set(uint32_t timeout)
{
	unsigned long t;
	
	if (!timeout)
		return IPSET_ELEM_UNSET;
	
	t = timeout * HZ + jiffies;
	if (t == IPSET_ELEM_UNSET)
		t++;
	
	return t;
}

static inline uint32_t
ip_set_timeout_get(unsigned long timeout)
{
	return timeout == IPSET_ELEM_UNSET ? 0 : (timeout - jiffies)/HZ;
}
#endif /* IP_SET_BITMAP_TIMEOUT */

#endif	/* __KERNEL__ */

#endif /*_IP_SET_TIMEOUT_H */
