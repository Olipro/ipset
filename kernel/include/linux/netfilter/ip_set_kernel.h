#ifndef _IP_SET_KERNEL_H
#define _IP_SET_KERNEL_H

/* Copyright (C) 2003-2010 Jozsef Kadlecsik <kadlec@blackhole.kfki.hu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.  
 */

#ifdef __KERNEL__

/* Complete debug messages */
#define pr_fmt(fmt) "%s %s[%i]: " fmt "\n", __FILE__, __func__, __LINE__

#include <linux/kernel.h>

#endif	/* __KERNEL__ */

#endif /*_IP_SET_H */
