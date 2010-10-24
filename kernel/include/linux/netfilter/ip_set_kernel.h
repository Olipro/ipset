#ifndef _IP_SET_KERNEL_H
#define _IP_SET_KERNEL_H

#ifdef __KERNEL__

#ifdef CONFIG_DEBUG_KERNEL
/* Complete debug messages */
#define pr_fmt(fmt) "%s %s[%i]: " fmt "\n", __FILE__, __func__, __LINE__
#endif

#include <linux/kernel.h>

#endif	/* __KERNEL__ */

#endif /*_IP_SET_H */
