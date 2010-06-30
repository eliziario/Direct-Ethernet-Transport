/*
 * Intel(R) Direct Ethernet Transport (Intel(R) DET)
 * RDMA emulation protocol driver.
 * Copyright (c) 2008, Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#ifndef __DET_DEBUG_H__
#define __DET_DEBUG_H__

#ifndef	__KERNEL__
#error Kernel mode header file included in user mode build
#endif

#ifdef	CONFIG_DET_DEBUG

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,16)
#include <linux/config.h>
#else
#include <linux/autoconf.h>
#endif

#ifdef CONFIG_KGDB
#include <linux/kgdb.h>
#define BREAK	breakpoint
#else
#define BREAK	BUG
#endif

/*
 * Assert with traditional printf/panic
 */
#ifdef	CONFIG_KERNEL_ASSERTS
/* kgdb stuff */

#define assert(p)		KERNEL_ASSERT(#p, p)
#else	/* CONFIG_KERNEL_ASSERTS */
#define assert(p)                                                      \
do {									\
	if (!(p)) {							\
		printk(KERN_CRIT "Assertion at %s:%d assert(%s)\n",	\
			__FILE__, __LINE__, #p);			\		
	}								\
} while (0)
#endif	/* CONFIG_KERNEL_ASSERTS */

#define dprintk(fmt, args...)						\
	printk(KERN_INFO "%s:%s() [%d]: " fmt,				\
		__FILE__, __FUNCTION__, __LINE__, ##args)

#define	enter()			dprintk("[\n")
#define	leave()			dprintk("]\n")

#else	/* CONFIG_DET_DEBUG */

#define assert(p)		do { } while (0)
#define dprintk(fmt, args...)	do { } while (0)
#define	enter()			do { } while (0)
#define	leave()			do { } while (0)

#endif	/* CONFIG_DET_DEBUG */

#endif /* __DET_DEBUG_H__ */

