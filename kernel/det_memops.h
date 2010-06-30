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

#ifndef __DET_MEMOPS_H__
#define __DET_MEMOPS_H__

/* Definitions must match usage in _det_memcpy */
#define MEMOPS_UNINITIALIZED	-1
#define MEMOPS_USE_REG		0
#define MEMOPS_USE_MMX		1
#define MEMOPS_USE_SSE2		2
#define MEMOPS_USE_STDLIB	3	/* standard C library routines */

extern int memops_method;

int det_init_memops(void);

char *det_memops_method_str(const int method);

void *_det_memcpy(void *to, const void *from, const size_t size);

#ifdef CONFIG_IA64

static inline void *det_memcpy(void *to, void *from, const size_t size)
{
	return memcpy(to, from, size);
}

#else	/* CONFIG_IA64 */

static inline void *det_memcpy(void *to, void *from, const size_t size)
{
	prefetch_range(from, size);

#ifdef memops_broken
	/*
	 * det_init_memops() must be called manually prior to this
	 * function in order to use the MEMOPS_USE_STDLIB check.
	 */
	return (memops_method == MEMOPS_USE_STDLIB) ?
		memcpy(to, from, size) : _det_memcpy(to, from, size);
#else
	return memcpy(to, from, size);
#endif
}
#endif /* !CONFIG_IA64 */

#endif /* __DET_MEMOPS_H__ */
