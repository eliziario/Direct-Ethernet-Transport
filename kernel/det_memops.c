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

#include "det_driver.h"

int memops_method	= MEMOPS_UNINITIALIZED;
u32 memops_cache_size	= 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,9)
#define cpu_has_xmm2	cpu_has_sse2
#endif

char *det_memops_method_str(const int method)
{
	switch (method) {
		case MEMOPS_USE_REG:		return "regs";
		case MEMOPS_USE_MMX:		return "mmx";
		case MEMOPS_USE_SSE2:		return "sse2";
		case MEMOPS_USE_STDLIB:		return "memcpy";
		case MEMOPS_UNINITIALIZED:
		default:			break;
	}
	return "uninitialized";

}

#ifndef CONFIG_IA64
int valid_memops_method(int method)
{
	switch (method) {
		case MEMOPS_USE_REG:
		case MEMOPS_USE_STDLIB:		return 1;
		case MEMOPS_USE_MMX:		return cpu_has_mmx;
		case MEMOPS_USE_SSE2:		return cpu_has_xmm2;
		case MEMOPS_UNINITIALIZED:
		default:			break;
	}
	return 0;
}

static inline void cpuid4(u32 index, u32 *eax, u32 *ebx, u32 *ecx, u32 *edx)
{
	__asm__("cpuid"
		: "=a" (*eax),
		  "=b" (*ebx),
		  "=c" (*ecx),
		  "=d" (*edx)
		: "" "a"(4), "c"(index));
}
#endif

int det_init_memops(void)
{
#ifdef CONFIG_IA64
	return memops_method = MEMOPS_USE_STDLIB;
#else

	/* Validate and override any prior invalid memops_method setting. */
	if (valid_memops_method(memops_method))
		return memops_method;

	preempt_disable();
	if (!strcmp("Pentium III (Coppermine)", current_cpu_data.x86_model_id)) {
		preempt_enable();
		return memops_method = MEMOPS_USE_STDLIB;
	}

	memops_method = cpu_has_xmm2 ? MEMOPS_USE_SSE2 :
			cpu_has_mmx  ? MEMOPS_USE_MMX  :
				       MEMOPS_USE_REG;
	memops_cache_size = current_cpu_data.x86_cache_size;

	if (current_cpu_data.cpuid_level >= 4) {
		u32 i, size, eax, ebx, ecx, edx;

		for (i = eax = 0; eax & 0x1f; i++) {
			/* See Intel Instruction Set Reference for CPUID */
			cpuid4(i++, &eax, &ebx, &ecx, &edx);
			size  = ((ebx >>  0) & 0xfff) + 1; /* System Coherency Line Size */
			size *= ((ebx >> 12) & 0x3ff) + 1; /* Physical Line Partitions	 */
			size *= ((ebx >> 22) & 0x3ff) + 1; /* Ways of Associativity	 */
			size *= ecx + 1;		   /* Number of Sets		 */

			if (memops_cache_size < size)
				memops_cache_size = size;
		}
	}
	preempt_enable();

	memops_cache_size *= 1024;
	return memops_method;
#endif
}
