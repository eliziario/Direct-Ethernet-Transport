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

#ifndef __DET_TYPES32_H__
#define __DET_TYPES32_H__

#include <linux/types.h>
#include <linux/compat.h>

#ifndef	__KERNEL__
#error Kernel mode header file included in user mode build
#endif


#ifdef CONFIG_COMPAT

/*
 * 32-bit clean DET structure definitions.
 * Comments indicate what pointer fields actually contain.  Pointer fields
 * are meaningless to the kernel and are filled in by the user-mode libary.
 */

struct det_record32 {
	enum det_event_code		code;
	enum det_type			type;
	compat_uptr_t			handle;		/* (void *) */
};


struct det_qp_create32 {
	compat_uptr_t			sq_cq;		/* (struct det_cq *) */
	compat_uptr_t			rq_cq;		/* (struct det_cq *) */
	__u32				sq_size;
	__u32				rq_size;
	__u32				sq_sges;
	__u32				rq_sges;
	__u32				max_or;
	__u32				max_ir;
};


struct det_qp_attr32 {
	compat_uptr_t			pd;		/* (struct det_pd *) */
	compat_uptr_t			sq_cq;		/* (struct det_cq *) */
	compat_uptr_t			rq_cq;		/* (struct det_cq *) */
	enum det_qp_state		state;
	__u32				mtu_size;
	__u32				sq_size;
	__u32				rq_size;
	__u32				sq_sges;
	__u32				rq_sges;
	__u32				max_or;
	__u32				max_ir;
	__u32				local_qp_num;
	__u32				remote_qp_num;
	struct det_mac_addr		local_mac;
	struct det_mac_addr		remote_mac;
};


struct det_mem_attr32 {
	compat_uptr_t			pd;		/* (struct det_pd *) */
	net32_t				r_key;
	__u32				length;
	enum det_access_ctrl		access;
};


struct det_mr_attr32 {
	struct det_mem_attr		base;
	__u32				l_key;
};


struct det_mr_mod32 {
	enum det_mr_mod_flags		flags;
	compat_uptr_t			pd;		/* (struct det_pd *) */
	enum det_access_ctrl		access;
};


struct det_mw_attr32 {
	struct det_mem_attr		base;
};

#endif /* CONFIG_COMPAT */

#endif /* __DET_TYPES32_H__ */
