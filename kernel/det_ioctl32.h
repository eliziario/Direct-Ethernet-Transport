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

#ifndef __DET_IOCTL32_H__
#define __DET_IOCTL32_H__

#include <linux/ioctl.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#include <linux/ioctl32.h>
#endif

#include "det_types32.h"

#ifndef	__KERNEL__
#error Kernel mode header file included in user mode build
#endif


void det_register_ioctl32(void);
void det_unregister_ioctl32(void);


#ifdef CONFIG_COMPAT

/*
 * 32-bit clean ioctl structure definitions.
 * Comments indicate what pointer fields actually contain.
 */

struct det_ioc32_event {
	__u64			context;
	struct det_record32	record;
} __attribute__((packed));


struct det_ioc32_wait_on_event {
	compat_uptr_t		event;		/* (struct det_ioc32_event *) */
	int			event_id;
	__s32			timeout;
} __attribute__((packed));


struct det_ioc32_generate_event {
	compat_uptr_t		handle;		/* (void *) */
	int			event_id;
} __attribute__((packed));


struct det_ioc32_open_nic {
	__u64			context;
	compat_uptr_t		nic_id;		/* (int *) */
	char			ifname[IFNAMSIZ];
	int			event_id;
} __attribute__((packed));


struct det_ioc32_query_nic {
	compat_uptr_t		attr;		/* (struct det_nic_attr *) */
	int			nic_id;
} __attribute__((packed));


struct det_ioc32_close_nic {
	compat_uptr_t		nr_events;	/* (int *) */
	int			nic_id;
} __attribute__((packed));


struct det_ioc32_alloc_pd {
	compat_uptr_t		pd_id;		/* (int *) */
	int			nic_id;
} __attribute__((packed));


struct det_ioc32_create_cq {
	__u64			context;
	compat_uptr_t		cq_id;		/* (int *) */
	compat_uptr_t		attr;		/* (struct det_cq_attr *) */
	__u32			size;
	int			nic_id;
	int			event_id;
} __attribute__((packed));


struct det_ioc32_query_cq {
	compat_uptr_t		attr;		/* (struct det_cq_attr *) */
	int			cq_id;
} __attribute__((packed));


struct det_ioc32_resize_cq {
	compat_uptr_t		attr;		/* (struct det_cq_attr *) */
	__u32			size;
	int			cq_id;
} __attribute__((packed));


struct det_ioc32_poll_cq {
	compat_uptr_t		wc_array;	/* (struct det_wc *) */
	compat_uptr_t		p_num_wc;	/* (__u32 *) */
	__u32			num_wc;
	int			cq_id;
} __attribute__((packed));


struct det_ioc32_destroy_cq {
	compat_uptr_t		nr_events;	/* (int *) */
	int			cq_id;
} __attribute__((packed));


struct det_ioc32_create_qp {
	__u64			context;
	compat_uptr_t		qp_id;		/* (int *) */
	const compat_uptr_t	create;		/* (struct det_qp_create32 *) */
	compat_uptr_t		attr;		/* (struct det_qp_attr32 *) */
	int			sq_cq_id;
	int			rq_cq_id;
	int			pd_id;
} __attribute__((packed));


struct det_ioc32_query_qp {
	compat_uptr_t		attr;		/* (struct det_qp_attr32 *) */
	int			qp_id;
} __attribute__((packed));


struct det_ioc32_modify_qp {
	compat_uptr_t		mod;		/* (struct det_qp_mod *) */
	compat_uptr_t		attr;		/* (struct det_qp_attr32 *) */
	int			qp_id;
} __attribute__((packed));


struct det_ioc32_destroy_qp {
	compat_uptr_t		nr_events;	/* (int *) */
	int			qp_id;
} __attribute__((packed));


struct det_ioc32_reg_mr {
	compat_uptr_t		mr_id;		/* (int *) */
	compat_uptr_t		l_key;		/* (__u32 *) */
	compat_uptr_t		r_key;		/* (net32_t *) */
	struct det_mr_reg	mr_reg;
	int			pd_id;
} __attribute__((packed));


struct det_ioc32_query_mr {
	compat_uptr_t		attr;		/* (struct det_mr_attr32 *) */
	int			mr_id;
} __attribute__((packed));


struct det_ioc32_modify_mr {
	const compat_uptr_t	mod;		/* (struct det_mr_mod32 *) */
	compat_uptr_t		l_key;		/* (__u32 *) */
	compat_uptr_t		r_key;		/* (net32_t *) */
	int			mr_id;
	int			pd_id;
} __attribute__((packed));


struct det_ioc32_reg_shared {
	compat_uptr_t		shared_id;	/* (int *) */
	compat_uptr_t		l_key;		/* (__u32 *) */
	compat_uptr_t		r_key;		/* (net32_t *) */
	enum det_access_ctrl	access;
	int			pd_id;
	int			mr_id;
} __attribute__((packed));


struct det_ioc32_create_mw {
	compat_uptr_t		mw_id;		/* (int *) */
	int			pd_id;
} __attribute__((packed));


struct det_ioc32_query_mw {
	compat_uptr_t		attr;		/* (struct det_mw_attr *) */
	int			mw_id;
} __attribute__((packed));


struct det_ioc32_send {
	__u64			wr_id;
	const compat_uptr_t	ds_array;	/* (struct det_local_ds *) */
	__u32			num_ds;
	__u32			immediate_data;
	enum det_wr_flags	flags;
	int			qp_id;
	struct det_local_ds	local_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc32_recv {
	__u64			wr_id;
	const compat_uptr_t	ds_array;	/* (struct det_local_ds *) */
	__u32			num_ds;
	int			qp_id;
	struct det_local_ds	local_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc32_read {
	__u64			wr_id;
	const compat_uptr_t	ds_array;	/* (struct det_local_ds *) */
	__u32			num_ds;
	net64_t			remote_address;
	net32_t			remote_key;
	enum det_wr_flags	flags;
	int			qp_id;
	struct det_local_ds	local_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc32_write {
	__u64			wr_id;
	const compat_uptr_t	ds_array;	/* (struct det_local_ds *) */
	__u32			num_ds;
	net64_t			remote_address;
	net32_t			remote_key;
	__u32			immediate_data;
	enum det_wr_flags	flags;
	int			qp_id;
	struct det_local_ds	local_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc32_bind {
	__u64			wr_id;
	int			qp_id;
	int			mr_id;
	int			mw_id;
	compat_uptr_t		r_key;		/* (net32_t *) */
	__u64			vaddr;
	__u32			length;
	enum det_access_ctrl	access;
	enum det_wr_flags	flags;
} __attribute__((packed));


struct det_ioc32_create_co {
	__u64			context;
	net64_t			tag;
	int			size;
	int			rank;
	signed long		timeout;
	compat_uptr_t		co_id;		/* (int *) */
	int			pd_id;
	int			cq_id;
} __attribute__((packed));


struct det_ioc32_destroy_co {
	compat_uptr_t		nr_events;	/* (int *) */
	int			co_id;
} __attribute__((packed));


struct det_ioc32_scatterv {
	__u64				wr_id;
	const compat_uptr_t		src_ds_array;	/* (struct det_local_ds *) */
	struct det_local_ds		dst_ds;
	int				root;
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc32_gatherv {
	__u64				wr_id;
	struct det_local_ds		src_ds;
	const compat_uptr_t		dst_ds_array;	/* (struct det_local_ds *) */
	int				root;
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc32_allgatherv {
	__u64				wr_id;
	const struct det_local_ds	src_ds;
	const compat_uptr_t		dst_ds_array;	/* (struct det_local_ds *) */
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc32_alltoallv {
	__u64				wr_id;
	const compat_uptr_t		src_ds_array;	/* (struct det_local_ds *) */
	const compat_uptr_t		dst_ds_array;	/* (struct det_local_ds *) */
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


#define	DET_IOC32_QUERY		_IOW(DET_MAGIC,  1, unsigned int)

#define	DET_IOC32_CREATE_EVENT	_IOR(DET_MAGIC,  2, unsigned int)
#define	DET_IOC32_WAIT_ON_EVENT	_IOW(DET_MAGIC,  3, struct det_ioc32_wait_on_event)
#define	DET_IOC32_GENERATE_EVENT _IOW(DET_MAGIC, 4, struct det_ioc32_generate_event)
#define	DET_IOC32_DESTROY_EVENT	_IOW(DET_MAGIC,  5, unsigned int)

#define	DET_IOC32_OPEN_NIC	_IOW(DET_MAGIC,  6, struct det_ioc32_open_nic)
#define	DET_IOC32_QUERY_NIC	_IOW(DET_MAGIC,  7, struct det_ioc32_query_nic)
#define	DET_IOC32_CLOSE_NIC	_IOW(DET_MAGIC,  8, struct det_ioc32_close_nic)

#define	DET_IOC32_ALLOC_PD	_IOW(DET_MAGIC,  9, struct det_ioc32_alloc_pd)
#define	DET_IOC32_DEALLOC_PD	_IOW(DET_MAGIC, 10, unsigned int)

#define	DET_IOC32_CREATE_CQ	_IOW(DET_MAGIC, 11, struct det_ioc32_create_cq)
#define	DET_IOC32_QUERY_CQ	_IOW(DET_MAGIC, 12, struct det_ioc32_query_cq)
#define	DET_IOC32_RESIZE_CQ	_IOW(DET_MAGIC, 13, struct det_ioc32_resize_cq)
/*	DET_IOC_ARM_CQ		is 32-bit compatible */
#define	DET_IOC32_POLL_CQ	_IOW(DET_MAGIC, 15, struct det_ioc32_poll_cq)
#define	DET_IOC32_DESTROY_CQ	_IOW(DET_MAGIC, 16, struct det_ioc32_destroy_cq)

#define	DET_IOC32_CREATE_QP	_IOW(DET_MAGIC, 17, struct det_ioc32_create_qp)
#define	DET_IOC32_QUERY_QP	_IOW(DET_MAGIC, 18, struct det_ioc32_query_qp)
#define	DET_IOC32_MODIFY_QP	_IOW(DET_MAGIC, 19, struct det_ioc32_modify_qp)
#define	DET_IOC32_DESTROY_QP	_IOW(DET_MAGIC, 20, struct det_ioc32_destroy_qp)

#define	DET_IOC32_REG_MR	_IOW(DET_MAGIC, 21, struct det_ioc32_reg_mr)
#define	DET_IOC32_QUERY_MR	_IOW(DET_MAGIC, 22, struct det_ioc32_query_mr)
#define	DET_IOC32_MODIFY_MR	_IOW(DET_MAGIC, 23, struct det_ioc32_modify_mr)
#define	DET_IOC32_REG_SHARED	_IOW(DET_MAGIC, 24, struct det_ioc32_reg_shared)
#define	DET_IOC32_DEREG_MR	_IOW(DET_MAGIC, 25, unsigned int)

#define	DET_IOC32_CREATE_MW	_IOW(DET_MAGIC, 26, struct det_ioc32_create_mw)
#define	DET_IOC32_QUERY_MW	_IOW(DET_MAGIC, 27, struct det_ioc32_query_mw)
#define	DET_IOC32_DESTROY_MW	_IOW(DET_MAGIC, 28, unsigned int)

#define	DET_IOC32_SEND		_IOW(DET_MAGIC, 29, struct det_ioc32_send)
#define	DET_IOC32_RECV		_IOW(DET_MAGIC, 30, struct det_ioc32_recv)
#define	DET_IOC32_READ		_IOW(DET_MAGIC, 31, struct det_ioc32_read)
#define	DET_IOC32_WRITE		_IOW(DET_MAGIC, 32, struct det_ioc32_write)
#define	DET_IOC32_BIND		_IOW(DET_MAGIC, 33, struct det_ioc32_bind)
/*	DET_IOC_COMP_EXCH	is 32-bit compatible */
/*	DET_IOC_FETCH_ADD	is 32-bit compatible */

#define	DET_IOC32_CREATE_CO	_IOW(DET_MAGIC, 36, struct det_ioc32_create_co)
/*	DET_IOC_JOIN		is 32-bit compatible */
#define	DET_IOC32_DESTROY_CO	_IOW(DET_MAGIC, 38, struct det_ioc32_destroy_co)
/*	DET_IOC_BARRIER		is 32-bit compatible */
/*	DET_IOC_BCAST		is 32-bit compatible */
/*	DET_IOC_SCATTER		is 32-bit compatible */
#define	DET_IOC32_SCATTERV	_IOW(DET_MAGIC, 42, struct det_ioc32_scatterv)
/*	DET_IOC_GATHER		is 32-bit compatible */
#define	DET_IOC32_GATHERV	_IOW(DET_MAGIC, 44, struct det_ioc32_gatherv)
/*	DET_IOC_ALLGATHER	is 32-bit compatible */
#define	DET_IOC32_ALLGATHERV	_IOW(DET_MAGIC, 46, struct det_ioc32_allgatherv)
/*	DET_IOC_ALLTOALL	is 32-bit compatible */
#define	DET_IOC32_ALLTOALLV	_IOW(DET_MAGIC, 48, struct det_ioc32_alltoallv)

#endif /* CONFIG_COMPAT */

#endif /* __DET_IOCTL32_H__ */
