/*
 * Intel(R) Direct Ethernet Transport (Intel(R) DET)
 * RDMA emulation protocol driver.
 * Copyright (c) 2008, Intel Corporation.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This library is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#ifndef __DET_IOCTL_H__
#define __DET_IOCTL_H__

#include <linux/ioctl.h>

#include "det_types.h"


struct det_verb {
	__u64				arg;
	int				cmd;
} __attribute__((packed));


struct det_ioc_event {
	__u64				context;
	struct det_record		record;
} __attribute__((packed));


struct det_ioc_wait_on_event {
	struct det_ioc_event		*event;
	int				event_id;
	signed long			timeout;
} __attribute__((packed));


struct det_ioc_generate_event {
	void				*handle;
	int				event_id;
} __attribute__((packed));


struct det_ioc_open_nic {
	__u64				context;
	int				*nic_id;
	char				ifname[IFNAMSIZ];
	int				event_id;
} __attribute__((packed));


struct det_ioc_query_nic {
	struct det_nic_attr		*attr;
	int				nic_id;
} __attribute__((packed));


struct det_ioc_close_nic {
	int				*nr_events;
	int				nic_id;
} __attribute__((packed));


struct det_ioc_alloc_pd {
	int				*pd_id;
	int				nic_id;
} __attribute__((packed));


struct det_ioc_create_cq {
	__u64				context;
	int				*cq_id;
	struct det_cq_attr		*attr;
	__u32				size;
	int				nic_id;
	int				event_id;
} __attribute__((packed));


struct det_ioc_query_cq {
	struct det_cq_attr		*attr;
	int				cq_id;
} __attribute__((packed));


struct det_ioc_resize_cq {
	struct det_cq_attr		*attr;
	__u32				size;
	int				cq_id;
} __attribute__((packed));


struct det_ioc_arm_cq {
	int				cq_id;
	enum det_cq_arm			arm;
	__u32				threshold;
} __attribute__((packed));


struct det_ioc_poll_cq {
	struct det_wc			*wc_array;
	__u32				*p_num_wc;
	__u32				num_wc;
	int				cq_id;
} __attribute__((packed));


struct det_ioc_destroy_cq {
	int				*nr_events;
	int				cq_id;
} __attribute__((packed));


struct det_ioc_create_qp {
	__u64				context;
	int				*qp_id;
	const struct det_qp_create	*create;
	struct det_qp_attr		*attr;
#ifdef	CONFIG_DET_DOORBELL
	struct det_doorbell		*doorbell;
#endif
	int				sq_cq_id;
	int				rq_cq_id;
	int				pd_id;
} __attribute__((packed));


struct det_ioc_query_qp {
	struct det_qp_attr		*attr;
	int				qp_id;
} __attribute__((packed));


struct det_ioc_modify_qp {
	const struct det_qp_mod		*mod;
	struct det_qp_attr		*attr;
	int				qp_id;
} __attribute__((packed));


struct det_ioc_destroy_qp {
	int				*nr_events;
	int				qp_id;
} __attribute__((packed));


struct det_ioc_reg_mr {
	int				*mr_id;
	__u32				*l_key;
	net32_t				*r_key;
	struct det_mr_reg		mr_reg;
	int				pd_id;
} __attribute__((packed));


struct det_ioc_query_mr {
	struct det_mr_attr		*attr;
	int				mr_id;
} __attribute__((packed));


struct det_ioc_modify_mr {
	const struct det_mr_mod		*mod;
	__u32				*l_key;
	net32_t				*r_key;
	int				mr_id;
	int				pd_id;
} __attribute__((packed));


struct det_ioc_reg_shared {
	int				*shared_id;
	__u32				*l_key;
	net32_t				*r_key;
	enum det_access_ctrl		access;
	int				pd_id;
	int				mr_id;
} __attribute__((packed));


struct det_ioc_create_mw {
	int				*mw_id;
	int				pd_id;
} __attribute__((packed));


struct det_ioc_query_mw {
	struct det_mw_attr		*attr;
	int				mw_id;
} __attribute__((packed));


#define	MAX_IOC_NUM_DS		2	/* Max inline with ioctl */


struct det_ioc_send {
	__u64				wr_id;
	const struct det_local_ds	*ds_array;
	__u32				num_ds;
	__u32				immediate_data;
	enum det_wr_flags		flags;
	int				qp_id;
	struct det_local_ds		local_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc_recv {
	__u64				wr_id;
	const struct det_local_ds	*ds_array;
	__u32				num_ds;
	int				qp_id;
	struct det_local_ds		local_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc_read {
	__u64				wr_id;
	const struct det_local_ds	*ds_array;
	__u32				num_ds;
	net64_t				remote_address;
	net32_t				remote_key;
	enum det_wr_flags		flags;
	int				qp_id;
	struct det_local_ds		local_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc_write {
	__u64				wr_id;
	const struct det_local_ds	*ds_array;
	__u32				num_ds;
	net64_t				remote_address;
	net32_t				remote_key;
	__u32				immediate_data;
	enum det_wr_flags		flags;
	int				qp_id;
	struct det_local_ds		local_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc_bind {
	__u64				wr_id;
	int				qp_id;
	int				mr_id;
	int				mw_id;
	net32_t				*r_key;
	__u64				vaddr;
	__u32				length;
	enum det_access_ctrl		access;
	enum det_wr_flags		flags;
} __attribute__((packed));


struct det_ioc_comp_exch {
	__u64				wr_id;
	__u64				comp_operand;
	__u64				exch_operand;
	net64_t				remote_address;
	net32_t				remote_key;
	struct det_local_ds		local_ds;
	enum det_wr_flags		flags;
	int				qp_id;
} __attribute__((packed));


struct det_ioc_fetch_add {
	__u64				wr_id;
	__u64				add_operand;
	net64_t				remote_address;
	net32_t				remote_key;
	struct det_local_ds		local_ds;
	enum det_wr_flags		flags;
	int				qp_id;
} __attribute__((packed));


struct det_ioc_create_co {
	__u64				context;
#ifdef	CONFIG_DET_DOORBELL
	struct det_doorbell		*doorbell;
#endif
	int				*co_id;
	int				pd_id;
	int				cq_id;
} __attribute__((packed));


struct det_ioc_join {
	__u64				wr_id;
	net64_t				tag;
	int				size;
	int				rank;
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc_destroy_co {
	int				*nr_events;
	int				co_id;
} __attribute__((packed));


struct det_ioc_barrier {
	__u64				wr_id;
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc_bcast {
	__u64				wr_id;
	struct det_local_ds		ds;
	int				root;
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc_scatter {
	__u64				wr_id;
	struct det_local_ds		src_ds;
	struct det_local_ds		dst_ds;
	int				root;
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc_scatterv {
	__u64				wr_id;
	const struct det_local_ds	*src_ds_array;
	struct det_local_ds		dst_ds;
	int				root;
	enum det_wr_flags		flags;
	int				co_id;
	struct det_local_ds		src_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc_gather {
	__u64				wr_id;
	struct det_local_ds		src_ds;
	struct det_local_ds		dst_ds;
	int				root;
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc_gatherv {
	__u64				wr_id;
	struct det_local_ds		src_ds;
	const struct det_local_ds	*dst_ds_array;
	int				root;
	enum det_wr_flags		flags;
	int				co_id;
	struct det_local_ds		dst_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc_allgather {
	__u64				wr_id;
	struct det_local_ds		src_ds;
	struct det_local_ds		dst_ds;
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc_allgatherv {
	__u64				wr_id;
	struct det_local_ds		src_ds;
	const struct det_local_ds	*dst_ds_array;
	enum det_wr_flags		flags;
	int				co_id;
	struct det_local_ds		dst_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


struct det_ioc_alltoall {
	__u64				wr_id;
	struct det_local_ds		src_ds;
	struct det_local_ds		dst_ds;
	enum det_wr_flags		flags;
	int				co_id;
} __attribute__((packed));


struct det_ioc_alltoallv {
	__u64				wr_id;
	const struct det_local_ds	*src_ds_array;
	const struct det_local_ds	*dst_ds_array;
	enum det_wr_flags		flags;
	int				co_id;
	struct det_local_ds		src_ds[MAX_IOC_NUM_DS];
	struct det_local_ds		dst_ds[MAX_IOC_NUM_DS];
} __attribute__((packed));


#ifdef	CONFIG_DET_DOORBELL
struct det_doorbell {
	volatile int			ring;
	unsigned int			ioctl_cmd;
	unsigned int			co_last_wc_count;
	unsigned int			co_current_wc_count;
	struct det_wc			co_wc;
	union	{
		struct det_ioc_send		send;
		struct det_ioc_recv		recv;
		struct det_ioc_read		read;
		struct det_ioc_write		write;
		struct det_ioc_comp_exch	comp_exch;
		struct det_ioc_fetch_add	fetch_add;
		struct det_ioc_join		join;
		struct det_ioc_barrier		barrier;
		struct det_ioc_bcast		bcast;
		struct det_ioc_scatter		scatter;
		struct det_ioc_scatterv		scatterv;
		struct det_ioc_gather		gather;
		struct det_ioc_gatherv		gatherv;
		struct det_ioc_allgather	allgather;
		struct det_ioc_allgatherv	allgatherv;
		struct det_ioc_alltoall		alltoall;
		struct det_ioc_alltoallv	alltoallv;
	};
} __attribute__((packed));
#endif


#define	DET_MAGIC		0xDE	/* Direct Ethernet - clever huh? */

#define	DET_IOC_QUERY		_IOR(DET_MAGIC,  1, unsigned long)

#define	DET_IOC_CREATE_EVENT	_IOR(DET_MAGIC,  2, unsigned long)
#define	DET_IOC_WAIT_ON_EVENT	_IOW(DET_MAGIC,  3, struct det_ioc_wait_on_event)
#define	DET_IOC_GENERATE_EVENT	_IOW(DET_MAGIC,  4, struct det_ioc_generate_event)
#define	DET_IOC_DESTROY_EVENT	_IOW(DET_MAGIC,  5, unsigned long)

#define	DET_IOC_OPEN_NIC	_IOW(DET_MAGIC,  6, struct det_ioc_open_nic)
#define	DET_IOC_QUERY_NIC	_IOW(DET_MAGIC,  7, struct det_ioc_query_nic)
#define	DET_IOC_CLOSE_NIC	_IOW(DET_MAGIC,  8, struct det_ioc_close_nic)

#define	DET_IOC_ALLOC_PD	_IOW(DET_MAGIC,  9, struct det_ioc_alloc_pd)
#define	DET_IOC_DEALLOC_PD	_IOW(DET_MAGIC, 10, unsigned long)

#define	DET_IOC_CREATE_CQ	_IOW(DET_MAGIC, 11, struct det_ioc_create_cq)
#define	DET_IOC_QUERY_CQ	_IOW(DET_MAGIC, 12, struct det_ioc_query_cq)
#define	DET_IOC_RESIZE_CQ	_IOW(DET_MAGIC, 13, struct det_ioc_resize_cq)
#define	DET_IOC_ARM_CQ		_IOW(DET_MAGIC, 14, struct det_ioc_arm_cq)
#define	DET_IOC_POLL_CQ		_IOW(DET_MAGIC, 15, struct det_ioc_poll_cq)
#define	DET_IOC_DESTROY_CQ	_IOW(DET_MAGIC, 16, struct det_ioc_destroy_cq)

#define	DET_IOC_CREATE_QP	_IOW(DET_MAGIC, 17, struct det_ioc_create_qp)
#define	DET_IOC_QUERY_QP	_IOW(DET_MAGIC, 18, struct det_ioc_query_qp)
#define	DET_IOC_MODIFY_QP	_IOW(DET_MAGIC, 19, struct det_ioc_modify_qp)
#define	DET_IOC_DESTROY_QP	_IOW(DET_MAGIC, 20, struct det_ioc_destroy_qp)

#define	DET_IOC_REG_MR		_IOW(DET_MAGIC, 21, struct det_ioc_reg_mr)
#define	DET_IOC_QUERY_MR	_IOW(DET_MAGIC, 22, struct det_ioc_query_mr)
#define	DET_IOC_MODIFY_MR	_IOW(DET_MAGIC, 23, struct det_ioc_modify_mr)
#define	DET_IOC_REG_SHARED	_IOW(DET_MAGIC, 24, struct det_ioc_reg_shared)
#define	DET_IOC_DEREG_MR	_IOW(DET_MAGIC, 25, unsigned long)

#define	DET_IOC_CREATE_MW	_IOW(DET_MAGIC, 26, struct det_ioc_create_mw)
#define	DET_IOC_QUERY_MW	_IOW(DET_MAGIC, 27, struct det_ioc_query_mw)
#define	DET_IOC_DESTROY_MW	_IOW(DET_MAGIC, 28, unsigned long)

#define	DET_IOC_SEND		_IOW(DET_MAGIC, 29, struct det_ioc_send)
#define	DET_IOC_RECV		_IOW(DET_MAGIC, 30, struct det_ioc_recv)
#define	DET_IOC_READ		_IOW(DET_MAGIC, 31, struct det_ioc_read)
#define	DET_IOC_WRITE		_IOW(DET_MAGIC, 32, struct det_ioc_write)
#define	DET_IOC_BIND		_IOW(DET_MAGIC, 33, struct det_ioc_bind)
#define	DET_IOC_COMP_EXCH	_IOW(DET_MAGIC, 34, struct det_ioc_comp_exch)
#define	DET_IOC_FETCH_ADD	_IOW(DET_MAGIC, 35, struct det_ioc_fetch_add)

#define	DET_IOC_CREATE_CO	_IOW(DET_MAGIC, 36, struct det_ioc_create_co)
#define	DET_IOC_JOIN		_IOW(DET_MAGIC, 37, struct det_ioc_join)
#define	DET_IOC_DESTROY_CO	_IOW(DET_MAGIC, 38, struct det_ioc_destroy_co)
#define	DET_IOC_BARRIER		_IOW(DET_MAGIC, 39, struct det_ioc_barrier)
#define	DET_IOC_BCAST		_IOW(DET_MAGIC, 40, struct det_ioc_bcast)
#define	DET_IOC_SCATTER		_IOW(DET_MAGIC, 41, struct det_ioc_scatter)
#define	DET_IOC_SCATTERV	_IOW(DET_MAGIC, 42, struct det_ioc_scatterv)
#define	DET_IOC_GATHER		_IOW(DET_MAGIC, 43, struct det_ioc_gather)
#define	DET_IOC_GATHERV		_IOW(DET_MAGIC, 44, struct det_ioc_gatherv)
#define	DET_IOC_ALLGATHER	_IOW(DET_MAGIC, 45, struct det_ioc_allgather)
#define	DET_IOC_ALLGATHERV	_IOW(DET_MAGIC, 46, struct det_ioc_allgatherv)
#define	DET_IOC_ALLTOALL	_IOW(DET_MAGIC, 47, struct det_ioc_alltoall)
#define	DET_IOC_ALLTOALLV	_IOW(DET_MAGIC, 48, struct det_ioc_alltoallv)

#endif /* __DET_IOCTL_H__ */
