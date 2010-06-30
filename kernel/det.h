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

#ifndef __DET_H__
#define __DET_H__

#include <linux/spinlock.h>
#include <linux/idr.h>
#include <linux/if.h>	/* for IFNAMSIZ (kernel) */

#include "det_verbs.h"
#include "det_protocol.h"

#ifndef	__KERNEL__
#error Kernel mode header file included in user mode build
#endif


//#define DET_LOCK_DEBUG

typedef struct {
	spinlock_t	lock	____cacheline_aligned;
#ifdef DET_LOCK_DEBUG
	int magic, owner_cpu;
	void *owner;
	void *eip;
	struct {
		void *owner;
		void *eip;
	} waiters[4];
#endif
} det_spinlock_t;

enum det_wr_type {
	DET_WR_SEND		= DET_WC_SEND,
	DET_WR_RDMA_WRITE	= DET_WC_RDMA_WRITE,
	DET_WR_RDMA_READ	= DET_WC_RDMA_READ,
	DET_WR_ATOMIC_COMP_EXCH	= DET_WC_ATOMIC_COMP_EXCH,
	DET_WR_ATOMIC_FETCH_ADD	= DET_WC_ATOMIC_FETCH_ADD,
	DET_WR_RECV		= DET_WC_RECV,
	DET_WR_BIND		= DET_WC_BIND,

	/* Collectives */
	DET_WR_JOIN		= DET_WC_JOIN,
	DET_WR_BARRIER		= DET_WC_BARRIER,
	DET_WR_BCAST		= DET_WC_BCAST,
	DET_WR_SCATTER		= DET_WC_SCATTER,
	DET_WR_SCATTERV		= DET_WC_SCATTERV,
	DET_WR_GATHER		= DET_WC_GATHER,
	DET_WR_GATHERV		= DET_WC_GATHERV,
	DET_WR_ALLGATHER	= DET_WC_ALLGATHER,
	DET_WR_ALLGATHERV	= DET_WC_ALLGATHERV,
	DET_WR_ALLTOALL		= DET_WC_ALLTOALL,
	DET_WR_ALLTOALLV	= DET_WC_ALLTOALLV,

	/* Psuedo types */
	DET_WR_RDMA_READ_RESP,
	DET_WR_ATOMIC_RESP	/* Must be last for det_stats & wr_type2str */
};

enum det_wr_state {
	WR_STATE_WAITING,
	WR_STATE_STARTED,
	WR_STATE_WAITING_FOR_ACK,
	WR_STATE_WAITING_FOR_RESP,
	WR_STATE_LAST_SEEN,
	WR_STATE_COMPLETED
};

struct det_ds {
	union {
		struct det_mr	*mr;
		struct det_mw	*mw;
	};
	u32			offset;
	u32			length;
	u32			l_key;
	u32			in_use;
};

struct det_segmentation_state {
	struct det_ds		*current_ds;
	struct det_mr		*current_mr;
	u32			current_page_index;
	u32			current_page_offset;
	u32			wr_length_remaining;
	u32			ds_length_remaining;
	u32			next_seq;
	u32			starting_seq;
	u32			ending_seq;
	u16			last_opcode;
	u32			timeout_cnt;
	u32			timeout_trigger;
	atomic_t		last_timeout_seq_sent;
};

struct det_reassembly_state {
	struct det_ds		*current_ds;
	u32			current_ds_offset;
	u32			last_packet_seq;
	u32			last_seen_seq;
	u32			opcode;
	u32			final_length;
	net32_t			immediate_data;
};

struct det_sar_state {
	struct det_segmentation_state	seg;
	struct det_reassembly_state	rea;
};

struct det_wr {
	enum det_wr_type	type;
	u32			total_length;
	u64			id;
	enum det_wr_flags	flags;

	u32			msg_id;
	atomic_t		state;
	struct det_sar_state	sar;

	union {
		struct det_send_wr {
			net32_t			immediate_data;
		} send;

		struct det_read_wr {
			net64_t			remote_address;
			net32_t			remote_key;
			net32_t			remote_length;
		} read;

		struct det_write_wr {
			net64_t			remote_address;
			net32_t			remote_key;
			net32_t			immediate_data;
		} write;

		struct det_bind_wr {
			struct det_mw		*mw;
			struct det_mr		*mr;
			net32_t			*r_key;
			u64			vaddr;
			u32			length;
			enum det_access_ctrl	access;
		} bind;

		struct det_comp_exch_wr {
			net64_t			comp_operand;
			net64_t			exch_operand;
			net64_t			remote_address;
			net32_t			remote_key;
		} comp_exch;

		struct det_fetch_add_wr {
			net64_t			add_operand;
			net64_t			remote_address;
			net32_t			remote_key;
		} fetch_add;

		/* Collective types */

		struct det_barrier_wr {
			int			mask;
		} barrier;

		struct det_bcast_wr {
			int			root;
			int			relative_rank;
			int			i;
			int			j;
			int			mask;
			int			nbytes;
			struct det_local_ds	ds;
		} bcast;

		struct det_scatter_wr {
			int			root;
			int			relative_rank;
			int			mask;
			int			nbytes;
			struct det_local_ds	src_ds;
			struct det_local_ds	dst_ds;
		} scatter;

		struct det_gather_wr {
			int			root;
			int			relative_rank;
			int			mask;
			int			nbytes;
			struct det_local_ds	src_ds;
			struct det_local_ds	dst_ds;
		} gather;

		struct det_allgather_wr {
			int			i;
			int			j;
			int			mask;
			int			nbytes;
			struct det_local_ds	dst_ds;
		} allgather;

		struct det_allgatherv_wr {
			int			i;
			int			j;
			int			mask;
			struct det_local_ds	*dst_ds_array;
		} allgatherv;

		struct det_alltoall_wr {
			int			pof2;
			int			count;
			int			nbytes;
			struct det_local_ds	src_ds;
			struct det_local_ds	dst_ds;
		} alltoall;

		/* Psuedo types */

		struct det_atomic_resp {
			net64_t			orig_data;
			u16			opcode;
		} atomic_resp;
	};

#ifdef	DET_TRIGGERED_WR
	s32			trigger;
	struct det_qp		*signal;	/* Only signals SQs */
#endif

#ifdef	DET_PERF
	u64	start;
#endif

	u32			num_ds;
	struct det_ds		ds_array[0];	/* Must be last */
};

struct det_device {
	struct list_head	entry;
	rwlock_t		map_lock	____cacheline_aligned;
	struct idr		map;
	rwlock_t		lock;		/* Protects lists and cnts */
	struct list_head	event_list;
	struct list_head	nic_list;
	struct list_head	pd_list;
	int			pd_cnt;
	struct list_head	cq_list;
	int			cq_cnt;
	struct list_head	qp_list;
	int			qp_cnt;
	struct list_head	mr_list;
	int			mr_cnt;
	struct list_head	mw_list;
	int			mw_cnt;
	struct list_head	co_list;
	int			co_cnt;
};

struct det_event {
	enum det_type		type;
	int			id;
	atomic_t		refcnt;
	struct list_head	entry;
	struct det_device	*detdev;
	det_spinlock_t		lock;
	struct list_head	event_queue;
	wait_queue_head_t	wait_queue;
	atomic_t		waitcnt;
	struct completion	done;
};

struct det_nic {
	enum det_type		type;
	int			id;
	int			valid;
	atomic_t		refcnt;
	struct list_head	entry;
	struct det_device	*detdev;
	struct net_device	*netdev;
	struct det_event	*event;
	struct det_scheduler	*scheduler;
	void			(*event_cb)(struct det_event * const,
					    const struct det_record * const);
	u64			context;
	u32			nr_events;
};

struct det_pd {
	enum det_type		type;
	int			id;
	atomic_t		refcnt;
	struct list_head	entry;
	struct det_device	*detdev;
	struct det_nic		*nic;
};

struct det_cq {
	enum det_type		type;
	int			id;
	int			valid;
	atomic_t		refcnt;
	struct list_head	entry;
	struct det_device	*detdev;
	struct det_nic		*nic;
	struct det_event	*event;
	void			(*completion_cb)(struct det_cq * const);
	u64			context;
	u32			nr_events;
	int			page_cnt;
	det_spinlock_t		lock;
	struct det_wc		*wc_array;
	u32			head;
	u32			tail;
	atomic_t		depth;
	int			solicited;
	struct det_cq_attr	attr;
	struct semaphore	mutex;
	struct det_co		*co;
};

struct det_rx_state {
	struct sk_buff_head	snack_deferred;
	struct sk_buff_head	co_deferred;
	int			defer_in_process;
	atomic_t		last_in_seq;
	u32			snacked;
	u32			first_snack_seq;
	u32			last_snack_seq;
	u32			last_seq_acked;
};

struct det_tx_state {
	atomic_t		snack_edge;
	atomic_t		next_seq;
	atomic_t		last_ack_seq_recvd;
	u32			next_msg_id;
	u32			last_timeout_seq;
};

struct det_wirestate {
	det_spinlock_t		lock;
	struct det_tx_state	sq_tx;
	struct det_tx_state	iq_tx;
	struct det_rx_state	sq_rx;
	struct det_rx_state	iq_rx;
};

struct det_scheduler {
	det_spinlock_t		lock;
	int			refcnt;		/* always refed under lock */
	atomic_t		stopped;
	atomic_t		available;
	atomic_t		was_new;
	atomic_t		was_retry;
	atomic_t		was_timeout;
	int			schedule_max;
	u32			count;
	struct list_head	qp_list;	/* List of QP's for netdev */
	struct list_head	entry;
	struct net_device	*netdev;
	det_spinlock_t		atomic_lock;
};

struct det_wq {
	det_spinlock_t		lock;
	struct det_wr		*array;
	u32			head;
	u32			tail;
	u32			depth;
	u32			size;
	u32			entry_size;
	u32			completion_cnt;
	u32			reap_cnt;
	u32			next_active_wr;
	u32			next_msg_id;
#ifdef	DET_TRIGGERED_WR
	atomic_t		gate;
#endif
};

enum det_schedule_op {
	DET_SCHEDULE_NEW	= BIT(0),
	DET_SCHEDULE_RETRY	= BIT(1),
	DET_SCHEDULE_TIMEOUT	= BIT(2),
	DET_SCHEDULE_RESUME	= DET_SCHEDULE_NEW /* For protocol layer */
};

struct det_qp {
	enum det_type		type;
	int			id;
	int			valid;
	atomic_t		refcnt;
	struct list_head	entry;
	struct det_device	*detdev;
	u64			context;
	struct net_device	*netdev;
	int			page_cnt;

	det_spinlock_t		lock;

	struct det_wq		sq;
	struct det_wq		rq;
	struct det_wq		iq;

	atomic_t		dma_pending;
	atomic_t		or_depth;
	atomic_t		or_posted;

#ifdef CONFIG_DET_DOORBELL
	struct det_doorbell	*doorbell;
	struct page		*doorbell_page;
#endif

	enum det_schedule_op	reschedule_flags;

	struct det_wirestate	wirestate;
	struct det_qp_attr	attr;

	struct list_head	scheduler_entry;
	struct det_scheduler	*scheduler;

	struct det_co		*co;
	int			loopback;
	u32			nr_events;

	atomic_t		resize;
	struct semaphore	mutex;
	struct completion	done;
};

struct det_mem_base {
	enum det_type		type;
	int			id;
	atomic_t		refcnt;
	struct list_head	entry;
	struct completion	done;
	struct det_device	*detdev;
};

struct det_mr {
	struct det_mem_base	base;	/* Must be first */
	struct det_mr_attr	attr;	/* Must follow struct det_mem_base */

	atomic_t		windows;
	det_spinlock_t		lock;
	u64			vaddr;

	int			page_cnt;
	struct page		*pages[0];	/* Must be last */
};

struct det_mw {
	struct det_mem_base	base;	/* Must be first */
	struct det_mw_attr	attr;	/* Must follow struct det_mem_base */

	struct det_mr		*mr;
	u32			mr_offset;
};

struct det_group {
	struct list_head	entry;
	det_spinlock_t		lock;
	struct completion	done;
	atomic_t		refcnt;
	net64_t			tag;
	int			size;
	struct det_co		*co[0];
};

typedef int (*det_co_next)(struct det_co * const);

struct det_co {
	struct det_qp		qp;	/* Must be first */
	enum det_type		type;
	int			id;
	struct list_head	entry;
	struct det_device	*detdev;
	struct det_group	*group;
	det_spinlock_t		lock;
	int			size;
	int			rank;
#if defined(DET_CO_TASKLET) || defined(DET_TRIGGERED_WR)
	struct tasklet_struct	task;
#endif
	det_co_next		next;
	struct det_cq		cq;
	int			tmp_size;
	void			*tmp;
	struct det_mr		*mr;
	struct det_qp		**qp_array;
};

#endif /* __DET_H__ */
