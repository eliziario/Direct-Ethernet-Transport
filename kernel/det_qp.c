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


struct qp_state_transition {
	int valid;
	int resize;	/* Resize allowed for SQ/RQ size and max or/ir. */
};

#define NUM_QP_STATES					4 /* det_qp_state */
#define	RESIZE_ALLOWED					1
#define	RESIZE_INVALID					0
#define	VALID_TRANSITION(next_state, resize_allowed)	{1, resize_allowed},
#define	INVAL_TRANSITION(next_state)			{0, RESIZE_INVALID},
#define	START_STATE(current_state)			{
#define	CEASE_STATE(current_state)			},

static struct qp_state_transition qp_transition[NUM_QP_STATES][NUM_QP_STATES] = {

	START_STATE(DET_QP_IDLE)
		VALID_TRANSITION(DET_QP_IDLE, RESIZE_ALLOWED)	
		VALID_TRANSITION(DET_QP_CONNECTED, RESIZE_ALLOWED)
		INVAL_TRANSITION(DET_QP_DISCONNECT)
		VALID_TRANSITION(DET_QP_ERROR, RESIZE_INVALID)
	CEASE_STATE(DET_QP_IDLE)

	START_STATE(DET_QP_CONNECTED)
		INVAL_TRANSITION(DET_QP_IDLE)
		VALID_TRANSITION(DET_QP_CONNECTED, RESIZE_INVALID)
		VALID_TRANSITION(DET_QP_DISCONNECT, RESIZE_INVALID)
		VALID_TRANSITION(DET_QP_ERROR, RESIZE_INVALID)
	CEASE_STATE(DET_QP_CONNECTED)

	START_STATE(DET_QP_DISCONNECT)		/* Transitory state to IDLE */
		INVAL_TRANSITION(DET_QP_IDLE)		/* Automatic */
		INVAL_TRANSITION(DET_QP_CONNECTED)
		INVAL_TRANSITION(DET_QP_DISCONNECT)
		INVAL_TRANSITION(DET_QP_ERROR)
	CEASE_STATE(DET_QP_DISCONNECT)

	START_STATE(DET_QP_ERROR)
		VALID_TRANSITION(DET_QP_IDLE, RESIZE_INVALID)
		INVAL_TRANSITION(DET_QP_CONNECTED)
		INVAL_TRANSITION(DET_QP_DISCONNECT)
		VALID_TRANSITION(DET_QP_ERROR, RESIZE_INVALID)
	CEASE_STATE(DET_QP_ERROR)
};


static void det_reset_tx_state(struct det_tx_state * const wq)
{
	atomic_set(&wq->snack_edge, 0);
	atomic_set(&wq->next_seq, 1);
	atomic_set(&wq->last_ack_seq_recvd, 0);
	wq->next_msg_id = 0;
	wq->last_timeout_seq = 0;
}


static void det_reset_rx_state(struct det_qp *qp,
			       struct det_rx_state * const wq)
{
	rq_lock_bh(&qp->rq.lock);
	skb_queue_purge(&wq->co_deferred);
	rq_unlock_bh(&qp->rq.lock);

	skb_queue_purge(&wq->snack_deferred);
	atomic_set(&wq->last_in_seq, 0);
	wq->snacked = 0;
	wq->first_snack_seq = 0;
	wq->last_snack_seq = 0;
	wq->last_seq_acked = 0;
	wq->defer_in_process = 0;
}


static void det_reset_wirestate(struct det_qp *qp)
{
	det_reset_tx_state(&qp->wirestate.sq_tx);
	det_reset_rx_state(qp, &qp->wirestate.sq_rx);

	det_reset_tx_state(&qp->wirestate.iq_tx);
	det_reset_rx_state(qp, &qp->wirestate.iq_rx);
}


/* Hold qp->lock during this call for synchronization. */
static void __det_query_qp(struct det_qp * const qp,
			   struct det_qp_attr * const qp_attr)
{
	if (qp_attr)
		*qp_attr = qp->attr;
}


/*
 * Caller must provide the proper synchronization for kernel mode
 * clients to this call using the qp->resize atomic for protection.
 */
static int det_resize_qp(struct det_qp * const qp,
			 __u32 sq_size,
			 __u32 rq_size,
			 __u32 max_ir)
{
	struct det_wr *sq_array, *rq_array, *iq_array;
	__u32 sq_bytes, rq_bytes, iq_bytes;
	u32 pages;

	/*
	 * Allocate one extra WQ entry, but do not report it in the QP
	 * attributes.  This will leave an unused slot in the WQ array,
	 * but it simplifies scheduling in the datapath/protocol layer.
	 */
	if (sq_size)
		++sq_size;
	if (rq_size)
		++rq_size;
	if (max_ir)
		++max_ir;

	sq_bytes = PAGE_ALIGN(sq_size * qp->sq.entry_size);
	rq_bytes = PAGE_ALIGN(rq_size * qp->rq.entry_size);
	iq_bytes = PAGE_ALIGN(max_ir  * qp->iq.entry_size);

	sq_size = sq_bytes / qp->sq.entry_size;
	rq_size = rq_bytes / qp->rq.entry_size;
	max_ir  = iq_bytes / qp->iq.entry_size;

	if ((qp->sq.size == sq_size) &&
	    (qp->rq.size == rq_size) &&
	    (qp->iq.size == max_ir))
		return 0;

	/*
	 * Note: If an error is returned, the work queues must be in
	 * the same state as they were prior to the attempt to resize.
	 */

	/* Calculate the number of pages required for this allocation. */
	pages = (sq_bytes + rq_bytes + iq_bytes) >> PAGE_SHIFT;

	/* Restrict memory usage to a percentage of kernel pages. */
	if (pages >
	    (det_max_pages - atomic_read(&det_page_count) + qp->page_cnt))
		return -EDQUOT;

	det_user_unlock();
	if (sq_size && (qp->sq.size != sq_size)) {
		sq_array = vmalloc(sq_bytes);
		if (unlikely(!sq_array)) {
			goto out;
		}
	} else
		sq_array = NULL;

	if (rq_size && (qp->rq.size != rq_size)) {
		rq_array = vmalloc(rq_bytes);
		if (unlikely(!rq_array)) {
			goto out1;
		}
	} else
		rq_array = NULL;

	if (max_ir && (qp->iq.size != max_ir)) {
		iq_array = vmalloc(iq_bytes);
		if (unlikely(!iq_array)) {
			goto out2;
		}
	} else
		iq_array = NULL;

	atomic_sub(qp->page_cnt, &det_page_count);
	qp->page_cnt = pages;
	atomic_add(qp->page_cnt, &det_page_count);

	/* Move the WQs. */

	if (qp->sq.size != sq_size) {
		if (qp->sq.depth)
			det_kcopy_ring(sq_array, qp->sq.array,
				       qp->sq.head, qp->sq.tail,
				       qp->sq.size, qp->sq.depth,
				       qp->sq.entry_size);
		if (qp->sq.array)
			vfree(qp->sq.array);

		qp->sq.array = sq_array;
		qp->sq.head = 0;
		qp->sq.tail = qp->sq.depth;
		qp->sq.size = sq_size;
	}

	if (qp->rq.size != rq_size) {
		if (qp->rq.depth)
			det_kcopy_ring(rq_array, qp->rq.array,
				       qp->rq.head, qp->rq.tail,
				       qp->rq.size, qp->rq.depth,
				       qp->rq.entry_size);
		if (qp->rq.array)
			vfree(qp->rq.array);

		qp->rq.array = rq_array;
		qp->rq.head = 0;
		qp->rq.tail = qp->rq.depth;
		qp->rq.size = rq_size;
	}

	if (qp->iq.size != max_ir) {
		if (qp->iq.depth)
			det_kcopy_ring(iq_array, qp->iq.array,
				       qp->iq.head, qp->iq.tail,
				       qp->iq.size, qp->iq.depth,
				       qp->iq.entry_size);
		if (qp->iq.array)
			vfree(qp->iq.array);

		qp->iq.array = iq_array;
		qp->iq.head = 0;
		qp->iq.tail = qp->iq.depth;
		qp->iq.size = max_ir;
	}

	/* Update the attributes; subtract the extra WQ entry added above. */
	qp->attr.sq_size = (sq_size) ? sq_size - 1 : 0;
	qp->attr.rq_size = (rq_size) ? rq_size - 1 : 0;
	qp->attr.max_ir	 = (max_ir)  ? max_ir  - 1 : 0;

	det_user_lock();
	return 0;

out2:
	if (rq_array)
		vfree(rq_array);
out1:
	if (sq_array)
		vfree(sq_array);
out:
	det_user_lock();
	return -ENOMEM;
}


/*
 * Initialize a newly created WQ structure.  Note that this
 * function assumes the wq_array has not yet been initialized.
 */
static void det_init_wq(struct det_wq * const wq,
			const u32 num_sges)
{
	memset(wq, 0, sizeof(*wq));
	det_spin_lock_init(&wq->lock);

	/*
	 * Calculate the size of each WQE in bytes.
	 * Round up to align WQEs on a 64-bit boundaries.
	 */
	wq->entry_size =((sizeof(struct det_wr) +
			 (sizeof(struct det_ds) * num_sges)) + 7) & ~7;
}


int det_create_qp(struct det_pd * const pd,
		  const struct det_qp_create * const qp_create,
		  struct det_qp_attr * const qp_attr,
		  struct det_qp * const qp)
{
	struct det_device *detdev = pd->detdev;
	struct det_scheduler *scheduler;
	int err;

	if (unlikely((qp_create->sq_size > MAX_SQ_SIZE)	       ||
		     (qp_create->rq_size > MAX_RQ_SIZE)	       ||
		     (qp_create->sq_sges > MAX_SGES)	       ||
		     (qp_create->rq_sges > MAX_SGES)	       ||
		     (qp_create->max_or  > MAX_OR)	       ||
		     (qp_create->max_ir  > MAX_IR)	       ||
		     (qp_create->sq_size && !qp_create->sq_cq) ||
		     (qp_create->rq_size && !qp_create->rq_cq)))
		return -EINVAL;

	if (unlikely(detdev->qp_cnt >= MAX_QPS))
		return -EAGAIN;

	qp->type = DET_TYPE_QP;
	qp->detdev = detdev;
	qp->netdev = pd->nic->netdev;
	det_spin_lock_init(&qp->lock);
	init_MUTEX(&qp->mutex);
	init_completion(&qp->done);
	atomic_set(&qp->refcnt, 1);
	atomic_set(&qp->resize, 0);
	atomic_set(&qp->dma_pending, 0);
	atomic_set(&qp->or_depth, 0);
	atomic_set(&qp->or_posted, 0);
	qp->co = NULL;
	qp->nr_events = 0;
	qp->page_cnt = 0;

	qp->attr.pd = pd;
	qp->attr.sq_cq = qp_create->sq_cq;
	qp->attr.rq_cq = qp_create->rq_cq;
	qp->attr.state = DET_QP_IDLE;

	read_lock(&dev_base_lock);
	qp->attr.mtu_size = qp->netdev->mtu;
	read_unlock(&dev_base_lock);

	qp->attr.sq_size = 0;
	qp->attr.rq_size = 0;

	qp->attr.sq_sges = qp_create->sq_sges;
	qp->attr.rq_sges = qp_create->rq_sges;

	qp->attr.max_or = qp_create->max_or;
	qp->attr.max_ir = 0;

	do {
		if (unlikely(!det_idr_pre_get(&det_wire_map, GFP_KERNEL)))
			return -ENOMEM;
		wiremap_write_lock_bh();
		err = det_get_id(&det_wire_map, qp, &qp->attr.local_qp_num);
		wiremap_write_unlock_bh();
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		return err;

	qp->attr.remote_qp_num = 0;

	det_get_mac(&qp->attr.local_mac, qp->netdev);
	memset(&qp->attr.remote_mac, 0, sizeof(qp->attr.remote_mac));

	det_init_wq(&qp->sq, qp->attr.sq_sges);
	det_init_wq(&qp->rq, qp->attr.rq_sges);
	det_init_wq(&qp->iq, 1);

	/* Reset wirestate to allow posting receives in DET_QP_IDLE state. */
	skb_queue_head_init(&qp->wirestate.sq_rx.snack_deferred);
	skb_queue_head_init(&qp->wirestate.sq_rx.co_deferred);
	skb_queue_head_init(&qp->wirestate.iq_rx.snack_deferred);
	skb_queue_head_init(&qp->wirestate.iq_rx.co_deferred);
	det_reset_wirestate(qp);
	det_spin_lock_init(&qp->wirestate.lock);

	err = det_resize_qp(qp, qp_create->sq_size, qp_create->rq_size,
			    qp_create->max_ir);
	if (unlikely(err))
		goto out;

	__det_query_qp(qp, qp_attr);

	atomic_inc(&pd->refcnt);
	if (qp_create->sq_cq)
		atomic_inc(&qp_create->sq_cq->refcnt);
	if (qp_create->rq_cq)
		atomic_inc(&qp_create->rq_cq->refcnt);

	/* Locate the net device in the global scheduler list for this QP. */
	sched_list_lock();
	list_for_each_entry(scheduler, &scheduler_list, entry) {
		if (scheduler->netdev == qp->netdev)
			break;
	}
	assert(&scheduler->entry != &scheduler_list);
	sched_list_unlock();

	qp->scheduler = scheduler;

	/* Add the QP to the net device in the global scheduler list. */
	sched_obj_lock(&scheduler->lock);
	list_add_tail(&qp->scheduler_entry, &scheduler->qp_list);
	scheduler->count++;
	sched_obj_unlock(&scheduler->lock);

	write_lock(&detdev->lock);
	list_add_tail(&qp->entry, &detdev->qp_list);
	detdev->qp_cnt++;
	write_unlock(&detdev->lock);

	return 0;

out:
	wiremap_write_lock_bh();
	idr_remove(&det_wire_map, qp->attr.local_qp_num);
	wiremap_write_unlock_bh();
	return err;
}
EXPORT_SYMBOL(det_create_qp);


int det_query_qp(struct det_qp * const qp,
		 struct det_qp_attr * const qp_attr)
{
	qp_lock_bh(&qp->lock);
	if (unlikely(atomic_read(&qp->resize))) {
		qp_unlock_bh(&qp->lock);
		return -EAGAIN;
	}
	__det_query_qp(qp, qp_attr);
	qp_unlock_bh(&qp->lock);

	return 0;
}
EXPORT_SYMBOL(det_query_qp);


/* Hold qp->lock during this call for synchronization. */
static void det_reset_wq(struct det_wq * const wq)
{
	wq->head = 0;
	wq->tail = 0;
	wq->depth = 0;
	wq->reap_cnt = 0;
	wq->next_msg_id = 0;
	wq->completion_cnt = 0;
	wq->next_active_wr = 0;
#ifdef	DET_TRIGGERED_WR
	atomic_set(&wq->gate, 0);
#endif
}


static int det_flush_wq(struct det_wq * const wq,
			struct det_cq * const cq)
{
	struct det_wr *wr;
	struct det_wc *wc;
	int i, num_wr, err;

	/* Prevent divide by zero traps on wrap math. */
	if (wq->size == 0)
		return 0;

	wq_lock_bh(&wq->lock);
	for (i = (wq->head + wq->completion_cnt) % wq->size, num_wr = 0;
	     wq->depth && (wq->completion_cnt != wq->depth);
	     i = (i + 1) % wq->size, num_wr++) {

		wr = det_get_wr(wq, i);

		det_clear_ds_refs(wr->ds_array, wr->num_ds);

		if (!cq) {
			wq->completion_cnt++;
			continue;
		}

		err = det_reserve_cqe(cq, &wc);
		if (err) {
			num_wr = err;
			break;
		}

		wc->id		   = wr->id;
		wc->status	   = DET_WS_FLUSHED;
		wc->type	   = wr->type;
		wc->flags	   = 0;
		wc->immediate_data = 0;
		wc->length	   = 0;
		wc->reserved	   = (unsigned long)wq;
		wc->reap_cnt	   = wq->reap_cnt + 1;

		wq->reap_cnt = 0;
		wq->completion_cnt++;

		det_append_cqe(cq, wc);
	}
	wq_unlock_bh(&wq->lock);

	if (num_wr && cq)
		det_notify_cq(cq);

	return num_wr;
}


/* Hold qp->lock during this call for synchronization. */
static int det_flush_sq(struct det_qp * const qp)
{
	int status = det_flush_wq(&qp->sq, qp->attr.sq_cq);

	if (status) {
		qp->attr.state = DET_QP_ERROR;
		if (status < 0)
			det_async_event(qp->attr.pd->nic,
					DET_AE_QP_SQ_ERROR, DET_TYPE_QP, qp);
	}

	return status;
}


/* Hold qp->lock during this call for synchronization. */
static int det_flush_rq(struct det_qp * const qp)
{
	int status = det_flush_wq(&qp->rq, qp->attr.rq_cq);

	if (status < 0) {
		qp->attr.state = DET_QP_ERROR;
		det_async_event(qp->attr.pd->nic,
				DET_AE_QP_RQ_ERROR, DET_TYPE_QP, qp);
	}

	return status;
}


/* Hold qp->lock during this call for synchronization. */
static int det_flush_iq(struct det_qp * const qp)
{
	return det_flush_wq(&qp->iq, NULL);
}


/* Hold qp->lock during this call for synchronization. */
void det_qp_error(struct det_qp * const qp)
{
	/* Disconnect the QP if it is connected. */
	if (qp->attr.state == DET_QP_CONNECTED)
		det_send_disconnect(qp, DET_AE_QP_ERROR);

	qp->attr.state = DET_QP_ERROR;
	det_flush_sq(qp);
	det_flush_rq(qp);
	det_flush_iq(qp);
}


/* Hold qp->lock during this call for synchronization. */
void det_qp_idle(struct det_qp * const qp)
{
	/*
	 * Clear the CQEs and reset the SQ and RQ to clear any previous
	 * suppressed completions that may have been left on the QP.
	 */

	det_clear_cqes(qp->attr.sq_cq, &qp->sq);
	det_clear_cqes(qp->attr.rq_cq, &qp->rq);

	det_reset_wq(&qp->sq);
	det_reset_wq(&qp->rq);
	det_reset_wq(&qp->iq);

	det_reset_wirestate(qp);

	qp->attr.state = DET_QP_IDLE;
}


/* Hold qp->lock during this call for synchronization. */
static void det_qp_local_disconnect(struct det_qp * const qp,
				    enum det_event_code reason)
{
	qp->attr.state = DET_QP_DISCONNECT;
	det_send_disconnect(qp, reason);

	det_flush_sq(qp);
	det_flush_rq(qp);
	det_flush_iq(qp);

	/* We don't ack disconnects yet, so just pretend we got one. */
	det_qp_disconnect_ack(qp, reason);
}


/* Hold qp->lock during this call for synchronization. */
void det_qp_disconnect_ack(struct det_qp * const qp,
			   const enum det_event_code reason)
{
	qp->attr.state = ((qp->attr.state == DET_QP_DISCONNECT) &&
			  (reason == DET_AE_DISCONNECT)) ? DET_QP_IDLE :
							   DET_QP_ERROR;
	if (qp->attr.state == DET_QP_IDLE)
		det_qp_idle(qp);

	det_async_event(qp->attr.pd->nic, reason, DET_TYPE_QP, qp);
}


void det_qp_internal_disconnect(struct det_qp * const qp,
				const enum det_event_code reason)
{
	qp_lock_bh(&qp->lock);
	det_qp_local_disconnect(qp, reason);
	qp_unlock_bh(&qp->lock);
}


void det_qp_remote_disconnect(struct det_qp * const qp,
			      const enum det_event_code reason)
{
	if (qp->loopback) {
		/*
		 * Prevent simultaneous loopback QP disconnect deadlocks.
		 * This is no worse than dropping a disconnect packet.
		 */
		if (!qp_trylock_bh(&qp->lock))
			return;
	} else
		qp_lock_bh(&qp->lock);

	if (qp->attr.state != DET_QP_CONNECTED) {
		qp_unlock_bh(&qp->lock);
		return;
	}

	qp->attr.state = (reason != DET_AE_DISCONNECT) ? DET_QP_ERROR :
							 DET_QP_IDLE;

	/* Must flush before calling det_qp_idle. */
	det_flush_sq(qp);
	det_flush_rq(qp);
	det_flush_iq(qp);

	if (qp->attr.state == DET_QP_IDLE)
		det_qp_idle(qp);

	qp_unlock_bh(&qp->lock);

	det_async_event(qp->attr.pd->nic,
		DET_AE_REMOTE | reason, DET_TYPE_QP, qp);
}


void det_qp_loopback(struct det_qp * const qp)
{
	/* Check for NIC loopback if the QP is not using the loopback device.*/
	qp->loopback = strncmp(qp->netdev->name, "lo", 2) &&
		       !memcmp(qp->attr.local_mac.addr,
			       qp->attr.remote_mac.addr, DET_MAC_ADDR_LEN);

	/* Reflect a loopback QP up to the collective membership. */
	if (qp_is_co_member(qp))
		qp_get_co(qp)->qp.loopback |= qp->loopback;
}


/* Hold qp->lock during this call for synchronization. */
static int det_qp_connect(struct det_qp * const qp,
			   const struct det_qp_mod * const qp_mod,
			   enum det_qp_state const cur_state)
{
	if (cur_state == DET_QP_CONNECTED)
		return 0;

	qp->attr.remote_qp_num = qp_mod->remote_qp_num;
	qp->attr.remote_mac    = qp_mod->remote_mac;

	det_qp_loopback(qp);

#ifdef	CONFIG_DET_LOOPBACK
	if (!qp->loopback)
		return -EPERM;
#endif

	qp->attr.state = DET_QP_CONNECTED;

	return 0;
}


int det_modify_qp(struct det_qp * const qp,
		  const struct det_qp_mod * const qp_mod,
		  struct det_qp_attr * const qp_attr)
{
	enum det_qp_state cur_state, new_state;
	__u32 sq_size, rq_size;
	__u32 max_or, max_ir;
	int err;

	qp_lock_bh(&qp->lock);
	if (unlikely(atomic_read(&qp->resize))) {
		qp_unlock_bh(&qp->lock);
		return -EAGAIN;
	}

	cur_state = qp->attr.state;

	/* First, validate any state transition. */
	if (qp_mod->flags & DET_QP_MOD_STATE_FLAG) {

		new_state = qp_mod->next_state;

		switch (new_state) {
			case DET_QP_IDLE:
			case DET_QP_CONNECTED:
			case DET_QP_DISCONNECT:
			case DET_QP_ERROR:
				break;
			default:
				qp_unlock_bh(&qp->lock);
				return -EINVAL;
		}

		if (unlikely(!qp_transition[cur_state][new_state].valid)) {
			qp_unlock_bh(&qp->lock);
			return -EPERM;
		}
	} else
		new_state = cur_state;

	/* Next, validate any resize request. */
	if (qp_mod->flags & (DET_QP_MOD_SQ_FLAG	    |
			     DET_QP_MOD_RQ_FLAG     |
			     DET_QP_MOD_MAX_OR_FLAG |
			     DET_QP_MOD_MAX_IR_FLAG)) {

		if (unlikely(!qp_transition[cur_state][new_state].resize)) {
			qp_unlock_bh(&qp->lock);
			return -EINVAL;
		}

		/*
		 * We cannot hold a lock during QP resize due to memory
		 * allocation.  Therefore, QP resize is only valid for the
		 * idle-to-idle and idle-to-connected state transitions
		 * since no bottom half processing can occur in these
		 * state transitions.  However, concurrent det_modify_qp
		 * must be prevented.  User-mode calls are protected by
		 * a mutex in the QP modify/query ioctl call paths.  Use
		 * of the qp->resize atomic provides protection for kernel
		 * mode clients.  It is safe to release lock at this point
		 * after having validated the resize state transition.
		 */
		atomic_inc(&qp->resize);
		qp_unlock_bh(&qp->lock);

		sq_size = (qp_mod->flags & DET_QP_MOD_SQ_FLAG) ?
				qp_mod->sq_size : qp->attr.sq_size;
		rq_size = (qp_mod->flags & DET_QP_MOD_RQ_FLAG) ?
				qp_mod->rq_size : qp->attr.rq_size;
		max_or  = (qp_mod->flags & DET_QP_MOD_MAX_OR_FLAG) ?
				qp_mod->max_or : qp->attr.max_or;
		max_ir  = (qp_mod->flags & DET_QP_MOD_MAX_IR_FLAG) ?
				qp_mod->max_ir : qp->attr.max_ir;

		if (unlikely((sq_size > MAX_SQ_SIZE)	  ||
			     (rq_size > MAX_RQ_SIZE)	  ||
			     (max_or  > MAX_OR)		  ||
			     (max_ir  > MAX_IR)		  ||
			     (sq_size && !qp->attr.sq_cq) ||
			     (rq_size && !qp->attr.rq_cq))) {
			atomic_dec(&qp->resize);
			return -EINVAL;
		}

		if (unlikely((sq_size < qp->sq.depth) ||
			     (rq_size < qp->rq.depth) ||
			     (max_ir  < qp->iq.depth) ||
			     (max_or  < atomic_read(&qp->or_depth)))) {
			atomic_dec(&qp->resize);
			return -EBUSY;
		}

		/* Validation successful, attempt to resize the QP. */
		err = det_resize_qp(qp, sq_size, rq_size, max_ir);
		if (unlikely(err)) {
			atomic_dec(&qp->resize);
			return err;
		}

		/* Note: No failure paths are expected below this point. */

		qp->attr.max_or = max_or;

		/* Re-acquire the QP lock and continue processing. */
		qp_lock_bh(&qp->lock);
		atomic_dec(&qp->resize);
	}

	err = 0;
	if (qp_mod->flags & DET_QP_MOD_STATE_FLAG) {

		/* Perform state change processing. */
		switch (new_state) {
			case DET_QP_IDLE:
				det_qp_idle(qp);
				break;

			case DET_QP_CONNECTED:
				err = det_qp_connect(qp, qp_mod, cur_state);
				break;

			case DET_QP_DISCONNECT:
				det_qp_local_disconnect(qp, DET_AE_DISCONNECT);
				break;

			case DET_QP_ERROR:
				det_qp_error(qp);
				break;

			default:
				/* Should never get here, but be graceful. */
				assert(0);
				qp_unlock_bh(&qp->lock);
				return -EINVAL;
		}
	}

	__det_query_qp(qp, qp_attr);
	qp_unlock_bh(&qp->lock);

	return err;
}
EXPORT_SYMBOL(det_modify_qp);


int det_destroy_qp(struct det_qp * const qp)
{
	struct det_device *detdev = qp->detdev;

	/* Remove the QP from the global map. */
	wiremap_write_lock_bh();
	idr_remove(&det_wire_map, qp->attr.local_qp_num);
	wiremap_write_unlock_bh();

	/* Disconnect the QP if it is connected. */
	if (qp->attr.state == DET_QP_CONNECTED)
		det_send_disconnect(qp, DET_AE_QP_DESTROYED);

	/* Remove the QP from the global scheduler list. */
	sched_obj_lock(&qp->scheduler->lock);
	list_del(&qp->scheduler_entry);
	qp->scheduler->count--;
	sched_obj_unlock(&qp->scheduler->lock);

	/* Release a QP reference. */
	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	/* Wait for all QP references to go away. */
	det_user_unlock();
	wait_for_completion(&qp->done);
	det_user_lock();

	/* Flush the send and receive WQs without QP events on error. */
	det_flush_wq(&qp->sq, qp->attr.sq_cq);
	det_flush_wq(&qp->rq, qp->attr.rq_cq);
	det_flush_wq(&qp->iq, NULL);

	/*
	 * For each WQ, walk the CQ completions and clear the WQ
	 * pointer to prevent retiring WQEs when CQEs are polled.
	 */
	det_clear_cqes(qp->attr.sq_cq, &qp->sq);
	det_clear_cqes(qp->attr.rq_cq, &qp->rq);

	/* Now safe to free WQs. */
	det_user_unlock();
	if (qp->iq.array)
		vfree(qp->iq.array);
	if (qp->rq.array)
		vfree(qp->rq.array);
	if (qp->sq.array)
		vfree(qp->sq.array);
	det_user_lock();

	det_reset_wirestate(qp);

	atomic_sub(qp->page_cnt, &det_page_count);

	if (qp->attr.rq_cq)
		atomic_dec(&qp->attr.rq_cq->refcnt);
	if (qp->attr.sq_cq)
		atomic_dec(&qp->attr.sq_cq->refcnt);
	atomic_dec(&qp->attr.pd->refcnt);

	det_remove_events(qp->attr.pd->nic->event, qp);

	write_lock(&detdev->lock);
	list_del(&qp->entry);
	detdev->qp_cnt--;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_destroy_qp);
