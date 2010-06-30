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


/*
 * Define DET_USE_DIRECT_INDEXING to use direct data
 * placement with the alltoall indexing algorithm.
 */
#define	DET_USE_DIRECT_INDEXING


struct det_join_ack {
	struct det_mac_addr	mac;
	net32_t			rank;
	net32_t			qp_num[];
};


#ifdef	DET_TRIGGERED_WR
struct det_twr {
	u64				id;
	struct det_qp			*qp;
	const struct det_local_ds	*ds_array;
	u32				num_ds;
	enum det_wr_type		type;
};
#else


static int det_barrier_cb(struct det_co * const co);
static int det_bcast_cb(struct det_co * const co);
static int det_bcast_doubling_cb(struct det_co * const co);
static int det_bcast_ring_cb(struct det_co * const co);
static int det_scatter_cb(struct det_co * const co);
static int det_allgather_doubling_cb(struct det_co * const co);
static int det_allgather_dissemination_cb(struct det_co * const co);
static int det_allgather_ring_cb(struct det_co * const co);
static int det_allgatherv_doubling_cb(struct det_co * const co);
static int det_allgatherv_disseminate_cb(struct det_co * const co);
static int det_allgatherv_ring_cb(struct det_co * const co);
static int det_alltoall_pairwise_cb(struct det_co * const co);
#endif
static int det_bcast_scatter_cb(struct det_co * const co);
static int det_co_pollcomplete_cb(struct det_co * const co);
static int det_gather_cb(struct det_co * const co);
#ifdef	DET_USE_DIRECT_INDEXING
static int det_alltoall_direct_index_cb(struct det_co * const co);
#else
static int det_alltoall_copy_index_cb(struct det_co * const co);
#endif


#define is_odd(n)		((n)  & 1)
#define is_pof2(n)		(((n) & ((n) - 1)) == 0)
#define pof2(n)			(1 << (n))
#define floor_log2(n)		(fls(n) - 1)
#define ceil_log2(n)		(floor_log2(n) + !is_pof2(n))


static inline int relative_rank(int rank, int root, int size)
{
	return (rank >= root) ? rank - root : rank - root + size;
}

/* Returns the number of binomial ranks at and below the given rank. */
static inline int __subtree(int rank, int size)
{
	return rank ? min(rank & -rank, size - rank) : size;
}


/* Returns the number of binomial ranks at and below the given rank. */
static inline int subtree(int rank, int root, int size)
{
	return __subtree(relative_rank(rank, root, size), size);
}


/* Returns the number of binomial ranks at and below the given relative rank. */
static inline int rel_subtree(int relative_rank, int size)
{
	return __subtree(relative_rank, size);
}


/* Returns the number of binomial ranks below the given relative rank. */
static inline int rel_subranks(int relative_rank, int size)
{
	return rel_subtree(relative_rank, size) - 1;
}


static int det_co_free_mr(struct det_co * const co)
{
	int err;

	if (!co->mr)
		return 0;

	err = det_dereg_mr(co->mr);
	if (unlikely(err))
		printk(KERN_INFO
			"det_co_free_mr: det_dereg_mr returned %d\n", err);

	det_user_unlock();
	if (co->mr->vaddr)
		vunmap((void *)(unsigned long)co->mr->vaddr);

	while (co->mr->page_cnt--)
		__free_page(co->mr->pages[co->mr->page_cnt]);

	vfree(co->mr);
	det_user_lock();
	co->mr = NULL;

	return 0;
}


static int det_co_alloc_mr(struct det_co * const co,
			   u32 size,
			   int mapped)
{
	struct det_mr_reg mr_reg;
	int page_cnt, err;
	u32 l_key;

	/*
	 * Since only one collective operation can be active at any time,
	 * only a single co mr is allowed to exist as a temporary buffer.
	 * If large enough, it may be re-used for subsequent operations;
	 * it only grows, does not shrink.  Note this routine may sleep.
	 */

	if (co->mr) {
		if ((co->mr->attr.base.length >= size) &&
		    (( mapped &&  co->mr->vaddr) ||
		     (!mapped && !co->mr->vaddr)))
			return 0;

		det_co_free_mr(co);
	}

	page_cnt = PAGE_ALIGN(size) >> PAGE_SHIFT;

	det_user_unlock();
	co->mr = vmalloc(sizeof(*co->mr) + (sizeof(struct page*) * page_cnt));
	if (unlikely(!co->mr)) {
		det_user_lock();
		return -ENOMEM;
	}

	co->mr->page_cnt = 0;
	mr_reg.vaddr = 0;

	for (; co->mr->page_cnt < page_cnt; co->mr->page_cnt++) {
		co->mr->pages[co->mr->page_cnt] = alloc_page(GFP_KERNEL);
		if (unlikely(!co->mr->pages[co->mr->page_cnt]))
			goto error;
	}

	if (mapped) {
		mr_reg.vaddr = (unsigned long)vmap(co->mr->pages,
						   page_cnt, VM_MAP,
						   PAGE_KERNEL);
		if (unlikely(!mr_reg.vaddr))
			goto error;
	}

	det_user_lock();

	mr_reg.length = size;
	mr_reg.access = DET_AC_LOCAL_READ | DET_AC_LOCAL_WRITE;

	err = det_reg_mr(co->qp.attr.pd, &mr_reg, &l_key, NULL, co->mr);
	if (unlikely(err))
		goto error;

	return 0;
error:
	while (co->mr->page_cnt--)
		__free_page(co->mr->pages[co->mr->page_cnt]);

	vfree(co->mr);
	det_user_lock();
	co->mr = NULL;
	return -ENOMEM;
}


static void det_co_free_tmp(struct det_co * const co)
{
	if (co->tmp) {
		kfree(co->tmp);
		co->tmp = NULL;
		co->tmp_size = 0;
	}
}


static int det_co_alloc_tmp(struct det_co * const co,
			    u32 size)
{
	if (co->tmp) {
		if (co->tmp_size >= size)
			return 0;

		det_co_free_tmp(co);
	}

	co->tmp = kmalloc(size, GFP_ATOMIC);
	if (unlikely(!co->tmp))
		return -ENOMEM;

	co->tmp_size = size;
	return 0;
}


void det_co_async_event(struct det_co * const co,
			const enum det_event_code code,
			const enum det_type type,
			void * const handle)
{
	WARN_ON((type != DET_TYPE_QP) && (type != DET_TYPE_CQ));
	det_qp_internal_disconnect(&co->qp, code);
}


#ifdef	DET_TRIGGERED_WR
int det_trig_send(struct det_qp * const qp,
		  const u64 id,
		  const struct det_local_ds * const ds_array,
		  const u32 num_ds,
		  const s32 trigger,
		  struct det_qp * const signal)
{
	struct det_wr *uninitialized_var(wr);
	int total_length, err;

	if (unlikely(num_ds > qp->attr.sq_sges))
		return -E2BIG;

	err = det_reserve_sq_wqe(qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	total_length = det_validate_ds(qp->attr.pd, ds_array, wr->ds_array,
					num_ds, DET_AC_LOCAL_READ, 1);
	if (unlikely(total_length < 0))
		goto out;

	wr->type = DET_WR_SEND;
	wr->total_length = (u32)total_length;
	wr->id = id;
	wr->flags = 0;
	wr->msg_id = qp->wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);
	wr->num_ds = num_ds;

	wr->trigger = trigger;
	wr->signal  = signal;

	det_append_sq_wqe(qp);
	det_schedule(DET_SCHEDULE_NEW, qp);

	return 0;

out:
	det_release_sq_wqe(qp);
	return total_length;
}


int det_trig_recv(struct det_qp * const qp,
		  const u64 id,
		  const struct det_local_ds * const ds_array,
		  const u32 num_ds,
		  struct det_qp * const signal)
{
	struct det_wr *uninitialized_var(wr);
	struct sk_buff *skb;
	union det_pdu *pdu;
	struct det_rx_state *rx;
	int total_length, err;

	if (unlikely(num_ds > qp->attr.rq_sges))
		return -E2BIG;

	err = det_reserve_rq_wqe(qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));

	total_length = det_validate_ds(qp->attr.pd, ds_array, wr->ds_array,
					num_ds, DET_AC_LOCAL_WRITE, 0);
	if (unlikely(total_length < 0))
		goto out;

	wr->type = DET_WR_RECV;
	wr->total_length = (u32)total_length;
	wr->id = id;
	wr->msg_id = qp->rq.next_msg_id;
	atomic_set(&wr->state, WR_STATE_WAITING);
	wr->num_ds = num_ds;

	wr->signal = signal;

	det_append_rq_wqe(qp);

	if (qp->loopback) {
		rq_unlock_bh(&qp->rq.lock);
		det_loopback_rq(qp);
		return 0;
	}
	rx = &qp->wirestate.sq_rx;
	rx->defer_in_process = 1;
	wmb();
	while ((skb = skb_peek(&rx->co_deferred))) {
		pdu = (union det_pdu *)skb->data;
		if (det_get_msg_id(pdu) != wr->msg_id)
			break;

		skb = skb_dequeue(&rx->co_deferred);
		rq_unlock_bh(&qp->rq.lock);
		local_bh_disable();
		det_process_pdu(qp, pdu, skb, 1);
		err = atomic_read(&qp->dma_pending) ?
			det_wait_on_dma(qp) : 0;
		if (likely(!err))
			det_schedule_rx_completions(qp, 0);
		local_bh_enable();
		kfree_skb(skb);
		rq_lock_bh(&qp->rq.lock);
		if (unlikely(err))
			break;
	}
	rx->defer_in_process = 0;
	wmb();
	rq_unlock_bh(&qp->rq.lock);

	return 0;
out:
	det_release_rq_wqe(qp);
	return total_length;
}

static int det_post_twr(const struct det_twr * const twr,
			s32 trigger,
			struct det_qp *signal)
{
	int err;

	if (!twr)
		return 0;

	switch (twr->type) {
	case DET_WR_SEND:
		err = det_trig_send(twr->qp, twr->id, twr->ds_array,
				    twr->num_ds, trigger, signal);
		if (unlikely(err))
			printk(KERN_INFO
				"det_post_twr: det_trig_send error %d\n", err);
		break;
	case DET_WR_RECV:
		err = det_trig_recv(twr->qp, twr->id, twr->ds_array,
				    twr->num_ds, signal);
		if (unlikely(err))
			printk(KERN_INFO
				"det_post_twr: det_trig_recv error %d\n", err);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}
#endif


#ifdef CONFIG_DET_DOORBELL
static int det_complete_co_wr(struct det_co *co,
			      enum det_wc_status status)
{
	struct det_wq *wq = &co->qp.sq;
	struct det_wr *wr;
	struct det_wc *wc;
	u32 target;

	sq_lock_bh(&wq->lock);

	target = (wq->head + wq->completion_cnt) % wq->size;
	if (target == wq->tail)
		goto done;

	wr = det_get_wr(wq, target);

	det_clear_ds_refs(wr->ds_array, wr->num_ds);

	/* Reserved WR's are never sent - update next active here. */
	if (wr->flags & DET_WR_CO_RESERVED)
		wq->next_active_wr = (wq->next_active_wr + 1) % wq->size;

	if (wr->flags & DET_WR_SURPRESSED)
		goto done;

	wc = &co->qp.doorbell->co_wc;

	if (det_tm_stamp_wc)
		PERF_GET_HRC(wc->id);
	else
	wc->id     = wr->id;
	wc->status = status;
	wc->type   = wr->type;
	wc->flags  = 0;
	wc->length = ((status != DET_WS_SUCCESS) ||
		      (wr->type == DET_WR_JOIN)) ? 0 : wr->total_length;

	/* Do a manual streamlined det_retire_wqes(). */
	wq->head = (wq->head + 1) % wq->size;
	wq->depth--;

	wmb();	/* Make sure wc is written before incrementing count. */
	co->qp.doorbell->co_current_wc_count++;
	wmb();	/* Make sure count is written before notify cq. */

	sq_unlock_bh(&wq->lock);

	/* Make sure there is a depth or notify will bail. */
	atomic_inc(&co->qp.attr.sq_cq->depth);
	det_notify_cq(co->qp.attr.sq_cq);
	atomic_dec(&co->qp.attr.sq_cq->depth);

	return 0;
done:
	sq_unlock_bh(&wq->lock);

	return 0;
}

#else
static int det_complete_co_wr(struct det_co *co,
			      enum det_wc_status status)
{
	struct det_wq *wq = &co->qp.sq;
	struct det_wr *wr;
	struct det_wc *uninitialized_var(wc);
	u32 target;
	int err;

	sq_lock_bh(&wq->lock);

	target = (wq->head + wq->completion_cnt) % wq->size;
	if (target == wq->tail)
		goto done;

	wr = det_get_wr(wq, target);

	det_clear_ds_refs(wr->ds_array, wr->num_ds);

	wq->completion_cnt++;
	wq->reap_cnt++;

	/* Reserved WR's are never sent - update next active here. */
	if (wr->flags & DET_WR_CO_RESERVED)
		wq->next_active_wr = (wq->next_active_wr + 1) % wq->size;

	if (wr->flags & DET_WR_SURPRESSED)
		goto done;

	err = det_reserve_cqe(co->qp.attr.sq_cq, &wc);
	if (unlikely(err)) {
		sq_unlock_bh(&wq->lock);
		printk(KERN_INFO
			"det_complete_co_wr: det_reserve_cqe error %d\n", err);
		return (err == -ENOSPC) ? DET_AE_CQ_OVERRUN :
					  DET_AE_CQ_FATAL;
	}
	if (det_tm_stamp_wc)
		PERF_GET_HRC(wc->id);
	else
	wc->id             = wr->id;
	wc->status	   = status;
	wc->type	   = wr->type;
	wc->flags	   = 0;
	wc->immediate_data = 0;
	wc->length	   = ((status != DET_WS_SUCCESS) ||
			      (wr->type == DET_WR_JOIN)) ? 0 : wr->total_length;
	wc->reserved = (unsigned long)wq;
	wc->reap_cnt = wq->reap_cnt;
	wq->reap_cnt = 0;

	det_append_cqe(co->qp.attr.sq_cq, wc);

	sq_unlock_bh(&wq->lock);
	det_notify_cq(co->qp.attr.sq_cq);

	return 0;
done:
	sq_unlock_bh(&wq->lock);

	return 0;
}
#endif

static int det_next_action(struct det_co * const co,
			   const det_co_next action,
			   const enum det_cq_arm arm,
			   const u32 threshold)
{
	co->next = action;
	wmb();
	return det_arm_cq(&co->cq, arm, threshold);
}


static void det_co_next_cb(struct det_co * const co)
{
	det_co_next next;
	int err;

	if ((next = co->next)) {
		co->next = NULL;  /* The call is a one-shot. */
		err = next(co);
		if (unlikely(err)) {
			printk(KERN_INFO "det_co_next_cb: error %d\n", err);
			det_qp_internal_disconnect(&co->qp, err);
		}
	}
}


#if defined(DET_CO_TASKLET) || defined(DET_TRIGGERED_WR)
static void det_co_task_cb(unsigned long co_ptr)
{
	/*
	 * If the tasklet is scheduled again before it has a chance to run,
	 * it runs only once.  However, if it is scheduled while it runs,
	 * it runs again after it completes.
	 */
	det_user_lock();
	det_co_next_cb((struct det_co *)co_ptr);
	det_user_unlock();
}


static inline void det_co_sched_task(struct det_co * const co)
{
	qp_lock_bh(&co->qp.lock);
	if (co->qp.attr.state == DET_QP_CONNECTED)
		tasklet_hi_schedule(&co->task);
	qp_unlock_bh(&co->qp.lock);
}
#endif


static void det_co_cq_cb(struct det_cq * const cq)
{
	struct det_co *co = cq_get_co(cq);

#ifdef DET_CO_TASKLET
	/*
	 * CQ callbacks occur with the SQ or RQ lock held, so new
	 * work requests cannot be posted directly from this callback.
	 * Schedule a tasklet to process completions.
	 */
	det_co_sched_task(co);
#else
	det_co_next_cb(co);
#endif
}


static int det_co_connect(struct det_co * const co,
			  struct det_join_ack *join,
			  int size)
{
	struct det_qp_mod qp_mod;
	int i, err;

	/* Walk through the join data and connect QPs to other members. */
	for (i = 0; i < co->size; i++, join = (void *)join + size) {

		/* Skip this rank's data. */
		if (join->rank == co->rank)
			continue;

		/* The join root QPs are already half-connected. */
		if (co->qp_array[join->rank]->attr.state == DET_QP_CONNECTED) {
			co->qp_array[join->rank]->attr.remote_mac = join->mac;
			co->qp_array[join->rank]->attr.remote_qp_num =
				NTOH32(join->qp_num[co->rank]);
			det_qp_loopback(co->qp_array[join->rank]);
			continue;
		}

		qp_mod.remote_qp_num = NTOH32(join->qp_num[co->rank]);
		qp_mod.remote_mac    = join->mac;
		qp_mod.next_state    = DET_QP_CONNECTED;
		qp_mod.flags	     = DET_QP_MOD_STATE_FLAG;

		err = det_modify_qp(co->qp_array[join->rank], &qp_mod, NULL);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_co_connect: det_modify_qp error %d\n",
				err);
			return err;
		}
	}

	return 0;
}


static int det_co_join_release(struct det_co * const co)
{
	int err = det_complete_co_wr(co, DET_WS_SUCCESS);
	if (unlikely(err))
		printk(KERN_INFO
			"det_co_join_release: det_complete_co_wr error %d\n",
			err);
	return err;
}


static int det_co_join_rel_cb(struct det_co * const co)
{
	struct det_wc wc;
	u32 i, num_wc;
	int err;

	/* Poll completions. */
	for (i = 0; i < co->size; i++) {

		if (i == co->rank)
			continue;

		num_wc = 1;
		err = det_poll_cq(&co->cq, &num_wc, &wc);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_co_join_rel_cb: poll cq error %d\n",
				err);
			goto out;
		}

		if (wc.status != DET_WS_SUCCESS) {
			printk(KERN_INFO
				"det_co_join_rel_cb: wc.status %d\n",
				wc.status);
			err = -EIO;
			goto out;
		}

		if (wc.type != DET_WC_SEND) {
			printk(KERN_INFO
				"det_co_join_rel_cb: type %d expected %d\n",
				wc.type, DET_WC_SEND);
			goto out;
		}
	}

	err = det_co_join_release(co);
	if (unlikely(err))
		printk(KERN_INFO
			"det_co_join_rel_cb: det_co_join_release error %d\n",
			err);
out:
	return err;
}


static int det_co_join_data_cb(struct det_co * const co)
{
	struct det_wc wc;
	u32 i, num_wc;
	int err;

	/* Poll completions. */
	for (i = 0; i < co->cq.attr.threshold; i++) {
		num_wc = 1;
		err = det_poll_cq(&co->cq, &num_wc, &wc);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_co_join_data_cb: poll cq error %d\n",
				err);
			return err;
		}

		if (wc.status != DET_WS_SUCCESS) {
			printk(KERN_INFO
				"det_co_join_data_cb: wc.status %d\n",
				wc.status);
			return -EIO;
		}
	}

	/* Set the next action for the join release. */
	err = det_next_action(co, det_co_join_rel_cb,
			      DET_CQ_THRESHOLD, co->size - 1);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_co_join_data_cb: det_next_action error %d\n",
			err);
		return err;
	}

	/* Send the final join release all other ranks. */
	for (i = 0; i < co->size; i++) {

		if (i == co->rank)
			continue;

		err = det_send(co->qp_array[i], 0, NULL, 0, 0, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_co_join_data_cb: det_send error %d\n",
				err);
			break;
		}
	}

	return err;
}


static int det_co_root_join_cb(struct det_co * const co)
{
	struct det_join_ack *join_ack;
	struct det_wq *wq;
	struct det_wr *wr;
	struct det_wc wc;
	struct det_local_ds ds;
	int ack_size, err;
	u32 i, num_wc;

	/* Calculate the size of the join ack data. */
	ack_size  = sizeof(*join_ack);			/* Base structure */
	ack_size += sizeof(net32_t) * co->size;		/* QP num array   */
	join_ack  = (struct det_join_ack *)(unsigned long)co->mr->vaddr;

	/* Poll completions. */
	for (i = 0; i < co->size; i++) {

		if (i == co->rank)
			continue;

		num_wc = 1;
		err = det_poll_cq(&co->cq, &num_wc, &wc);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_co_root_join_cb: poll cq error %d\n",
				err);
			goto out;
		}

		if (wc.status != DET_WS_SUCCESS) {
			printk(KERN_INFO
				"det_co_root_join_cb: wc.status %d\n",
				wc.status);
			err = -EIO;
			goto out;
		}

		if (wc.type != DET_WC_RECV) {
			printk(KERN_INFO
				"det_co_root_join_cb: type %d expected %d\n",
				wc.type, DET_WC_RECV);
			goto out;
		}

		if (unlikely(wc.length != ack_size)) {
			printk(KERN_INFO
				"det_co_root_join_cb: size %d expected %d\n",
				wc.length, ack_size);
			goto out;
		}
	}

	/* Stop the join broadcast - it should be the WR at the head. */
	wq = &co->qp.sq;
	sq_lock_bh(&wq->lock);
	wr = det_get_wr(wq, wq->head);
	if (unlikely(wr->type != DET_WR_JOIN)) {
		sq_unlock_bh(&wq->lock);
		err = -EIO;
		goto out;
	}
	wr->flags |= DET_WR_CO_RESERVED;
	det_clear_ds_refs(wr->ds_array, wr->num_ds);
	wq->next_active_wr--;
	sq_unlock_bh(&wq->lock);

	err = det_co_connect(co, join_ack, ack_size);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_co_root_join_cb: det_co_connect error %d\n", err);
		goto out;
	}

	/*
	 * Set the next action after the join data sends posted below
	 * and the join complete messages from all other ranks.
	 */
	err = det_next_action(co, det_co_join_data_cb,
			      DET_CQ_THRESHOLD, (co->size - 1) * 2);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_co_root_join_cb: det_next_action error %d\n", err);
		goto out;
	}

	/* Post receives and send the join data to all other ranks. */
	for (i = 0; i < co->size; i++) {

		if (i == co->rank)
			continue;

		err = det_recv(co->qp_array[i], 0, NULL, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_co_root_join_cb: det_recv error %d\n",
				err);
			goto out;
		}

		ds.l_key  = co->mr->attr.l_key;
		ds.length = ack_size * co->size;
		ds.vaddr  = (unsigned long)join_ack;

		err = det_send(co->qp_array[i], 0, &ds, 1, 0, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_co_root_join_cb: det_send error %d\n",
				err);
			goto out;
		}
	}
out:
	return err;
}


static int det_co_rank_complete_cb(struct det_co * const co)
{
	u32 num_wc;
	struct det_wc wc[2];
	int i, err;

	/* There should be two completions, one send and one receive. */
	num_wc = 2;
	err = det_poll_cq(&co->cq, &num_wc, wc);
	if (unlikely(err)) {
		printk(KERN_INFO "det_co_rank_complete_cb: poll cq error %d\n",
			err);
		goto out;
	}

	if (num_wc != 2) {
		printk(KERN_INFO
			"det_co_rank_complete_cb: expected 2 got %d\n", num_wc);
		err = -EIO;
		goto out;
	}

	for (i = 0; i < num_wc; i++) {
		if (wc[i].status != DET_WS_SUCCESS) {
			printk(KERN_INFO
				"det_co_rank_complete_cb: wc[%d].status %d\n",
				i, wc[i].status);
			err = -EIO;
			goto out;
		}
	}

	err = det_co_join_release(co);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_co_rank_complete_cb: det_co_join_release error %d\n",
			err);
	}
out:
	return err;
}


static int det_co_rank_join_cb(struct det_co * const co)
{
	u32 num_wc;
	struct det_wc wc[2];
	struct det_join_ack *join_ack;
	int i, ack_size, err;

	/* Calculate the size of the join ack data. */
	ack_size  = sizeof(*join_ack);			/* Base structure */
	ack_size += sizeof(net32_t) * co->size;		/* QP num array   */
	join_ack  = (struct det_join_ack *)(unsigned long)co->mr->vaddr;

	/* There should be two completions, one send and one receive. */
	num_wc = 2;
	err = det_poll_cq(&co->cq, &num_wc, wc);
	if (unlikely(err)) {
		printk(KERN_INFO "det_co_rank_join_cb: poll cq error %d\n",
			err);
		goto out;
	}

	if (num_wc != 2) {
		printk(KERN_INFO
			"det_co_rank_join_cb: expected 2 got %d\n", num_wc);
		err = -EIO;
		goto out;
	}

	for (i = 0; i < num_wc; i++) {
		if (wc[i].status != DET_WS_SUCCESS) {
			printk(KERN_INFO
				"det_co_rank_join_cb: wc[%d].status %d\n",
				i, wc[i].status);
			err = -EIO;
			goto out;
		}

		if (wc[i].type == DET_WC_SEND)
			continue;

		WARN_ON(wc[i].type != DET_WC_RECV);

		if (unlikely(wc[i].length != (ack_size * co->size))) {
			printk(KERN_INFO
				"det_co_rank_join_cb: size %d expected %d\n",
				wc[i].length, ack_size * co->size);
			goto out;
		}

		err = det_co_connect(co, join_ack, ack_size);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_co_rank_join_cb: det_co_connect error %d\n",
				err);
			goto out;
		}
	}

	/*
	 * Set the next action after two completions:
	 *    - the send of the join completion posted below
	 *    - the receive of the join release message
	 */
	err = det_next_action(co, det_co_rank_complete_cb, DET_CQ_THRESHOLD, 2);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_co_rank_join_cb: det_next_action error %d\n", err);
		return err;
	}

	/* Send the join completion message to rank 0. */
	err = det_send(co->qp_array[0], 0, NULL, 0, 0, 0);
	if (unlikely(err)) {
		printk(KERN_INFO "det_co_rank_complete_cb: det_send error %d\n",
			err);
	}
out:
	return err;
}


static int det_process_join(struct det_co *co,
			    union det_pdu *pdu,
			    struct sk_buff *skb)
{
	struct det_join_ack *join;
	struct det_qp_mod qp_mod;
	struct det_local_ds ds;
	int err;

	if (pdu->join.size != co->size)
		return -EINVAL;

	/*
	 * This looks strange, but we acquire and release the SQ lock to
	 * synchronize with becoming a member and posting the WR in det_join.
	 */
	sq_lock_bh(&co->qp.sq.lock);
	sq_unlock_bh(&co->qp.sq.lock);

	/*
	 * Remove PDU header.  Since the skb may be passed to another
	 * rank running on this node, we can't mess with skb pointers.
	 * So, we'll do a virutal skb_pull()...
	 *
	 *  skb_pull(skb, sizeof(pdu->join));
	 */
	join = (struct det_join_ack *)(skb->data + sizeof(pdu->join));

	/* verify this is not a re-broadcast */
	if (co->qp_array[join->rank]->attr.state == DET_QP_CONNECTED)
		return 0;

	/* Connect the QP to the root of the join. */
	qp_mod.remote_qp_num = NTOH32(join->qp_num[co->rank]);
	qp_mod.remote_mac    = join->mac;
	qp_mod.next_state    = DET_QP_CONNECTED;
	qp_mod.flags	     = DET_QP_MOD_STATE_FLAG;

	err = det_modify_qp(co->qp_array[join->rank], &qp_mod, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_process_join: det_modify_qp error %d\n",
			err);
		return err;
	}

	/*
	 * Set the next action after two completions:
	 *    - the send of the join ack posted below
	 *    - the receive of join response data posted non-root members
	 */
	err = det_next_action(co, det_co_rank_join_cb, DET_CQ_THRESHOLD, 2);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_process_join: det_next_action error %d\n", err);
		return err;
	}

	/* Calculate the join ack data size to initialize the data segment. */
	ds.length  = sizeof(*join);			/* Base structure */
	ds.length += sizeof(net32_t) * co->size;	/* QP num array   */
	ds.vaddr   = co->mr->vaddr + (ds.length * co->rank);
	ds.l_key   = co->mr->attr.l_key;

	/* Send the root a join ack. */
	err = det_send(co->qp_array[pdu->join.root], 0, &ds, 1, 0, 0);
	if (unlikely(err))
		printk(KERN_INFO "det_process_join: det_send error %d\n", err);

	return err;
}


int det_create_co(struct det_pd * const pd,
		  struct det_cq * const cq,
		  struct det_co * const co)
{
	struct det_device *detdev = pd->detdev;
	struct det_qp_create qp_create;
	int err;

	if (unlikely(detdev->co_cnt >= MAX_COS))
		return -EAGAIN;

	co->type	= DET_TYPE_CO;
	co->detdev	= detdev;
	co->tmp		= NULL;
	co->group	= NULL;
	co->qp_array	= NULL;
	co->next	= NULL;
	co->mr		= NULL;
	det_spin_lock_init(&co->lock);
#if defined(DET_CO_TASKLET) || defined(DET_TRIGGERED_WR)
	tasklet_init(&co->task, det_co_task_cb, (unsigned long)co);
#endif

	memset(&qp_create, 0, sizeof(qp_create));
	qp_create.sq_cq	  = cq;
	qp_create.sq_size = 1;

	err = det_create_qp(pd, &qp_create, NULL, &co->qp);
	if (unlikely(err))
		return err;

	/* Truncate the SQ attributes to one outstanding work request. */
	co->qp.attr.sq_size = 1;

	qp_set_co(&co->qp, co);

	/* Create a CQ for internal completions. */
	co->cq.event = NULL;
	err = det_create_cq(pd->nic, 0, det_co_cq_cb, NULL, &co->cq);
	if (unlikely(err)) {
		det_destroy_qp(&co->qp);
		return err;
	}

	cq_set_co(&co->cq, co);

	write_lock(&detdev->lock);
	list_add_tail(&co->entry, &detdev->co_list);
	detdev->co_cnt++;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_create_co);


int det_join(struct det_co * const co,
	     const __u64 id,
	     const net64_t tag,
	     const int size,
	     const int rank,
	     const enum det_wr_flags flags)
{
	static DECLARE_MUTEX(mutex);

	struct det_group *grp;
	struct det_qp_mod qp_mod;
	struct det_wr *wr = NULL;
	struct det_join_ack *join_ack, *ack_array = NULL;
	struct det_local_ds ds;
	int nr_sges, ack_size, i, new_grp, err;

	/*
	 * Prevent another thread/process from doing a join so we don't
	 * have to hold the collective lock throughout this routine.
	 */
	det_serialize_start(&mutex, NULL, NULL);

	if (unlikely(co->qp.attr.state == DET_QP_CONNECTED)) {
		det_serialize_end(&mutex);
		return -EBUSY;
	}

	if (unlikely(size < 2)) {
		det_serialize_end(&mutex);
		return -EINVAL;
	}

	/* Calculate the minimum number of SGEs that may be required. */

	/*
	 * The allgatherv Bruck dissemination algorithm will post WRs with
	 * a maximum of pof2(floor(lg p)-1) SGEs in the first floor(lg p)
	 * steps, but a remainder number of SGEs in the last step if the
	 * size is not a power of 2.  Take the maximum of these requirements.
	 */
	nr_sges = max(pof2(floor_log2(size) - 1), size - pof2(floor_log2(size)));
#ifdef	DET_USE_DIRECT_INDEXING
	/*
	 * The alltoall Bruck indexing algorithm requires an SGE for each jth
	 * data block transferred (see algorithm) for direct data placement.
	 */
	nr_sges = max(nr_sges, (size / 2) + is_odd(size));
#endif
	/*
	 * Finally, the binomial tree algorithms may require at least 2 SGEs.
	 */
	nr_sges = max(nr_sges, 2);

	if (unlikely(nr_sges > MAX_SGES)) {
		det_serialize_end(&mutex);
		return -E2BIG;
	}

	/*
	 * Check the size of the join ack data to make sure the
	 * data from the root will fit in a single broadcast PDU.
	 *
	 * TODO: remove this limitation.
	 */
	ack_size  = sizeof(*join_ack);			/* Base structure */
	ack_size += sizeof(net32_t) * size;		/* QP num array   */
	if ((sizeof(struct ethhdr) + sizeof(struct det_send_hdr) + ack_size) >
	    co->qp.attr.mtu_size) {
		det_serialize_end(&mutex);
		return -E2BIG;
	}

	if (unlikely(rank >= size)) {
		det_serialize_end(&mutex);
		return -EINVAL;
	}

	co->size = size;
	co->rank = rank;

	/* Make sure group tag is unique and this rank is unregistered. */
	new_grp = 0;
	collective_grp_lock();
	list_for_each_entry(grp, &collective_grp_list, entry) {
		if (grp->tag == tag) {
			if ((grp->size != co->size) || (grp->co[co->rank])) {
				collective_grp_unlock();
				det_serialize_end(&mutex);
				return -EEXIST;
			}
			atomic_inc(&grp->refcnt);
			break;
		}
	}
	collective_grp_unlock();

	/* See if collective group object needs to be created. */
	if (&grp->entry == &collective_grp_list) {
		det_user_unlock();
		grp = vmalloc(sizeof(*grp) + (co->size * sizeof(co)));
		det_user_lock();
		if (grp == NULL) {
			det_serialize_end(&mutex);
			return -ENOMEM;
		}
		new_grp = 1;

		memset(grp, 0, sizeof(*grp) + (co->size * sizeof(co)));
		INIT_LIST_HEAD(&grp->entry);
		det_spin_lock_init(&grp->lock);
		grp->tag = tag;
		grp->size = co->size;
		init_completion(&grp->done);
		atomic_set(&grp->refcnt, 1);
	}

	/* Resize the internal CQ. */
	err = det_resize_cq(&co->cq, co->size * 2, NULL);
	if (unlikely(err))
		goto out;

	/* Allocate an array to hold the QP pointers. */
	det_user_unlock();
	co->qp_array = vmalloc(sizeof(*co->qp_array) * co->size);
	det_user_lock();
	if (unlikely(!co->qp_array)) {
		err = -ENOMEM;
		goto out;
	}
	memset(co->qp_array, 0, sizeof(*co->qp_array) * co->size);

	/* Create QPs for all other ranks (excluding this rank). */
	for (i = 0; i < co->size; i++) {
		struct det_qp_create qp_create;

		if (i == co->rank)
			continue;

		det_user_unlock();
		co->qp_array[i] = (void *)vmalloc(sizeof(**co->qp_array));
		det_user_lock();
		if (unlikely(!co->qp_array[i])) {
			err = -ENOMEM;
			goto out;
		}

#ifdef CONFIG_DET_DOORBELL
		co->qp_array[i]->doorbell = NULL;
		co->qp_array[i]->doorbell_page = NULL;
#endif
		/* SQ and RQ must be configured identically. */
		qp_create.max_or  = qp_create.max_ir  = 0;
		qp_create.sq_cq	  = qp_create.rq_cq   = &co->cq;
		qp_create.sq_size = qp_create.rq_size = co->size;
		qp_create.sq_sges = qp_create.rq_sges = nr_sges;

		err = det_create_qp(co->qp.attr.pd, &qp_create, NULL,
				    co->qp_array[i]);
		if (unlikely(err)) {
			det_user_unlock();
			vfree(co->qp_array[i]);
			det_user_lock();
			co->qp_array[i] = NULL;
			goto out;
		}

		qp_set_co(co->qp_array[i], co);
		co->qp_array[i]->valid = 1;
	}

	/* Allocate an array for the join ack data from all ranks. */
	err = det_co_alloc_mr(co, ack_size * co->size, 1);
	if (unlikely(err))
		goto out;

	ack_array = (void *)(unsigned long)co->mr->vaddr;
	memset(ack_array, 0, ack_size * co->size);

	/* Fill the join ack data for this rank. */
	join_ack = (void *)ack_array + (ack_size * co->rank);
	join_ack->rank = co->rank;
	join_ack->mac  = co->qp.attr.local_mac;
	for (i = 0; i < co->size; i++) {

		if (i == co->rank)
			continue;

		join_ack->qp_num[i] = HTON32(co->qp_array[i]->attr.local_qp_num);
	}

	/*
	 * Now prepare the co->qp.
	 * The co->qp is only used to broadcast the join request and to queue
	 * and complete client WRs.  Collective data transfer operations use
	 * the QP array and the internal CQ.  Rank 0 is the root of the join.
	 */
	memset(&qp_mod.remote_mac.addr, 0xff, DET_MAC_ADDR_LEN);
	qp_mod.remote_qp_num = -1;
	qp_mod.next_state    = DET_QP_CONNECTED;
	qp_mod.flags	     = DET_QP_MOD_STATE_FLAG;

	err = det_modify_qp(&co->qp, &qp_mod, NULL);
	if (unlikely(err))
		goto out;

	if (co->rank == 0) {
		/* Post a receive for join ack data from all other ranks. */
		for (i = 0; i < co->size; i++) {

			if (i == co->rank)
				continue;

			/* Half-connect to allow receives. */
			memset(&qp_mod.remote_mac.addr, 0xff, DET_MAC_ADDR_LEN);
			qp_mod.remote_qp_num = -1;
			qp_mod.next_state    = DET_QP_CONNECTED;
			qp_mod.flags	     = DET_QP_MOD_STATE_FLAG;

			err = det_modify_qp(co->qp_array[i], &qp_mod, NULL);
			if (unlikely(err))
				goto out;

			ds.l_key  = co->mr->attr.l_key;
			ds.length = ack_size;
			ds.vaddr  = (unsigned long)((void *)ack_array +
						    (ack_size * i));
			err = det_recv(co->qp_array[i], 0, &ds, 1);
			if (unlikely(err))
				goto out;
		}

		/* Set the next action for the last receive completion. */
		err = det_next_action(co, det_co_root_join_cb,
				      DET_CQ_THRESHOLD, co->size - 1);
		if (unlikely(err))
			goto out;
	} else {
		/* Post a receive for the join response data from rank 0. */
		ds.l_key  = co->mr->attr.l_key;
		ds.length = ack_size * co->size;
		ds.vaddr  = (unsigned long)ack_array;

		err = det_recv(co->qp_array[0], 0, &ds, 1);
		if (unlikely(err))
			goto out;

		/* Post a 0-byte receive for the final rank 0 join release. */
		err = det_recv(co->qp_array[0], 0, NULL, 0);
		if (unlikely(err))
			goto out;
	}

	/* Get a WR to for the join request. */
	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		goto out;

	/* If root, prepare the WR to broadcast the root join data. */
	if (co->rank == 0) {
		ds.l_key  = co->mr->attr.l_key;
		ds.length = ack_size;
		ds.vaddr  = (unsigned long)ack_array;

		i = det_validate_ds(co->qp.attr.pd, &ds, wr->ds_array,
				    1, DET_AC_LOCAL_READ, 1);
		if (unlikely(i < 0)) {
			err = i;
			goto out;
		}
	}

	/*
	 * No error paths beyond this point.
	 * Place in group list if just created.
	 */
	if (new_grp) {
		collective_grp_lock();
		list_add_tail(&grp->entry, &collective_grp_list);
		collective_grp_unlock();
	}

	/* Now become a member of the group. */
	co->group = grp;
	wmb();
	grp->co[co->rank] = co;

	det_serialize_end(&mutex);

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_JOIN;
	wr->id = id;
	wr->flags = flags | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	if (co->rank == 0) {
		wr->num_ds = 1;
		wr->total_length = i;
	} else {
		wr->num_ds = 0;
		wr->total_length = 0;
		wr->flags |= DET_WR_CO_RESERVED;
	}

	det_append_sq_wqe(&co->qp);
	det_schedule(DET_SCHEDULE_NEW, &co->qp);

	return 0;
out:
	if (wr)
		det_release_sq_wqe(&co->qp);

	if (co->qp.attr.state != DET_QP_IDLE)
		det_qp_idle(&co->qp);

	det_serialize_end(&mutex);

	if (new_grp) {
		det_user_unlock();
		vfree(grp);
		det_user_lock();
	} else if (atomic_dec_and_test(&grp->refcnt))
		complete(&grp->done);

	if (co->qp_array) {
		for (i = 0; i < co->size; i++) {
			if (!co->qp_array[i])
				continue;
			det_destroy_qp(co->qp_array[i]);
			det_user_unlock();
			vfree(co->qp_array[i]);
			det_user_lock();
		}
		det_user_unlock();
		vfree(co->qp_array);
		det_user_lock();
		co->qp_array = NULL;
	}

	det_co_free_mr(co);

	return err;
}
EXPORT_SYMBOL(det_join);


int det_destroy_co(struct det_co * const co)
{
	struct det_device *detdev = co->detdev;
	struct det_qp_mod qp_mod;
	int i = -1;

	/*  If a member, remove yourself from the group list. */
	if (co->group) {
		group_lock(&co->group->lock);
		co->group->co[co->rank] = NULL;
		group_unlock(&co->group->lock);

		collective_grp_lock();
		if (!list_empty(&co->group->entry)) {
			/* Count empty local members. */
			for (i = 0; (i < co->size) && !co->group->co[i]; i++)
				;
			if (i == co->size) {
				list_del_init(&co->group->entry);
			}
		}
		collective_grp_unlock();

		/* Release a group reference. */
		if (atomic_dec_and_test(&co->group->refcnt))
			complete(&co->group->done);
	}

	if (co->qp.attr.state == DET_QP_CONNECTED) {
		qp_mod.next_state = DET_QP_DISCONNECT;
		qp_mod.flags	  = DET_QP_MOD_STATE_FLAG;
		det_modify_qp(&co->qp, &qp_mod, NULL);
	}

	/* Check if last member (the group is empty). */
	if (i == co->size) {
		/* Wait for all references to go away. */
		det_user_unlock();
		wait_for_completion(&co->group->done);
		vfree(co->group);
		det_user_lock();
	}

#if defined(DET_CO_TASKLET) || defined(DET_TRIGGERED_WR)
	det_user_unlock();
	tasklet_kill(&co->task);
	det_user_lock();
#endif

	if (co->qp_array) {
		qp_mod.next_state = DET_QP_DISCONNECT;
		qp_mod.flags	  = DET_QP_MOD_STATE_FLAG;
		for (i = 0; i < co->size; i++) {
			if (!co->qp_array[i] ||
			    (co->qp_array[i]->attr.state != DET_QP_CONNECTED))
				continue;
			det_modify_qp(co->qp_array[i], &qp_mod, NULL);
		}
	}

	det_user_unlock();
	synchronize_net();
	det_user_lock();

	if (co->qp_array) {
		for (i = 0; i < co->size; i++) {
			if (!co->qp_array[i])
				continue;
			det_destroy_qp(co->qp_array[i]);
			det_user_unlock();
			vfree(co->qp_array[i]);
			det_user_lock();
		}
		det_user_unlock();
		vfree(co->qp_array);
		det_user_lock();
	}

	det_destroy_qp(&co->qp);
	det_destroy_cq(&co->cq);

	det_co_free_tmp(co);

	det_co_free_mr(co);

	write_lock(&detdev->lock);
	list_del(&co->entry);
	detdev->co_cnt--;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_destroy_co);


static int det_co_pollcomplete_cb(struct det_co * const co)
{
	struct det_wc wc;
	u32 num_wc;
	int i, err;

	for (i = 0; i < co->cq.attr.threshold; i++) {
		num_wc = 1;
		err = det_poll_cq(&co->cq, &num_wc, &wc);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_co_pollcomplete_cb: rank %d poll cq error %d\n",
				co->rank, err);
			return err;
		}

		if (unlikely(wc.status != DET_WS_SUCCESS)) {
			printk(KERN_INFO
				"det_co_pollcomplete_cb: rank %d wc.status %d\n",
				co->rank, wc.status);
			return -EIO;
		}
	}

	err = det_complete_co_wr(co, DET_WS_SUCCESS);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_co_pollcomplete_cb: det_complete_co_wr error %d\n",
			err);
		return err;
	}

	return 0;
}


static int det_co_sendrecv(struct det_co * const co,
			   u64 id,
			   int dst,
			   int src,
			   int num_snd_ds,
			   const struct det_local_ds * const snd_ds,
			   int num_rcv_ds,
			   const struct det_local_ds * const rcv_ds,
   			   const det_co_next action)
{
	int err;

	err = det_next_action(co, action, DET_CQ_THRESHOLD, 2);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_co_sendrecv: det_next_action error %d\n", err);
		return err;
	}

	err = det_recv(co->qp_array[src], id, rcv_ds, num_rcv_ds);
	if (unlikely(err)) {
		printk(KERN_INFO "det_co_sendrecv: det_recv error %d\n", err);
		return err;
	}

	err = det_send(co->qp_array[dst], id, snd_ds, num_snd_ds, 0, 0);
	if (unlikely(err)) {
		printk(KERN_INFO "det_co_sendrecv: det_send error %d\n", err);
		return err;
	}

	return 0;
}


static int det_co_sendrecv_cb(struct det_co * const co,
			      u64 * const id)
{
	struct det_wc wc[2];
	u32 num_wc;
	int i, err;

	num_wc = 2;
	err = det_poll_cq(&co->cq, &num_wc, wc);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_co_sendrecv_cb: rank %d poll cq error %d\n",
			co->rank, err);
		return err;
	}

	if (num_wc != 2) {
		printk(KERN_INFO
			"det_co_sendrecv_cb: rank %d expected 2 got %d\n",
			co->rank, num_wc);
		return -EIO;
	}

	for (i = 0; i < num_wc; i++) {
		if (wc[i].status == DET_WS_SUCCESS)
			continue;

		printk(KERN_INFO
			"det_co_sendrecv_cb: rank %d wc[%d].status %d\n",
			co->rank, i, wc[i].status);
		return -EIO;
	}

	*id = wc[0].id;

	return 0;
}


static int __det_barrier(struct det_co * const co,
			 struct det_wr * const wr)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr snd_wr, rcv_wr;
	int nr_sends = 0;
#endif
	int src, dst, err;

#ifdef	DET_TRIGGERED_WR
	snd_wr.id	= (unsigned long)wr;
	snd_wr.ds_array = NULL;
	snd_wr.num_ds	= 0;
	snd_wr.type	= DET_WR_SEND;

	rcv_wr.id	= (unsigned long)wr;
	rcv_wr.ds_array = NULL;
	rcv_wr.num_ds	= 0;
	rcv_wr.type	= DET_WR_RECV;

	while (wr->barrier.mask < co->size) {
#else
	if (wr->barrier.mask < co->size) {
#endif
		src = (co->rank - wr->barrier.mask  + co->size) % co->size;
		dst = (co->rank + wr->barrier.mask) % co->size;

		wr->barrier.mask <<= 1;

#ifdef	DET_TRIGGERED_WR
		if (nr_sends) {
			/*
			 * Post the previous work requests.
			 */
			err = det_post_twr(&snd_wr,
					   (nr_sends == 1) ? 0 :
						(nr_sends == 2) ? 1 : 2,
					   (nr_sends > 1) ?
						co->qp_array[dst] : NULL);
			if (unlikely(err)) {
				printk(KERN_INFO
					"__det_barrier: det_post_twr snd error %d\n",
					err);
				return err;
			}

			err = det_post_twr(&rcv_wr, 0, co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"__det_barrier: det_post_twr rcv error %d\n",
					err);
				return err;
			}
		}

		/* Set up the next work requests. */
		snd_wr.qp = co->qp_array[dst];
		rcv_wr.qp = co->qp_array[src];

		/* Prepare for next pass. */
		nr_sends++;
#else
		err = det_co_sendrecv(co, (unsigned long)wr, dst, src,
				      0, NULL, 0, NULL, det_barrier_cb);
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_barrier: rank %d det_co_sendrecv error %d\n",
				co->rank, err);
			return err;
		}

		return 0;
#endif
	}

#ifdef	DET_TRIGGERED_WR
	/* Post the last send/receive. */
	err = det_post_twr(&snd_wr,
			   (nr_sends == 1) ? 0 : (nr_sends == 2) ? 1 : 2, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO
			"__det_barrier: det_post_twr snd error %d\n",
			err);
		return err;
	}

	err = det_post_twr(&rcv_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "__det_barrier: det_post_twr rcv error %d\n", err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb,
			      DET_CQ_THRESHOLD, nr_sends + 1);
	if (unlikely(err)) {
		printk(KERN_INFO "__det_barrier: det_next_action error %d\n",
			err);
		return err;
	}
#else
	err = det_complete_co_wr(co, DET_WS_SUCCESS);
	if (unlikely(err)) {
		printk(KERN_INFO "__det_barrier: det_complete_co_wr error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_barrier_cb(struct det_co * const co)
{
	u64 id;
	int err;

	err = det_co_sendrecv_cb(co, &id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_barrier_cb: det_complete_co_wr error %d\n", err);
		return err;
	}

	err = __det_barrier(co, (struct det_wr *)(unsigned long)id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_barrier_cb: __det_barrier error %d\n", err);
		return err;
	}

	return 0;
}
#endif


/*
 *  Refer to the MPICH MPI_Barrier code for the algorithm.
 */
int det_barrier(struct det_co * const co,
		const __u64 id,
		const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int err;

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_BARRIER;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = 0;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	wr->barrier.mask = 1;

	err = __det_barrier(co, wr);
	if (unlikely(err)) {
		printk(KERN_INFO "det_barrier: __det_barrier error %d\n", err);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(det_barrier);


#ifdef	DET_TRIGGERED_WR
static int det_bcast_send(struct det_co * const co,
			  struct det_wr * const wr,
			  struct det_twr *twr)
#else
static int det_bcast_send(struct det_co * const co,
			  struct det_wr * const wr)
#endif
{
	int dst, err;
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig_wr;
	int recv, nr_sends = 0;

	recv = (twr) ? 1 : 0;
#endif
	/* This process is responsible for all processes that have bits
	set from the LSB upto (but not including) mask.  Because of
	the "not including", we start by shifting mask back down one.

	We can easily change to a different algorithm at any power of
	two by changing the test (mask > 1) to (mask > block_size) 

	One such version would use non-blocking operations for the last
	2-4 steps (this also bounds the number of MPI_Requests that
	would be needed). */

	wr->bcast.mask >>= 1;
	while (wr->bcast.mask > 0) {
		if (wr->bcast.relative_rank + wr->bcast.mask >= co->size) {
			wr->bcast.mask >>= 1;
			continue;
		}

		dst = co->rank + wr->bcast.mask;
		if (dst >= co->size)
			dst -= co->size;

#ifdef	DET_TRIGGERED_WR
		if (twr) {
			/* Post the previous work request. */
			err = det_post_twr(twr, ((nr_sends > 1) ||
						 (recv && nr_sends)) ? 1 : 0,
					   co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_bcast_send: det_post_twr error %d\n",
					err);
				return err;
			}
		} else
			twr = &trig_wr;

		/* Set up the next work request. */
		twr->id	      = (unsigned long)wr;
		twr->qp	      = co->qp_array[dst];
		twr->ds_array = &wr->bcast.ds;
		twr->num_ds   = 1;
		twr->type     = DET_WR_SEND;
		nr_sends++;

		wr->bcast.mask >>= 1;
#else
		err = det_send(co->qp_array[dst], (unsigned long)wr,
			       &wr->bcast.ds, 1, 0, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_send: det_send error %d\n", err);
			return err;
		}

		/*
		 * Note: we only initiate one send at a time to
		 * ensure parallelism across all ranks.  Posting
		 * more than one could serialize data transfer out
		 * the port and defeat the purpose of the algorithm.
		 */
		err = det_next_action(co, det_bcast_cb, DET_CQ_THRESHOLD, 1);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_send: det_next_action error %d\n",
				err);
			return err;
		}

		return 0;
#endif
	}

#ifdef	DET_TRIGGERED_WR
	err = det_post_twr(twr, ((nr_sends > 1) ||
			         (recv && nr_sends)) ? 1 : 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_send: det_post_twr error %d\n", err);
		return err;
	}

	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      (nr_sends) ? nr_sends : 1);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_send: det_next_action error %d\n",
			err);
		return err;
	}
#else
	/* If nothing was sent then this is root or leaf and bcast is done. */
	err = det_complete_co_wr(co, DET_WS_SUCCESS);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_send: det_complete_co_wr error %d\n", err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_bcast_cb(struct det_co * const co)
{
	struct det_wc wc;
	u32 num_wc;
	int err;

	num_wc = 1;
	err = det_poll_cq(&co->cq, &num_wc, &wc);
	if (unlikely(err)) {
		printk(KERN_INFO "det_bcast_cb: rank %d poll cq error %d\n",
			co->rank, err);
		return err;
	}

	if (unlikely(wc.status != DET_WS_SUCCESS)) {
		printk(KERN_INFO "det_bcast_cb: rank %d wc.status %d\n",
			co->rank, wc.status);
		err = -EIO;
		return err;
	}

	err = det_bcast_send(co, (struct det_wr *)(unsigned long)wc.id);
	if (unlikely(err)) {
		printk(KERN_INFO "det_bcast_cb: det_bcast_send error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


static int det_bcast_doubling(struct det_co * const co,
			      struct det_wr * const wr)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr snd_wr, rcv_wr;
#else
	struct det_local_ds snd_ds, rcv_ds;
	int scatter_size;
#endif
	int i, j, dst, relative_dst, err;

	/*
	Recursive Doubling Algorithm:
	In the first step, processes that are a distance 1 apart
	exchange their data.  In the second step, processes that
	are a distance 2 apart exchange their own data as well as
	the data they received in the previous step.  In the third
	step, processes that are a distance 4 apart exchange their
	own data as well the data they received in the previous
	two steps.  In this way, for a power-of-two number of
	processes, all processes get all the data in lg p steps. 
	*/

#ifdef	DET_TRIGGERED_WR
	/* Sends are dependant on multiple disjoint receives. */

	/* Setup the static twr fields. */
	snd_wr.id   = (unsigned long)wr;
	snd_wr.type = DET_WR_SEND;

	rcv_wr.id   = (unsigned long)wr;
	rcv_wr.type = DET_WR_RECV;

	while (wr->bcast.mask < co->size) {
#else
	/* Ceiling division. */
	scatter_size = (wr->bcast.ds.length + co->size - 1) / co->size;

	snd_ds.l_key = wr->bcast.ds.l_key;
	rcv_ds.l_key = wr->bcast.ds.l_key;

	if (wr->bcast.mask < co->size) {
#endif
		relative_dst = wr->bcast.relative_rank ^ wr->bcast.mask;
		dst = (relative_dst + wr->bcast.root) % co->size; 

#ifdef	DET_TRIGGERED_WR
		/*
		 * Post work requests using the temporary data segment array
		 * built in det_bcast_allgather for recursive doubling, since
		 * some ranks may not have any data.
		 */

		if (wr->bcast.i) {
			/*
			 * Post the previous send/receive.
			 * Must do this before clobbering the snd_wr or rcv_wr.
			 */
			err = det_post_twr(&snd_wr,
					   (wr->bcast.i == 1) ? 0 :
						(wr->bcast.i == 2) ? 1 : 2,
					   (wr->bcast.i > 1) ?
						co->qp_array[dst] : NULL);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_bcast_doubling: det_post_twr snd error %d\n",
					err);
				return err;
			}

			err = det_post_twr(&rcv_wr, 0, co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_bcast_doubling: det_post_twr rcv error %d\n",
					err);
				return err;
			}
		}
#endif
		/*
		 * Find offset into send and recv buffers.  Clear 
		 * the least significant "i" bits of relative_rank
		 * and dst to find root of src and dst subtrees.
		 * This becomes the index into the buffers.
		 */

		i = wr->bcast.relative_rank >> wr->bcast.i;
		i <<= wr->bcast.i;

		j = relative_dst >> wr->bcast.i;
		j <<= wr->bcast.i;

#ifdef	DET_TRIGGERED_WR
		snd_wr.qp	= co->qp_array[dst];
		snd_wr.ds_array = &((struct det_local_ds *)co->tmp)[i];
		snd_wr.num_ds   = wr->bcast.mask;

		rcv_wr.qp	= co->qp_array[dst];
		rcv_wr.ds_array = &((struct det_local_ds *)co->tmp)[j];
		rcv_wr.num_ds   = wr->bcast.mask;
#else
		snd_ds.length = wr->bcast.nbytes;
		snd_ds.vaddr  = wr->bcast.ds.vaddr + scatter_size * i;

		rcv_ds.length = scatter_size * wr->bcast.mask;
		rcv_ds.vaddr  = wr->bcast.ds.vaddr + scatter_size * j;
#endif
		/* Prepare for next pass. */
		wr->bcast.i++;
		wr->bcast.mask <<= 1;

#ifndef	DET_TRIGGERED_WR
		/*
		 * Post one at a time to ensure that data from previous
		 * round is received before being sent in the next round.
		 */
		err = det_co_sendrecv(co, (unsigned long)wr, dst, dst, 1,
			&snd_ds, 1, &rcv_ds, det_bcast_doubling_cb);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_doubling: det_co_sendrecv error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_doubling: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}
#else
	}

	err = det_post_twr(&snd_wr,
			   (wr->bcast.i == 1) ? 0 :
				(wr->bcast.i == 2) ? 1 : 2, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_bcast_doubling: final det_post_twr snd error %d\n",
			err);
		return err;
	}

	err = det_post_twr(&rcv_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_bcast_doubling: final det_post_twr rcv error %d\n",
			err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      wr->bcast.i + 1);
	if (unlikely(err)) {
		printk(KERN_INFO "det_bcast_doubling: det_next_action error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_bcast_doubling_cb(struct det_co * const co)
{
	struct det_wc wc[2];
	struct det_wr *wr = NULL;
	u32 num_wc;
	int i, err;

	num_wc = 2;
	err = det_poll_cq(&co->cq, &num_wc, wc);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_doubling_cb: rank %d poll cq error %d\n",
			co->rank, err);
		return err;
	}

	if (num_wc != 2) {
		printk(KERN_INFO
			"det_bcast_doubling_cb: rank %d expected 2 got %d\n",
			co->rank, num_wc);
		return -EIO;
	}

	for (i = 0; i < num_wc; i++) {
		if (wc[i].status != DET_WS_SUCCESS) {
			printk(KERN_INFO
				"det_bcast_doubling_cb: rank %d wc[%d].status %d\n",
				co->rank, i, wc[i].status);
			return -EIO;
		}

		/* Include data just received in the next transfer. */
		if (wc[i].type == DET_WC_RECV) {
			wr = (struct det_wr *)(unsigned long)wc[i].id;
			wr->bcast.nbytes += wc[i].length;
		}
	}

	err = det_bcast_doubling(co, wr);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_doubling_cb: det_bcast_doubling error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


static int det_bcast_ring(struct det_co * const co,
			  struct det_wr * const wr)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig_wr;
#endif
	struct det_local_ds snd_ds, rcv_ds;
	int *rcvcnts, *displs, left, right, i, j, jnext, err;

	/*
	Ring Algorithm:
	In the ring algorithm, the data from each process is
	sent around a virtual ring of processes.  In the first
	step, each process i sends its contribution to process
	i + 1 and receives the contribution from process i - 1
	(with wrap-around).  From the second step onward each
	process i forwards to process i + 1 the data it received
	from process i - 1 in the previous step.  If p is the
	number of processes, the entire algorithm takes p - 1
	steps.  If n is the total amount of data to be gathered
	on each process, then at every step each process sends
	and receives n/p amount of data.
	*/
	rcvcnts = co->tmp;
	displs  = &rcvcnts[co->size];

	left  = (co->size + co->rank - 1) % co->size;
	right = (co->rank + 1) % co->size;

#ifdef	DET_TRIGGERED_WR
	/* Setup static trig_wr fields for posting receives. */
	trig_wr.id	 = (unsigned long)wr;
	trig_wr.qp	 = co->qp_array[left];
	trig_wr.ds_array = &rcv_ds;
	trig_wr.num_ds   = 1;
	trig_wr.type     = DET_WR_RECV;

	while (wr->bcast.i < co->size) {
#else
	if (wr->bcast.i < co->size) {
#endif
		j = wr->bcast.j;
		jnext = wr->bcast.mask;

		/* Build the send data segment. */
		i = (j - wr->bcast.root + co->size) % co->size;
		snd_ds.l_key  = wr->bcast.ds.l_key;
		snd_ds.length =	rcvcnts[i];
		snd_ds.vaddr  = wr->bcast.ds.vaddr + displs[i];

#ifdef	DET_TRIGGERED_WR
		if (wr->bcast.i > 1) {
			/*
			 * Post the previous work request.  Must do this
			 * before clobbering the receive data segment.
			 */
			err = det_post_twr(&trig_wr, 0, co->qp_array[right]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_bcast_ring: det_post_twr error %d\n",
					err);
				return err;
			}
		}

		err = det_trig_send(co->qp_array[right], (unsigned long)wr,
				    &snd_ds, 1, (wr->bcast.i > 1) ? 1 : 0,
				    NULL);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_ring: det_trig_send error %d\n",
				err);
			return err;
		}
#endif
		/* Build the receive data segment. */
		i = (jnext - wr->bcast.root + co->size) % co->size;
		rcv_ds.l_key  = wr->bcast.ds.l_key;
		rcv_ds.length =	rcvcnts[i];
		rcv_ds.vaddr  = wr->bcast.ds.vaddr + displs[i];

		/* Prepare for next pass. */
		wr->bcast.mask = (co->size + jnext - 1) % co->size;
		wr->bcast.j    = jnext;
		wr->bcast.i++;

#ifndef	DET_TRIGGERED_WR
		err = det_co_sendrecv(co, (unsigned long)wr, right, left, 1,
				      &snd_ds, 1, &rcv_ds, det_bcast_ring_cb);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_ring: det_co_sendrecv error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_ring: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}
#else
	}

	err = det_post_twr(&trig_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_bcast_ring: final det_post_twr error %d\n",
			err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      wr->bcast.i);
	if (unlikely(err)) {
		printk(KERN_INFO "det_bcast_ring: det_next_action error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_bcast_ring_cb(struct det_co * const co)
{
	u64 id;
	int err;

	err = det_co_sendrecv_cb(co, &id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_ring_cb: det_complete_co_wr error %d\n",
			err);
		return err;
	}

	err = det_bcast_ring(co, (struct det_wr *)(unsigned long)id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_ring_cb: det_bcast_ring error %d\n", err);
		return err;
	}

	return 0;
}
#endif


static int det_bcast_allgather(struct det_co * const co,
			       struct det_wr * const wr)
{
	int *rcvcnts, *displs, i, scatter_size, err;

	/* Ceiling division. */
	scatter_size = (wr->bcast.ds.length + co->size - 1) / co->size;

	if ((wr->bcast.ds.length < BCAST_LONG_MSG) && is_pof2(co->size)) {
#ifdef	DET_TRIGGERED_WR
		int rem;

		/* Allocate a tmp buffer for data segments. */
		err = det_co_alloc_tmp(co, sizeof(wr->bcast.ds) * co->size);
		if (unlikely(err))
			return err;

		/* Build the data segment array. */
		rem = wr->bcast.ds.length;
		for (i = 0; i < co->size; i++) {
			((struct det_local_ds *)co->tmp)[i].l_key = wr->bcast.ds.l_key;
			((struct det_local_ds *)co->tmp)[i].vaddr = wr->bcast.ds.vaddr +
				scatter_size * i;
			if (rem >= scatter_size) {
				((struct det_local_ds *)co->tmp)[i].length = scatter_size;
				rem -= scatter_size;
			} else {
				if (!rem)
					((struct det_local_ds *)co->tmp)[i].vaddr = wr->bcast.ds.vaddr;
				((struct det_local_ds *)co->tmp)[i].length = rem;
				rem = 0;
			}
		}
#endif
		/*
		 * Medium-size and power-of-two.  Use recursive doubling. 
		 */
		wr->bcast.i    = 0;
		wr->bcast.mask = 1;
		err = det_bcast_doubling(co, wr);

	} else {
		/*
		 * Long message or medium-size message and non-power-of-two
		 * number of processes.  Use ring algorithm.
		 */

		err = det_co_alloc_tmp(co, sizeof(int) * co->size * 2);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_allgather: det_co_alloc_mr error %d\n",
				err);
			return err;
		}
		rcvcnts = co->tmp;
		displs  = &rcvcnts[co->size];

		for (i = 0; i < co->size; i++) {
			rcvcnts[i] = wr->bcast.ds.length - i * scatter_size;
			if (rcvcnts[i] > scatter_size)
				rcvcnts[i] = scatter_size;
			if (rcvcnts[i] < 0)
				rcvcnts[i] = 0;
		}

		displs[0] = 0;
		for (i = 1; i < co->size; i++)
			displs[i] = displs[i - 1] + rcvcnts[i - 1];

		wr->bcast.i    = 1;
		wr->bcast.j    = co->rank;
		wr->bcast.mask = (co->size + co->rank - 1) % co->size;
		err = det_bcast_ring(co, wr);
	}

	if (unlikely(err)) {
		printk(KERN_INFO "det_bcast_allgather: error %d\n", err);
		return err;
	}

	return 0;
}


#ifdef	DET_TRIGGERED_WR
static int det_bcast_scatter_send(struct det_co * const co,
				  struct det_wr * const wr,
				  struct det_twr *twr)
#else
static int det_bcast_scatter_send(struct det_co * const co,
				  struct det_wr * const wr)
#endif
{
	struct det_local_ds snd_ds;
	int scatter_size, dst, len, err;
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig_wr;
	int recv, nr_sends = 0;

	recv = (twr) ? 1 : 0;
#endif
	snd_ds.l_key  = wr->bcast.ds.l_key;

	/* Ceiling division. */
	scatter_size = (wr->bcast.ds.length + co->size - 1) / co->size;

	/*
	 * This process is responsible for all processes that have bits
	 * set from the LSB upto (but not including) mask.  Because of
	 * the "not including", we start by shifting mask back down one.
	 */
	wr->bcast.mask >>= 1;
	while (wr->bcast.mask > 0) {

		if (wr->bcast.relative_rank + wr->bcast.mask >= co->size) {
			wr->bcast.mask >>= 1;
			continue;
		}

		len = wr->bcast.nbytes - scatter_size * wr->bcast.mask;

		if (len <= 0) {
			wr->bcast.mask >>= 1;
			continue;
		}

		wr->bcast.nbytes -= len;

		dst = co->rank + wr->bcast.mask;
		if (dst >= co->size)
			dst -= co->size;

#ifdef	DET_TRIGGERED_WR
		if (twr) {
			/*
			 * Post the previous work request.  Must do this
			 * before clobbering the send data segment.
			 */
			err = det_post_twr(twr, ((nr_sends > 1) ||
						 (recv && nr_sends)) ? 1 : 0,
					   co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_bcast_scatter_send: det_post_twr error %d\n",
					err);
				return err;
			}
		} else
			twr = &trig_wr;

		/* Set up the next work request. */
		twr->id	      = (unsigned long)wr;
		twr->qp	      = co->qp_array[dst];
		twr->ds_array = &snd_ds;
		twr->num_ds   = 1;
		twr->type     = DET_WR_SEND;
#endif
		snd_ds.length = len;
		snd_ds.vaddr  = wr->bcast.ds.vaddr + scatter_size *
			       (wr->bcast.relative_rank + wr->bcast.mask);
#ifdef	DET_TRIGGERED_WR
		nr_sends++;
		wr->bcast.mask >>= 1;
#else
		err = det_send(co->qp_array[dst], (unsigned long)wr,
			       &snd_ds, 1, 0, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_scatter_send: det_send error %d\n",
				err);
			return err;
		}

		/*
		 * Note: we only initiate one send at a time to
		 * ensure parallelism across all ranks.  Posting
		 * more than one could serialize data transfer out
		 * the port and defeat the purpose of the algorithm.
		 */
		err = det_next_action(co, det_bcast_scatter_cb,
				      DET_CQ_THRESHOLD, 1);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_scatter_send: det_next_action error %d\n",
				err);
			return err;
		}

		return 0;
#endif
	}

#ifdef	DET_TRIGGERED_WR
	err = det_post_twr(twr, ((nr_sends > 1) ||
				 (recv && nr_sends)) ? 1 : 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_scatter_send: det_post_twr error %d\n", err);
		return err;
	}

	err = det_next_action(co, det_bcast_scatter_cb,
			      DET_CQ_THRESHOLD, (nr_sends) ? nr_sends : 1);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_scatter_send: det_next_action error %d\n",
			err);
		return err;
	}
#else
	err = det_bcast_allgather(co, wr);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_scatter_send: det_bcast_allgather error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


static int __det_bcast_scatter_cb(struct det_co * const co)
{
	struct det_wc wc;
	u32 num_wc;
	int i, err;

	for (i = 0; i < co->cq.attr.threshold; i++) {
		num_wc = 1;
		err = det_poll_cq(&co->cq, &num_wc, &wc);
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_bcast_scatter_cb: rank %d poll cq error %d\n",
				co->rank, err);
			return err;
		}

		if (unlikely(wc.status != DET_WS_SUCCESS)) {
			printk(KERN_INFO
				"__det_bcast_scatter_cb: rank %d wc.status %d\n",
				co->rank, wc.status);
			return -EIO;
		}
	}

#ifdef	DET_TRIGGERED_WR
	err = det_bcast_allgather(co, (struct det_wr *)(unsigned long)wc.id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"__det_bcast_scatter_cb: det_bcast_allgather error %d\n",
			err);
		return err;
	}
#else
	err = det_bcast_scatter_send(co, (struct det_wr *)(unsigned long)wc.id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"__det_bcast_scatter_cb: det_bcast_scatter_send error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


static int det_bcast_scatter_cb(struct det_co * const co)
{
#ifdef	DET_TRIGGERED_WR
	/*
	 * If the collective membership includes loopback QPs, schedule
	 * a tasklet between the bcast scatter and allgather algorithms.
	 * This is needed for loopback QPs when triggered work requests
	 * are used to prevent lock recursion; non-loopback QPs do not
	 * require a tasklet because the receive path is not executed
	 * by the sending thread.
	 */
	if (co->qp.loopback) {
		co->next = __det_bcast_scatter_cb;
		det_co_sched_task(co);
		return 0;
	} else
#endif
		return __det_bcast_scatter_cb(co);
}


static int det_bcast_scatter(struct det_co * const co,
			     struct det_wr * const wr,
			     const int root,
			     const struct det_local_ds * const ds)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig, *twr = NULL;
#endif
	struct det_local_ds rcv_ds;
	int scatter_size, src, err;

	wr->bcast.root		= root;
	wr->bcast.mask		= 1;
	wr->bcast.ds		= *ds;
	wr->bcast.nbytes	= (co->rank == root) ? ds->length : 0;
	wr->bcast.relative_rank = relative_rank(co->rank, root, co->size);

	/* Ceiling division. */
	scatter_size = (ds->length + co->size - 1) / co->size;

	while (wr->bcast.mask < co->size) {
		if (!(wr->bcast.relative_rank & wr->bcast.mask)) {
			wr->bcast.mask <<= 1;
			continue;
		}

		src = co->rank - wr->bcast.mask; 
		if (src < 0)
			src += co->size;

		/*
		 * This process may not receive data due to uneven division.
		 */
		rcv_ds.length = ds->length -
				wr->bcast.relative_rank * scatter_size;
		if (rcv_ds.length <= 0)
			goto do_allgather;

		rcv_ds.l_key = ds->l_key;
		rcv_ds.vaddr = ds->vaddr +
			       scatter_size * wr->bcast.relative_rank;

		wr->bcast.nbytes = scatter_size *
				rel_subtree(wr->bcast.relative_rank, co->size);

		if (rcv_ds.length > wr->bcast.nbytes)
			rcv_ds.length = wr->bcast.nbytes;
		else
			wr->bcast.nbytes = rcv_ds.length;

#ifdef	DET_TRIGGERED_WR
		twr = &trig;
		twr->id       = (unsigned long)wr;
		twr->qp       = co->qp_array[src];
		twr->ds_array = &rcv_ds;
		twr->num_ds   = 1;
		twr->type     = DET_WR_RECV;

		break;
#else
		err = det_recv(co->qp_array[src], (unsigned long)wr, &rcv_ds, 1);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_scatter: det_recv error %d\n", err);
			return err;
		}

		err = det_next_action(co, det_bcast_scatter_cb,
				      DET_CQ_THRESHOLD, 1);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_bcast_scatter: det_next_action error %d\n",
				err);
			return err;
		}

		goto done;
#endif
	}

#ifdef	DET_TRIGGERED_WR
	err = det_bcast_scatter_send(co, wr, twr);
#else
	err = det_bcast_scatter_send(co, wr);
#endif
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_scatter: det_bcast_scatter_send error %d\n",
			err);
		return err;
	}

	return 0;

do_allgather:
	err = det_bcast_allgather(co, wr);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_bcast_scatter_send: det_bcast_allgather error %d\n",
			err);
		return err;
	}
#ifndef	DET_TRIGGERED_WR
done:
#endif
	return 0;
}


int __det_bcast(struct det_co * const co,
		struct det_wr * const wr,
		const int root,
		const struct det_local_ds * const ds)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig, *twr = NULL;
#endif
	int src, err;

	if ((ds->length < BCAST_SHORT_MSG) || (co->size < BCAST_MIN_PROCS)) {
		/*
		 *  Use short message algorithm, namely, binomial tree
		 */
		wr->bcast.mask		= 1;
		wr->bcast.ds		= *ds;
		wr->bcast.relative_rank = relative_rank(co->rank, root,
							co->size);

		while (wr->bcast.mask < co->size) {
			if (!(wr->bcast.relative_rank & wr->bcast.mask)) {
				wr->bcast.mask <<= 1;
				continue;
			}

			src = co->rank - wr->bcast.mask; 
			if (src < 0)
				src += co->size;

#ifdef	DET_TRIGGERED_WR
			twr = &trig;
			twr->id       = (unsigned long)wr;
			twr->qp       = co->qp_array[src];
			twr->ds_array = ds;
			twr->num_ds   = 1;
			twr->type     = DET_WR_RECV;

			break;
#else
			err = det_recv(co->qp_array[src], (unsigned long)wr,
				       ds, 1);
			if (unlikely(err)) {
				printk(KERN_INFO
					"__det_bcast: det_recv error %d\n", err);
				return err;
			}

			err = det_next_action(co, det_bcast_cb,
					      DET_CQ_THRESHOLD, 1);
			if (unlikely(err)) {
				printk(KERN_INFO
					"__det_bcast: det_next_action error %d\n",
					err);
				return err;
			}

			goto done;
#endif
		}

#ifdef	DET_TRIGGERED_WR
		err = det_bcast_send(co, wr, twr);
#else
		err = det_bcast_send(co, wr);
#endif
		if (unlikely(err)) {
			printk(KERN_INFO "__det_bcast: det_bcast_send error %d\n",
				err);
			return err;
		}
	} else {
		/*
		 * Use long message algorithm, a binomial tree scatter
		 * followed by an allgather.
		 *
		 * The scatter algorithm divides the buffer into nprocs
		 * pieces and scatters them among the processes.  Root
		 * gets the first piece, root+1 gets the second piece,
		 * and so forth.  Uses the same binomial tree algorithm
		 * as above.  Ceiling division is used to compute the
		 * size of each piece.  This means some processes may
		 * not get any data.  For example if bufsize = 97 and
		 * nprocs = 16, ranks 15 and 16 will get 0 data. On each
		 * process, the scattered data is stored at the same
		 * offset in the buffer as it is on the root process.
		 */
		err = det_bcast_scatter(co, wr, root, ds);
		if (unlikely(err)) {
			printk(KERN_INFO "__det_bcast: det_bcast_scatter error %d\n",
				err);
			return err;
		}
	}
#ifndef	DET_TRIGGERED_WR
done:
#endif
	return 0;
}


/*
 *  Refer to the MPICH MPI_Bcast code for the algorithm.
 */
int det_bcast(struct det_co * const co,
	      const __u64 id,
	      const int root,
	      const struct det_local_ds * const ds,
	      const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int err;

	if (unlikely((root < 0) || (root >= co->size)))
		return -EINVAL;

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_BCAST;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = ds->length;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	err = __det_bcast(co, wr, root, ds);
	if (unlikely(err)) {
		printk(KERN_INFO "det_bcast: __det_bcast error %d\n", err);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(det_bcast);


static int det_local_copy(struct det_co * const co,
			  const struct det_local_ds * const src_ds,
			  const struct det_local_ds * const dst_ds)
{
	struct det_ds src, dst;
	int total_length, err;

	if (!src_ds || !src_ds->length || !dst_ds || !dst_ds->length)
		return 0;

	total_length = det_validate_ds(co->qp.attr.pd, dst_ds, &dst,
				       1, DET_AC_LOCAL_WRITE, 1);
	if (unlikely(total_length < 0)) {
		printk(KERN_INFO
			"det_local_copy: dst_ds det_validate_ds error %d\n",
			total_length);
		return total_length;
	}

	total_length = det_validate_ds(co->qp.attr.pd, src_ds, &src,
				       1, DET_AC_LOCAL_READ, 1);
	if (unlikely(total_length < 0)) {
		printk(KERN_INFO
			"det_local_copy: src_ds det_validate_ds error %d\n",
			total_length);
		det_clear_ds_ref(&dst);
		return total_length;
	}

	err = det_copy_data(&dst, &src, src_ds->length);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_local_copy: det_copy_data error %d\n", err);
		return err;
	}

	det_clear_ds_ref(&dst);
	det_clear_ds_ref(&src);

	return 0;
}


#ifdef	DET_TRIGGERED_WR
static int det_scatter_send(struct det_co * const co,
			    struct det_wr * const wr,
			    struct det_twr *twr)
#else
static int det_scatter_send(struct det_co * const co,
			    struct det_wr * const wr)
#endif
{
	struct det_local_ds ds[2];
	int dst, n, num_ds, err;
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig_wr;
	int recv, nr_sends = 0;

	recv = (twr) ? 1 : 0;
#endif
	/*
	 * This process is responsible for all processes that have bits
	 * set from the LSB upto (but not including) mask.  Because of
	 * the "not including", we start by shifting mask back down one.
	 */
	wr->scatter.mask >>= 1;
	while (wr->scatter.mask > 0) {

		if (wr->scatter.relative_rank + wr->scatter.mask >= co->size) {
			wr->scatter.mask >>= 1;
			continue;
		}

		dst = co->rank + wr->scatter.mask;
		if (dst >= co->size)
			dst -= co->size;

#ifdef	DET_TRIGGERED_WR
		if (twr) {
			/*
			 * Post the previous work request.  Must do this
			 * before clobbering the data segment.
			 */
			err = det_post_twr(twr, ((nr_sends > 1) ||
						 (recv && nr_sends)) ? 1 : 0,
					   co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_scatter_send: det_post_twr error %d\n",
					err);
				return err;
			}
		} else
			twr = &trig_wr;

		/* Set up the next work request. */
		twr->id	      = (unsigned long)wr;
		twr->qp	      = co->qp_array[dst];
		twr->ds_array = ds;
		twr->type     = DET_WR_SEND;
#endif
		n = subtree(dst, wr->gather.root, co->size);

		/*
		 * If the root is not rank 0, we reorder the data in
		 * order of relative ranks so that all the sends from
		 * the root are contiguous and in the right order.
		 */
		ds[0].l_key = wr->scatter.src_ds.l_key;
		if ((co->rank == wr->scatter.root) && (wr->scatter.root != 0)) {

			ds[0].vaddr = wr->scatter.src_ds.vaddr +
				      wr->scatter.nbytes * dst;
			/*
			 * Determine if the transfer length wraps the buffer.
			 */
			if (n > (co->size - dst)) {
				ds[0].length = wr->scatter.nbytes *
					       (co->size - dst);
				ds[1].l_key  = wr->scatter.src_ds.l_key;
				ds[1].vaddr  = wr->scatter.src_ds.vaddr;
				ds[1].length = wr->scatter.nbytes *
					       (n - (co->size - dst));
				num_ds = 2;
			} else {
				ds[0].length = wr->scatter.nbytes * n;
				num_ds = 1;
			}
		} else {
			if (co->rank != wr->scatter.root)
				ds[0].vaddr = wr->scatter.src_ds.vaddr +
				      wr->scatter.nbytes *
				     (wr->scatter.mask - 1);
			else
				ds[0].vaddr = wr->scatter.src_ds.vaddr +
				       wr->scatter.nbytes * wr->scatter.mask;
			ds[0].length = wr->scatter.nbytes * n;
			num_ds = 1;
		}

#ifdef	DET_TRIGGERED_WR
		twr->num_ds = num_ds;
		nr_sends++;
		wr->scatter.mask >>= 1;
#else
		err = det_send(co->qp_array[dst], (unsigned long)wr,
			       ds, num_ds, 0, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_scatter_send: det_send error %d\n", err);
			return err;
		}

		/*
		 * Note: we only initiate one send at a time to
		 * ensure parallelism across all ranks.  Posting
		 * more than one could serialize data transfer out
		 * the port and defeat the purpose of the algorithm.
		 */
		err = det_next_action(co, det_scatter_cb, DET_CQ_THRESHOLD, 1);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_scatter_send: det_next_action error %d\n", err);
			return err;
		}

		return 0;
#endif
	}

#ifdef	DET_TRIGGERED_WR
	err = det_post_twr(twr, ((nr_sends > 1) ||
				 (recv && nr_sends)) ? 1 : 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_scatter_send: det_post_twr error %d\n", err);
		return err;
	}
#endif
	/* Copy local data on the root node if needed. */
	if ((co->rank == wr->scatter.root) && wr->scatter.dst_ds.length) {

		wr->scatter.src_ds.vaddr += co->rank * wr->scatter.nbytes;
		wr->scatter.src_ds.length = wr->scatter.nbytes;

		err = det_local_copy(co, &wr->scatter.src_ds,
					 &wr->scatter.dst_ds);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_scatter_send: det_local_copy error %d\n",
				err);
			return err;
		}
	}

#ifdef	DET_TRIGGERED_WR
	err = det_next_action(co, det_co_pollcomplete_cb,
			      DET_CQ_THRESHOLD, (nr_sends) ? nr_sends : 1);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_scatter_send: det_next_action error %d\n",
			err);
		return err;
	}
#else
	err = det_complete_co_wr(co, DET_WS_SUCCESS);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_scatter_send: det_complete_co_wr error %d\n", err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_scatter_cb(struct det_co * const co)
{
	struct det_wc wc;
	u32 num_wc;
	int err;

	num_wc = 1;
	err = det_poll_cq(&co->cq, &num_wc, &wc);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_scatter_cb: rank %d poll cq error %d\n",
			co->rank, err);
		return err;
	}

	if (unlikely(wc.status != DET_WS_SUCCESS)) {
		printk(KERN_INFO
			"det_scatter_cb: rank %d wc.status %d\n",
			co->rank, wc.status);
		return -EIO;
	}

	err = det_scatter_send(co, (struct det_wr *)(unsigned long)wc.id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_scatter_cb: det_scatter_send error %d\n", err);
		return err;
	}

	return 0;
}
#endif


static int __det_scatter(struct det_co * const co,
			 struct det_wr * const wr,
			 const int root,
			 const struct det_local_ds * const src_ds,
			 const struct det_local_ds * const dst_ds)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig, *twr = NULL;
#endif
	struct det_local_ds ds[2], *rcv_ds;
	int src, n, num_ds, err;

	wr->scatter.mask	  = 1;
	wr->scatter.root	  = root;
	wr->scatter.relative_rank = relative_rank(co->rank, root, co->size);
	wr->scatter.nbytes	  = (co->rank == root) ?
				    src_ds->length / co->size : dst_ds->length;
	if (src_ds)
		wr->scatter.src_ds = *src_ds;
	if (dst_ds)
		wr->scatter.dst_ds = *dst_ds;
	else
		wr->scatter.dst_ds.length = 0;

	/* Root has all the data; others have zero so far. */

	while (wr->scatter.mask < co->size) {
		if (!(wr->scatter.relative_rank & wr->scatter.mask)) {
			wr->scatter.mask <<= 1;
			continue;
		}

		src = co->rank - wr->scatter.mask; 
		if (src < 0)
			src += co->size;

		/*
		 * Even nodes other than root may need a temporary buffer to
		 * receive data for sub-ranks.  The temporary buffer becomes
		 * the src_ds for forwarding data. Local data and leaf nodes
		 * receive directly into the dst_ds.
		 */
		if ((n = rel_subranks(wr->scatter.relative_rank, co->size))) {

			wr->scatter.src_ds.length = wr->scatter.nbytes * n;

			err = det_co_alloc_mr(co, wr->scatter.src_ds.length, 0);
			if (unlikely(err))
				return err;

			wr->scatter.src_ds.vaddr = 0;
			wr->scatter.src_ds.l_key = co->mr->attr.l_key;

			/* Local data */
			ds[0] = *dst_ds;

			/* Forwarded data */
			ds[1] = wr->scatter.src_ds;

			num_ds = 2;
			rcv_ds = ds;
		} else {
			num_ds = 1;
			rcv_ds = (struct det_local_ds *)dst_ds;
		}

#ifdef	DET_TRIGGERED_WR
		twr = &trig;
		twr->id       = (unsigned long)wr;
		twr->qp       = co->qp_array[src];
		twr->ds_array = rcv_ds;
		twr->num_ds   = num_ds;
		twr->type     = DET_WR_RECV;

		break;
#else
		err = det_recv(co->qp_array[src], (unsigned long)wr, rcv_ds,
			       num_ds);
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_scatter: det_recv error %d\n", err);
			return err;
		}

		err = det_next_action(co, det_scatter_cb, DET_CQ_THRESHOLD, 1);
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_scatter: det_next_action error %d\n",
				err);
			return err;
		}

		goto done;
#endif
	}

#ifdef	DET_TRIGGERED_WR
	err = det_scatter_send(co, wr, twr);
#else
	err = det_scatter_send(co, wr);
#endif
	if (unlikely(err)) {
		printk(KERN_INFO
			"__det_scatter: det_scatter_send error %d\n", err);
		return err;
	}
#ifndef	DET_TRIGGERED_WR
done:
#endif
	return 0;
}


/*
 *  Refer to the MPICH MPI_Scatter code for the algorithm.
 */
int det_scatter(struct det_co * const co,
		const __u64 id,
		const int root,
		const struct det_local_ds * const src_ds,
		const struct det_local_ds * const dst_ds,
		const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int err;

	if (unlikely((root < 0) || (root >= co->size)))
		return -EINVAL;

	if (co->rank == root) {
		if (unlikely( !src_ds ||
			      (src_ds->length && (src_ds->length % co->size))))
			return -EINVAL;
		if (dst_ds && (dst_ds->length != (src_ds->length / co->size)))
			return -EINVAL;
	} else {
		if (unlikely(!dst_ds))
			return -EINVAL;
	}

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_SCATTER;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = (dst_ds) ? dst_ds->length : 0;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	err = __det_scatter(co, wr, root, src_ds, dst_ds);
	if (unlikely(err)) {
		printk(KERN_INFO "det_scatter: __det_scatter error %d\n", err);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(det_scatter);


/*
 *  Refer to the MPICH MPI_Scatterv code for the algorithm.
 */
int det_scatterv(struct det_co * const co,
		 const __u64 id,
		 const int root,
		 const struct det_local_ds * const src_ds_array,
		 const struct det_local_ds * const dst_ds,
		 const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int i, count, err;

	if (unlikely((root < 0) || (root >= co->size)))
		return -EINVAL;

	if (co->rank == root) {
		if (unlikely(!src_ds_array))
			return -EINVAL;
		if (dst_ds && (dst_ds->length != src_ds_array[co->rank].length))
			return -EINVAL;
	} else {
		if (unlikely(!dst_ds))
			return -EINVAL;
	}

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_SCATTERV;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = (dst_ds) ? dst_ds->length : 0;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	count = 0;
	if (co->rank == root) {
		if (dst_ds && dst_ds->length) {
			err = det_local_copy(co, &src_ds_array[root], dst_ds);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_scatterv: det_local_copy error %d\n",
					err);
				return err;
			}
		}

		for (i = 0; i < co->size; i++) {
			if ((i == root) || !src_ds_array[i].length)
				continue;

			err = det_send(co->qp_array[i], 0, &src_ds_array[i],
				       1, 0, 0);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_scatterv: det_send error %d\n",
					err);
				return err;
			}
			count++;
		}
	} else if (dst_ds->length) {

		err = det_recv(co->qp_array[root], 0, dst_ds, 1);
		if (unlikely(err)) {
			printk(KERN_INFO "det_scatterv: det_recv error %d\n",
				err);
			return err;
		}
		count++;
	}

	if (count) {
		err = det_next_action(co, det_co_pollcomplete_cb,
				      DET_CQ_THRESHOLD, count);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_scatterv: det_next_action error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_scatterv: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}

	return 0;
}
EXPORT_SYMBOL(det_scatterv);


#ifdef	DET_TRIGGERED_WR
static int det_gather_send(struct det_co * const co,
			   struct det_wr * const wr,
			   int nrecvs)
#else
static int det_gather_send(struct det_co * const co,
			   struct det_wr * const wr)
#endif
{
	struct det_local_ds ds[2], *snd_ds;
	int dst, num_ds, err;

	for (wr->gather.mask = 1;
	     wr->gather.mask < co->size;
	     wr->gather.mask <<= 1) {
		if (!(wr->gather.relative_rank & wr->gather.mask))
			continue;

		dst = wr->gather.relative_rank ^ wr->gather.mask;
		dst = (dst + wr->gather.root) % co->size;

		if ((wr->gather.relative_rank % 2) ||
		    (wr->gather.dst_ds.length == 0)) {
			/* Leaf nodes send directly from the source buffer. */
			snd_ds = &wr->gather.src_ds;
			num_ds = 1;
		} else {
			ds[0] = wr->gather.src_ds;

			ds[1].l_key  = wr->gather.dst_ds.l_key;
			ds[1].length = wr->gather.nbytes *
				       rel_subranks(wr->gather.relative_rank,
						    co->size);
			ds[1].vaddr  = wr->gather.dst_ds.vaddr;

			snd_ds = ds;
			num_ds = 2;
		}

#ifdef	DET_TRIGGERED_WR
		err = det_trig_send(co->qp_array[dst], (unsigned long)wr,
				    snd_ds, num_ds, nrecvs, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_gather_send: det_trig_send error %d\n",
				err);
			return err;
		}
#else
		err = det_send(co->qp_array[dst], (unsigned long)wr,
			       snd_ds, num_ds, 0, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_gather_send: det_send error %d\n", err);
			return err;
		}
#endif

		err = det_next_action(co, det_gather_cb, DET_CQ_THRESHOLD, 1);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_gather_send: det_next_action error %d\n",
				err);
			return err;
		}

		break;
	}

	return 0;
}


static int det_gather_cb(struct det_co * const co)
{
#ifndef	DET_TRIGGERED_WR
	struct det_wr *wr = NULL;
#endif
	struct det_wc wc;
	u32 num_wc;
	int i, err;

	for (i = 0; i < co->cq.attr.threshold; i++) {
		num_wc = 1;
		err = det_poll_cq(&co->cq, &num_wc, &wc);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_gather_cb: rank %d poll cq error %d\n",
				co->rank, err);
			return err;
		}

		if (unlikely(wc.status != DET_WS_SUCCESS)) {
			printk(KERN_INFO
				"det_gather_cb: rank %d wc.status %d\n",
				co->rank, wc.status);
			return -EIO;
		}
	}

#ifndef	DET_TRIGGERED_WR
	wr = (struct det_wr *)(unsigned long)wc.id;
	if ((wc.type == DET_WC_RECV) && (co->rank != wr->gather.root)) {
		err = det_gather_send(co, wr);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_gather_cb: det_gather_send error %d\n",
				err);
			return err;
		}
	} else {
#endif
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_gather_cb: det_complete_co_wr error %d\n",
				err);
			return err;
		}
#ifndef	DET_TRIGGERED_WR
	}
#endif
	return 0;
}


#ifdef	DET_TRIGGERED_WR
static int det_gather_recv(struct det_co * const co,
			   struct det_wr * const wr,
			   int src,
			   struct det_qp * const dst_qp)
#else
static int det_gather_recv(struct det_co * const co,
			   struct det_wr * const wr,
			   int src)
#endif
{
	struct det_local_ds ds[2];
	int n, num_ds, err;

	if ((wr->gather.dst_ds.length == 0) && wr->gather.relative_rank) {
		/*
		 * Even nodes other than root may need a temporary buffer to
		 * receive data from sub-ranks.  The temporary buffer becomes
		 * the dst_ds for forwarding data.  Local data and leaf nodes
		 * send directly from the src_ds.
		 */
		wr->gather.dst_ds.length = wr->gather.nbytes *
			rel_subranks(wr->gather.relative_rank, co->size);

		err = det_co_alloc_mr(co, wr->gather.dst_ds.length, 0);
		if (unlikely(err))
			return err;

		wr->gather.dst_ds.vaddr = 0;
		wr->gather.dst_ds.l_key = co->mr->attr.l_key;
	}

	n = subtree(src, wr->gather.root, co->size);

	/*
	 * If the root is not rank 0, we order the data so that
	 * data received at the root are in the right order.
	 */
	ds[0].l_key = wr->gather.dst_ds.l_key;
	if ((co->rank == wr->gather.root) && (wr->gather.root != 0)) {

		ds[0].vaddr = wr->gather.dst_ds.vaddr +
			      wr->gather.nbytes * src;
		/*
		 * Determine if the transfer length wraps the buffer.
		 */
		if (n > (co->size - src)) {
			ds[0].length = wr->gather.nbytes * (co->size - src);
			ds[1].l_key  = wr->gather.dst_ds.l_key;
			ds[1].vaddr  = wr->gather.dst_ds.vaddr;
			ds[1].length = wr->gather.nbytes *
				       (n - (co->size - src));
			num_ds = 2;
		} else {
			ds[0].length = wr->gather.nbytes * n;
			num_ds = 1;
		}
	} else {
		if (co->rank != wr->gather.root)
			ds[0].vaddr  = wr->gather.dst_ds.vaddr +
				       wr->gather.nbytes *
				      (wr->gather.mask - 1);
		else
			ds[0].vaddr = wr->gather.dst_ds.vaddr +
				      wr->gather.nbytes * wr->gather.mask;
		ds[0].length = wr->gather.nbytes * n;
		num_ds = 1;
	}

#ifdef	DET_TRIGGERED_WR
	err = det_trig_recv(co->qp_array[src], (unsigned long)wr, ds, num_ds,
			    dst_qp);
	if (unlikely(err)) {
		printk(KERN_INFO "det_gather_recv: det_trig_recv error %d\n",
			err);
		return err;
	}
#else
	err = det_recv(co->qp_array[src], (unsigned long)wr, ds, num_ds);
	if (unlikely(err)) {
		printk(KERN_INFO "det_gather_recv: det_recv error %d\n", err);
		return err;
	}
#endif
	return 0;
}


static int __det_gather(struct det_co * const co,
			struct det_wr * const wr,
			const int root,
			const struct det_local_ds * const src_ds,
			const struct det_local_ds * const dst_ds)
{
#ifdef	DET_TRIGGERED_WR
	struct det_qp *dst_qp = NULL;
#endif
	int src, nrecvs, err;

	wr->gather.mask		 = 1;
	wr->gather.root		 = root;
	wr->gather.relative_rank = relative_rank(co->rank, root, co->size);
	wr->gather.nbytes	 = (co->rank == root) ?
				   dst_ds->length / co->size : src_ds->length;
	if (dst_ds)
		wr->gather.dst_ds = *dst_ds;
	else
		wr->gather.dst_ds.length = 0;
	if (src_ds)
		wr->gather.src_ds = *src_ds;
	else
		wr->gather.src_ds.length = 0;

	/* Post receives as needed, working down from highest relative rank. */
	for (nrecvs = 0; wr->gather.mask < co->size; wr->gather.mask <<= 1) {
		if (!(wr->gather.relative_rank & wr->gather.mask))
			continue;
#ifdef	DET_TRIGGERED_WR
		/* Temporarily hi-jack src to determine destination QP. */
		src = wr->gather.relative_rank ^ wr->gather.mask;
		src = (src + wr->gather.root) % co->size;
		dst_qp = co->qp_array[src];
#endif
		break;
	}
	for (wr->gather.mask >>= 1; wr->gather.mask > 0; wr->gather.mask >>= 1) {

		if (wr->gather.relative_rank + wr->gather.mask >= co->size)
			continue;

		src = co->rank + wr->gather.mask;
		if (src >= co->size)
			src -= co->size;

#ifdef	DET_TRIGGERED_WR
		err = det_gather_recv(co, wr, src, dst_qp);
#else
		err = det_gather_recv(co, wr, src);
#endif
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_gather: det_gather_recv error %d\n",
				err);
			return err;
		}
		nrecvs++;
	}

	/* Copy local data on the root node if needed. */
	if ((co->rank == root) && wr->gather.src_ds.length) {

		wr->gather.dst_ds.vaddr += co->rank * wr->gather.nbytes;
		wr->gather.dst_ds.length = wr->gather.nbytes;
		err = det_local_copy(co, &wr->gather.src_ds,
					 &wr->gather.dst_ds);
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_gather: det_local_copy error %d\n", err);
			return err;
		}
	}

#ifdef	DET_TRIGGERED_WR
	if (co->rank == root) {
#else
	/* Wait for any receives before doing the send. */
	if (nrecvs) {
#endif
		err = det_next_action(co, det_gather_cb, DET_CQ_THRESHOLD,
				      nrecvs);
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_gather: det_next_action error %d\n",
				err);
			return err;
		}
	} else {
#ifdef	DET_TRIGGERED_WR
		err = det_gather_send(co, wr, nrecvs);
#else
		err = det_gather_send(co, wr);
#endif
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_gather: det_gather_send error %d\n",
				err);
			return err;
		}
	}

	return 0;
}


/*
 *  Refer to the MPICH MPI_Gather code for the algorithm.
 */
int det_gather(struct det_co * const co,
	       const __u64 id,
	       const int root,
	       const struct det_local_ds * const src_ds,
	       const struct det_local_ds * const dst_ds,
	       const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int err;

	if (unlikely((root < 0) || (root >= co->size)))
		return -EINVAL;

	if (co->rank == root) {
		if (unlikely( !dst_ds ||
			      (dst_ds->length && (dst_ds->length % co->size))))
			return -EINVAL;
		if (src_ds && (src_ds->length != (dst_ds->length / co->size)))
			return -EINVAL;
	} else {
		if (unlikely(!src_ds))
			return -EINVAL;
	}

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_GATHER;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = (src_ds) ? src_ds->length : 0;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	err = __det_gather(co, wr, root, src_ds, dst_ds);
	if (unlikely(err)) {
		printk(KERN_INFO "det_gather: __det_gather error %d\n", err);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(det_gather);


/*
 *  Refer to the MPICH MPI_Gatherv code for the algorithm.
 */
int det_gatherv(struct det_co * const co,
		const __u64 id,
		const int root,
		const struct det_local_ds * const src_ds,
		const struct det_local_ds * const dst_ds_array,
		const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int i, count, err;

	if (unlikely((root < 0) || (root >= co->size)))
		return -EINVAL;

	count = 0;
	if (co->rank == root) {
		if (unlikely(!dst_ds_array))
			return -EINVAL;
		if (src_ds && (src_ds->length != dst_ds_array[co->rank].length))
			return -EINVAL;

		for (i = 0; i < co->size; i++)
			count += dst_ds_array[i].length;
	} else {
		if (unlikely(!src_ds))
			return -EINVAL;
	}

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_GATHERV;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = count;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	count = 0;
	if (co->rank == root) {
		if (src_ds && src_ds->length) {
			err = det_local_copy(co, src_ds, &dst_ds_array[root]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_gatherv: det_local_copy error %d\n",
					err);
				return err;
			}
		}

		for (i = 0; i < co->size; i++) {
			if ((i == root) || !dst_ds_array[i].length)
				continue;

			err = det_recv(co->qp_array[i], 0, &dst_ds_array[i], 1);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_gatherv: det_recv error %d\n",
					err);
				return err;
			}
			count++;
		}
	} else if (src_ds->length) {
		err = det_send(co->qp_array[root], 0, src_ds, 1, 0, 0);
		if (unlikely(err)) {
			printk(KERN_INFO "det_gatherv: det_send error %d\n",
				err);
			return err;
		}
		count++;
	}

	if (count) {
		err = det_next_action(co, det_co_pollcomplete_cb,
				      DET_CQ_THRESHOLD, count);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_gatherv: det_next_action error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_gatherv: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}

	return 0;
}
EXPORT_SYMBOL(det_gatherv);


static int det_allgather_doubling(struct det_co * const co,
				  struct det_wr * const wr)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr snd_wr, rcv_wr;
#endif
	struct det_local_ds snd_ds, rcv_ds;
	int i, dst, err;

	/*
	Recursive Doubling Algorithm:
	In the first step, processes that are a distance 1 apart
	exchange their data.  In the second step, processes that
	are a distance 2 apart exchange their own data as well as
	the data they received in the previous step.  In the third
	step, processes that are a distance 4 apart exchange their
	own data as well the data they received in the previous
	two steps.  In this way, for a power-of-two number of
	processes, all processes get all the data in lg p steps. 
	*/

	snd_ds.l_key = wr->allgather.dst_ds.l_key;
	rcv_ds.l_key = wr->allgather.dst_ds.l_key;

#ifdef	DET_TRIGGERED_WR
	/* Sends are dependant on multiple disjoint receives. */

	/* Setup the static twr fields. */
	snd_wr.id	= (unsigned long)wr;
	snd_wr.ds_array = &snd_ds;
	snd_wr.num_ds   = 1;
	snd_wr.type     = DET_WR_SEND;

	rcv_wr.id	= (unsigned long)wr;
	rcv_wr.ds_array = &rcv_ds;
	rcv_wr.num_ds   = 1;
	rcv_wr.type     = DET_WR_RECV;

	while (wr->allgather.mask < co->size) {
#else
	if (wr->allgather.mask < co->size) {
#endif
		dst = co->rank ^ wr->allgather.mask;

#ifdef	DET_TRIGGERED_WR
		if (wr->allgather.i) {
			/*
			 * Post the previous send/receive.
			 * Must do this before clobbering the snd_wr or rcv_wr.
			 */
			err = det_post_twr(&snd_wr,
					   (wr->allgather.i == 1) ? 0 :
						(wr->allgather.i == 2) ? 1 : 2,
					   (wr->allgather.i > 1) ?
						co->qp_array[dst] : NULL);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgather_doubling: det_post_twr snd error %d\n",
					err);
				return err;
			}

			err = det_post_twr(&rcv_wr, 0, co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgather_doubling: det_post_twr rcv error %d\n",
					err);
				return err;
			}
		}

		snd_wr.qp = co->qp_array[dst];
		rcv_wr.qp = co->qp_array[dst];
#endif
		/*
		 * Find offset into send and recv buffers.  Clear 
		 * the least significant "i" bits of rank and dst
		 * to find root of src and dst subtrees.  This
		 * becomes the index into the buffers.
		 */

		i = co->rank >> wr->allgather.i;
		i <<= wr->allgather.i;

		snd_ds.length = wr->allgather.nbytes * wr->allgather.mask;
		snd_ds.vaddr  = wr->allgather.dst_ds.vaddr +
				wr->allgather.nbytes * i;

		i = dst >> wr->allgather.i;
		i <<= wr->allgather.i;

		rcv_ds.length = wr->allgather.nbytes * wr->allgather.mask;
		rcv_ds.vaddr  = wr->allgather.dst_ds.vaddr +
				wr->allgather.nbytes * i;

		/* Prepare for next pass. */
		wr->allgather.i++;
		wr->allgather.mask <<= 1;

#ifndef	DET_TRIGGERED_WR
		/*
		 * Post one at a time to ensure that data from previous
		 * round is received before being sent in the next round.
		 */
		err = det_co_sendrecv(co, (unsigned long)wr, dst, dst, 1,
			&snd_ds, 1, &rcv_ds, det_allgather_doubling_cb);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_doubling: det_co_sendrecv error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_doubling: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}
#else
	}

	err = det_post_twr(&snd_wr,
			   (wr->allgather.i == 1) ? 0 :
				(wr->allgather.i == 2) ? 1 : 2, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgather_doubling: final det_post_twr snd error %d\n",
			err);
		return err;
	}

	err = det_post_twr(&rcv_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgather_doubling: final det_post_twr rcv error %d\n",
			err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      wr->allgather.i + 1);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgather_doubling: det_next_action error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_allgather_doubling_cb(struct det_co * const co)
{
	u64 id;
	int err;

	err = det_co_sendrecv_cb(co, &id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgather_doubling_cb: det_complete_co_wr error %d\n",
			err);
		return err;
	}

	err = det_allgather_doubling(co, (struct det_wr *)(unsigned long)id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgather_doubling_cb: det_allgather_doubling error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


static int det_disseminate_ds(struct det_co * const co,
			      struct det_local_ds *ds_array,
			      struct det_local_ds *ds,
			      int index,
			      int nbytes,
			      int count)
{
	int num_ds;

	/*
	 * Build the ds_array to transfer data specified by ds.  The
	 * count parameter is the number of blocks transfered, where
	 * each blocks is nbytes in length.  Return the number segments.
	 */
	ds_array[0].l_key = ds->l_key;
	ds_array[0].vaddr = ds->vaddr + nbytes * index;

	/* Check if transfer wraps buffer. */
	if ((index + count) > co->size) {
		ds_array[0].length = nbytes * (co->size - index);
		ds_array[1].l_key  = ds->l_key;
		ds_array[1].length = nbytes * (count - (co->size - index));
		ds_array[1].vaddr  = ds->vaddr;
		num_ds = 2;
	} else {
		ds_array[0].length = nbytes * count;
		num_ds = 1;
	}

	return num_ds;
}


#ifndef	DET_TRIGGERED_WR
static int det_allgather_disseminate(struct det_co * const co,
				     struct det_wr * const wr,
				     int mask,
				     int count)
{
	struct det_local_ds snd_ds[2], rcv_ds[2];
	int num_snd_ds, num_rcv_ds, src, dst, err;

	src = (co->rank + mask) % co->size;
	dst = (co->rank - mask  + co->size) % co->size;

	num_snd_ds = det_disseminate_ds(co, snd_ds, &wr->allgather.dst_ds,
					co->rank, wr->allgather.nbytes, count);

	num_rcv_ds = det_disseminate_ds(co, rcv_ds, &wr->allgather.dst_ds,
					src, wr->allgather.nbytes, count);

	err = det_co_sendrecv(co, (unsigned long)wr, dst, src, num_snd_ds,
		snd_ds, num_rcv_ds, rcv_ds, det_allgather_dissemination_cb);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgather_disseminate: det_co_sendrecv error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


#ifdef	DET_TRIGGERED_WR
static int det_allgather_dissemination(struct det_co * const co,
				       struct det_wr * const wr)
{
	struct det_twr snd_wr, rcv_wr;
	struct det_local_ds snd_ds[2], rcv_ds[2];
	int src, dst, rem, err;

	/*
	Dissemination Algorithm:
	The Bruck algorithm for allgather is a variant of the
	dissemination algorithm for barrier.  Both algorithms
	take [lg p] steps in all cases, even for non-power-of-two
	number of processes.  In the dissemination algorithm
	for barrier, in each step k (0 <= k < [lg p]), process
	i sends a (zero-byte) message to process (i + 2^k) and
	receives a (zero-byte) message from process (i - 2^k)
	(with wrap-around).  If the same order were used to
	perform an allgather, it would require communicating
	noncontiguous data in each step in order to get the
	right data to the right process.  The Bruck algorithm
	avoids this problem nicely by a simple modifcation to
	the dissemination algorithm in which, in each step k,
	process i sends data to process (i - 2^k) and receives
	data from process (i + 2^k), instead of the other way
	around.  The result is that all communication is contiguous,
	except where data wraps the buffer in which case two
	data segments are used to transfer data in the right order.
	*/

	/* Sends are dependant on multiple disjoint receives. */

	/* Setup the static twr fields. */
	snd_wr.id	= (unsigned long)wr;
	snd_wr.ds_array = snd_ds;
	snd_wr.type     = DET_WR_SEND;

	rcv_wr.id	= (unsigned long)wr;
	rcv_wr.ds_array = rcv_ds;
	rcv_wr.type     = DET_WR_RECV;

	wr->allgather.i = 0;
	while (wr->allgather.mask <= co->size / 2) {

		/* The first floor(lg p) steps are done here. */

		src = (co->rank + wr->allgather.mask) % co->size;
		dst = (co->rank - wr->allgather.mask  + co->size) % co->size;

		if (wr->allgather.i) {
			/*
			 * Post the previous send/receive.
			 * Must do this before clobbering the snd_wr or rcv_wr.
			 */
			err = det_post_twr(&snd_wr,
					   (wr->allgather.i == 1) ? 0 :
						(wr->allgather.i == 2) ? 1 : 2,
					   (wr->allgather.i > 1) ?
						co->qp_array[dst] : NULL);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgather_dissemination: det_post_twr snd error %d\n",
					err);
				return err;
			}

			err = det_post_twr(&rcv_wr, 0, co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgather_dissemination: det_post_twr rcv error %d\n",
					err);
				return err;
			}
		}

		snd_wr.qp     = co->qp_array[dst];
		snd_wr.num_ds = det_disseminate_ds(co, snd_ds,
					&wr->allgather.dst_ds,
					co->rank, wr->allgather.nbytes,
					wr->allgather.mask);

		rcv_wr.qp     = co->qp_array[src];
		rcv_wr.num_ds = det_disseminate_ds(co, rcv_ds,
					&wr->allgather.dst_ds,
					src, wr->allgather.nbytes,
					wr->allgather.mask);

		/* Prepare for next pass. */
		wr->allgather.i++;
		wr->allgather.mask *= 2;
	}

	/*
	 * If size is not a power-of-two, one more step is needed.
	 * Note that rem is the number of blocks left to send.
	 */
	if ((rem = co->size - wr->allgather.mask)) {

		src = (co->rank + wr->allgather.mask) % co->size;
		dst = (co->rank - wr->allgather.mask  + co->size) % co->size;

		/*
		 * Post the previous send/receive.
		 * Must do this before clobbering the snd_wr or rcv_wr.
		 */
		err = det_post_twr(&snd_wr,
				   (wr->allgather.i == 1) ? 0 :
					(wr->allgather.i == 2) ? 1 : 2,
				   (wr->allgather.i > 1) ?
					co->qp_array[dst] : NULL);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_dissemination: det_post_twr snd error %d\n",
				err);
			return err;
		}

		err = det_post_twr(&rcv_wr, 0, co->qp_array[dst]);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_dissemination: det_post_twr rcv error %d\n",
				err);
			return err;
		}

		snd_wr.qp     = co->qp_array[dst];
		snd_wr.num_ds = det_disseminate_ds(co, snd_ds,
					&wr->allgather.dst_ds,
					co->rank, wr->allgather.nbytes, rem);

		rcv_wr.qp     = co->qp_array[src];
		rcv_wr.num_ds = det_disseminate_ds(co, rcv_ds,
					&wr->allgather.dst_ds,
					src, wr->allgather.nbytes, rem);
		wr->allgather.i++;
	}

	err = det_post_twr(&snd_wr,
			   (wr->allgather.i == 1) ? 0 :
				(wr->allgather.i == 2) ? 1 : 2, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgather_dissemination: final det_post_twr snd error %d\n",
			err);
		return err;
	}

	err = det_post_twr(&rcv_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgather_dissemination: final det_post_twr rcv error %d\n",
			err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      wr->allgather.i + 1);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgather_dissemination: det_next_action error %d\n",
			err);
		return err;
	}

	return 0;
}

#else

static int det_allgather_dissemination(struct det_co * const co,
				       struct det_wr * const wr)
{
	int mask, rem, err;

	/*
	Dissemination Algorithm:
	The Bruck algorithm for allgather is a variant of the
	dissemination algorithm for barrier.  Both algorithms
	take [lg p] steps in all cases, even for non-power-of-two
	number of processes.  In the dissemination algorithm
	for barrier, in each step k (0 <= k < [lg p]), process
	i sends a (zero-byte) message to process (i + 2^k) and
	receives a (zero-byte) message from process (i - 2^k)
	(with wrap-around).  If the same order were used to
	perform an allgather, it would require communicating
	noncontiguous data in each step in order to get the
	right data to the right process.  The Bruck algorithm
	avoids this problem nicely by a simple modifcation to
	the dissemination algorithm in which, in each step k,
	process i sends data to process (i - 2^k) and receives
	data from process (i + 2^k), instead of the other way
	around.  The result is that all communication is contiguous,
	except where data wraps the buffer in which case two
	data segments are used to transfer data in the right order.
	*/
	if (wr->allgather.mask <= co->size / 2) {
		mask = wr->allgather.mask;

		/* Prepare for next pass. */
		wr->allgather.mask *= 2;

		/* The first floor(lg p) steps are done here. */
		err = det_allgather_disseminate(co, wr, mask, mask);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_dissemination: det_allgather_disseminate error %d\n",
				err);
			return err;
		}
	} else if ((rem = co->size - wr->allgather.mask)) {
		/*
		 * If size is not a power-of-two, one more step is needed.
		 * Note that rem is the number of blocks left to send.
		 * Set mask to size to trigger completion on next call.
		 */
		mask = wr->allgather.mask;
		wr->allgather.mask = co->size;

		err = det_allgather_disseminate(co, wr, mask, rem);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_dissemination: det_allgather_disseminate error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_dissemination: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}

	return 0;
}


static int det_allgather_dissemination_cb(struct det_co * const co)
{
	u64 id;
	int err;

	err = det_co_sendrecv_cb(co, &id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgather_dissemination_cb: det_complete_co_wr error %d\n",
			err);
		return err;
	}

	err = det_allgather_dissemination(co,
					(struct det_wr *)(unsigned long)id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgather_dissemination_cb: det_allgather_dissemination error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


static int det_allgather_ring(struct det_co * const co,
			      struct det_wr * const wr)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig_wr;
#endif
	struct det_local_ds snd_ds, rcv_ds;
	int left, right, j, jnext, err;

	/*
	Ring Algorithm:
	In the ring algorithm, the data from each process is
	sent around a virtual ring of processes.  In the first
	step, each process i sends its contribution to process
	i + 1 and receives the contribution from process i - 1
	(with wrap-around).  From the second step onward each
	process i forwards to process i + 1 the data it received
	from process i - 1 in the previous step.  If p is the
	number of processes, the entire algorithm takes p - 1
	steps.  If n is the total amount of data to be gathered
	on each process, then at every step each process sends
	and receives n/p amount of data.
	*/
	left  = (co->size + co->rank - 1) % co->size;
	right = (co->rank + 1) % co->size;

#ifdef	DET_TRIGGERED_WR
	/* Setup static trig_wr fields for posting receives. */
	trig_wr.id	 = (unsigned long)wr;
	trig_wr.qp	 = co->qp_array[left];
	trig_wr.ds_array = &rcv_ds;
	trig_wr.num_ds   = 1;
	trig_wr.type     = DET_WR_RECV;

	while (wr->allgather.i < co->size) {
#else
	if (wr->allgather.i < co->size) {
#endif
		j = wr->allgather.j;
		jnext = wr->allgather.mask;

		/* Build the send data segment. */
		snd_ds.l_key  = wr->allgather.dst_ds.l_key;
		snd_ds.length = wr->allgather.nbytes;
		snd_ds.vaddr  = wr->allgather.dst_ds.vaddr +
				wr->allgather.nbytes * j;

#ifdef	DET_TRIGGERED_WR
		if (wr->allgather.i > 1) {
			/*
			 * Post the previous receive to trigger this send.
			 * Must do this before clobbering the recevie ds.
			 */
			err = det_post_twr(&trig_wr, 0, co->qp_array[right]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgather_ring: det_post_twr error %d\n",
					err);
				return err;
			}
		}

		err = det_trig_send(co->qp_array[right], (unsigned long)wr,
				    &snd_ds, 1, (wr->allgather.i > 1) ? 1 : 0,
				    NULL);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_ring: det_trig_send error %d\n",
				err);
			return err;
		}
#endif
		/* Build the receive data segment. */
		rcv_ds.l_key  = wr->allgather.dst_ds.l_key;
		rcv_ds.length = wr->allgather.nbytes;
		rcv_ds.vaddr  = wr->allgather.dst_ds.vaddr +
				wr->allgather.nbytes * jnext;

		/* Prepare for next pass. */
		wr->allgather.mask = (co->size + jnext - 1) % co->size;
		wr->allgather.j = jnext;
		wr->allgather.i++;

#ifndef	DET_TRIGGERED_WR
		err = det_co_sendrecv(co, (unsigned long)wr, right, left, 1,
			&snd_ds, 1, &rcv_ds, det_allgather_ring_cb);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_ring: det_co_sendrecv error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgather_ring: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}
#else
	}

	err = det_post_twr(&trig_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgather_ring: final det_post_twr error %d\n",
			err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      wr->allgather.i);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgather_ring: det_next_action error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_allgather_ring_cb(struct det_co * const co)
{
	u64 id;
	int err;

	err = det_co_sendrecv_cb(co, &id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgather_ring_cb: det_complete_co_wr error %d\n",
			err);
		return err;
	}

	err = det_allgather_ring(co, (struct det_wr *)(unsigned long)id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgather_ring_cb: det_allgather_ring error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


static int __det_allgather(struct det_co * const co,
			   struct det_wr * const wr,
			   const struct det_local_ds * const src_ds,
			   const struct det_local_ds * const dst_ds)
{
	struct det_local_ds ds;
	int err;

	wr->allgather.dst_ds = *dst_ds;
	wr->allgather.nbytes = dst_ds->length / co->size;

	if (src_ds) {
		/* Copy the local data. */
		ds.l_key  = dst_ds->l_key;
		ds.length = wr->allgather.nbytes;
		ds.vaddr  = dst_ds->vaddr + wr->allgather.nbytes * co->rank;

		err = det_local_copy(co, src_ds, &ds);
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_allgather: det_local_copy error %d\n",
				err);
			return err;
		}
	}

	if ((dst_ds->length < ALLGATHER_LONG_MSG) && is_pof2(co->size)) {
		/*
		 * Short or medium size message and power-of-two number
		 * of processes.  Use recursive doubling algorithm.
		 */
		wr->allgather.i	   = 0;
		wr->allgather.mask = 1;
		err = det_allgather_doubling(co, wr);

	} else if (dst_ds->length < ALLGATHER_SHORT_MSG) {
		/*
		 * Short message and non-power-of-two number of processes.
		 * Use Bruck algorithm (see description below).
		 */
		wr->allgather.mask = 1;
		err = det_allgather_dissemination(co, wr);
	} else {
		/*
		 * Long message or medium-size message and non-power-of-two
		 * number of processes.  Use ring algorithm.
		 */
		wr->allgather.i	   = 1;
		wr->allgather.j	   = co->rank;
		wr->allgather.mask = (co->size + co->rank - 1) % co->size;
		err = det_allgather_ring(co, wr);
	}

	if (unlikely(err)) {
		printk(KERN_INFO "__det_allgather: error %d\n", err);
		return err;
	}

	return 0;
}


/*
 *  Refer to the MPICH MPI_Allgather code for the algorithm.
 */
int det_allgather(struct det_co * const co,
		  const __u64 id,
		  const struct det_local_ds * const src_ds,
		  const struct det_local_ds * const dst_ds,
		  const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int err;

	if (unlikely(!dst_ds || (dst_ds->length && (dst_ds->length % co->size))))
		return -EINVAL;

	if (unlikely( src_ds && (src_ds->length != (dst_ds->length / co->size))))
		return -EINVAL;

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_ALLGATHER;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = dst_ds->length;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	err = __det_allgather(co, wr, src_ds, dst_ds);
	if (unlikely(err)) {
		printk(KERN_INFO "det_gather: __det_allgather error %d\n", err);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(det_allgather);


static int det_allgatherv_doubling(struct det_co * const co,
				   struct det_wr * const wr)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr snd_wr, rcv_wr;
#endif
	int i, j, dst, num_ds, err;

	/*
	Recursive Doubling Algorithm:
	In the first step, processes that are a distance 1 apart
	exchange their data.  In the second step, processes that
	are a distance 2 apart exchange their own data as well as
	the data they received in the previous step.  In the third
	step, processes that are a distance 4 apart exchange their
	own data as well the data they received in the previous
	two steps.  In this way, for a power-of-two number of
	processes, all processes get all the data in lg p steps. 
	*/

#ifdef	DET_TRIGGERED_WR
	/* Sends are dependant on multiple disjoint receives. */

	/* Setup the static twr fields. */
	snd_wr.id   = (unsigned long)wr;
	snd_wr.type = DET_WR_SEND;

	rcv_wr.id   = (unsigned long)wr;
	rcv_wr.type = DET_WR_RECV;

	while (wr->allgatherv.mask < co->size) {
#else
	if (wr->allgatherv.mask < co->size) {
#endif
		dst = co->rank ^ wr->allgatherv.mask;
		num_ds = wr->allgatherv.mask;

#ifdef	DET_TRIGGERED_WR
		if (wr->allgatherv.i) {
			/*
			 * Post the previous send/receive.
			 * Must do this before clobbering the snd_wr or rcv_wr.
			 */
			err = det_post_twr(&snd_wr,
					   (wr->allgatherv.i == 1) ? 0 :
						(wr->allgatherv.i == 2) ? 1 : 2,
					   (wr->allgatherv.i > 1) ?
						co->qp_array[dst] : NULL);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgatherv_doubling: det_post_twr snd error %d\n",
					err);
				return err;
			}

			err = det_post_twr(&rcv_wr, 0, co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgatherv_doubling: det_post_twr rcv error %d\n",
					err);
				return err;
			}
		}
#endif
		/*
		 * Find offset into send and recv data segment arrays.
		 * Clear the least significant "i" bits of rank and dst
		 * to find root of src and dst subtrees.
		 */ 

		i = co->rank >> wr->allgatherv.i;
		i <<= wr->allgatherv.i;

		j = dst >> wr->allgatherv.i;
		j <<= wr->allgatherv.i;

#ifdef	DET_TRIGGERED_WR
		snd_wr.qp	= co->qp_array[dst];
		snd_wr.ds_array = &wr->allgatherv.dst_ds_array[i];
		snd_wr.num_ds   = num_ds;

		rcv_wr.qp	= co->qp_array[dst];
		rcv_wr.ds_array = &wr->allgatherv.dst_ds_array[j];
		rcv_wr.num_ds   = num_ds;
#endif

		/* Prepare for next pass. */
		wr->allgatherv.i++;
		wr->allgatherv.mask <<= 1;

#ifndef	DET_TRIGGERED_WR
		/*
		 * Post one at a time to ensure that data from previous
		 * round is received before being sent in the next round.
		 */
		err = det_co_sendrecv(co, (unsigned long)wr, dst, dst,
			num_ds, &wr->allgatherv.dst_ds_array[i],
			num_ds, &wr->allgatherv.dst_ds_array[j],
			det_allgatherv_doubling_cb);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_doubling: det_co_sendrecv error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_doubling: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}
#else
	}

	err = det_post_twr(&snd_wr,
			   (wr->allgatherv.i == 1) ? 0 :
				(wr->allgatherv.i == 2) ? 1 : 2, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgatherv_doubling: final det_post_twr snd error %d\n",
			err);
		return err;
	}

	err = det_post_twr(&rcv_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgatherv_doubling: final det_post_twr rcv error %d\n",
			err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      wr->allgatherv.i + 1);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgatherv_doubling: det_next_action error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_allgatherv_doubling_cb(struct det_co * const co)
{
	struct det_wc wc;
	u32 i, num_wc;
	int err;

	/* Poll completions. */
	for (i = 0; i < co->cq.attr.threshold; i++) {
		num_wc = 1;
		err = det_poll_cq(&co->cq, &num_wc, &wc);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_doubling_cb: poll cq error %d\n",
				err);
			return err;
		}

		if (wc.status != DET_WS_SUCCESS) {
			printk(KERN_INFO
				"det_allgatherv_doubling_cb: wc.status %d\n",
				wc.status);
			return -EIO;
		}
	}

	err = det_allgatherv_doubling(co, (struct det_wr *)(unsigned long)wc.id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgatherv_doubling_cb: det_allgatherv_doubling error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


#ifdef	DET_TRIGGERED_WR
static int det_allgatherv_dissemination(struct det_co * const co,
					struct det_wr * const wr)
{
	struct det_twr snd_wr, rcv_wr;
	int src, dst, rem, err;

	/*
	Dissemination Algorithm:
	The Bruck algorithm for allgather is a variant of the
	dissemination algorithm for barrier.  Both algorithms
	take [lg p] steps in all cases, even for non-power-of-two
	number of processes.  In the dissemination algorithm
	for barrier, in each step k (0 <= k < [lg p]), process
	i sends a (zero-byte) message to process (i + 2^k) and
	receives a (zero-byte) message from process (i - 2^k)
	(with wrap-around).  If the same order were used to
	perform an allgather, it would require communicating
	noncontiguous data in each step in order to get the
	right data to the right process.  The Bruck algorithm
	avoids this problem nicely by a simple modifcation to
	the dissemination algorithm in which, in each step k,
	process i sends data to process (i - 2^k) and receives
	data from process (i + 2^k), instead of the other way
	around.  The result is that all communication is contiguous.
	*/

	/* Sends are dependant on multiple disjoint receives. */

	/* Setup the static twr fields. */
	snd_wr.id   = (unsigned long)wr;
	snd_wr.type = DET_WR_SEND;

	rcv_wr.id   = (unsigned long)wr;
	rcv_wr.type = DET_WR_RECV;

	wr->allgatherv.i = 0;
	while (wr->allgatherv.mask <= co->size / 2) {

		/* The first floor(lg p) steps are done here. */

		src = (co->rank + wr->allgatherv.mask) % co->size;
		dst = (co->rank - wr->allgatherv.mask  + co->size) % co->size;

		if (wr->allgatherv.i) {
			/*
			 * Post the previous send/receive.
			 * Must do this before clobbering the snd_wr or rcv_wr.
			 */
			err = det_post_twr(&snd_wr,
					   (wr->allgatherv.i == 1) ? 0 :
						(wr->allgatherv.i == 2) ? 1 : 2,
					   (wr->allgatherv.i > 1) ?
						co->qp_array[dst] : NULL);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgatherv_dissemination: det_post_twr snd error %d\n",
					err);
				return err;
			}

			err = det_post_twr(&rcv_wr, 0, co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgatherv_dissemination: det_post_twr rcv error %d\n",
					err);
				return err;
			}
		}

		snd_wr.qp	= co->qp_array[dst];
		snd_wr.ds_array = wr->allgatherv.dst_ds_array;
		snd_wr.num_ds	= wr->allgatherv.mask;

		rcv_wr.qp	= co->qp_array[src];
		rcv_wr.ds_array = &wr->allgatherv.dst_ds_array[wr->allgatherv.mask];
		rcv_wr.num_ds	= wr->allgatherv.mask;

		/* Prepare for next pass. */
		wr->allgatherv.i++;
		wr->allgatherv.mask *= 2;
	}

	/*
	 * If size is not a power-of-two, one more step is needed.
	 * Note that rem is the number of blocks left to send.
	 */
	if ((rem = co->size - wr->allgatherv.mask)) {

		src = (co->rank + wr->allgatherv.mask) % co->size;
		dst = (co->rank - wr->allgatherv.mask  + co->size) % co->size;

		/*
		 * Post the previous send/receive.
		 * Must do this before clobbering the snd_wr or rcv_wr.
		 */
		err = det_post_twr(&snd_wr,
				   (wr->allgatherv.i == 1) ? 0 :
					(wr->allgatherv.i == 2) ? 1 : 2,
				   (wr->allgatherv.i > 1) ?
					co->qp_array[dst] : NULL);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_dissemination: det_post_twr snd error %d\n",
				err);
			return err;
		}

		/*
		 * Post the previous receive to trigger this send.
		 * Must do this before clobbering the trig_wr.
		 */
		err = det_post_twr(&rcv_wr, 0, co->qp_array[dst]);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_dissemination: det_post_twr rcv error %d\n",
				err);
			return err;
		}

		snd_wr.qp	= co->qp_array[dst];
		snd_wr.ds_array = wr->allgatherv.dst_ds_array;
		snd_wr.num_ds	= rem;

		rcv_wr.qp	= co->qp_array[src];
		rcv_wr.ds_array = &wr->allgatherv.dst_ds_array[wr->allgatherv.mask];
		rcv_wr.num_ds	= rem;

		wr->allgatherv.i++;
	}

	err = det_post_twr(&snd_wr,
			   (wr->allgatherv.i == 1) ? 0 :
				(wr->allgatherv.i == 2) ? 1 : 2, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgatherv_dissemination: final det_post_twr snd error %d\n",
			err);
		return err;
	}

	err = det_post_twr(&rcv_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgatherv_dissemination: final det_post_twr rcv error %d\n",
			err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      wr->allgatherv.i + 1);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgatherv_dissemination: det_next_action error %d\n",
			err);
		return err;
	}

	return 0;
}

#else

static int det_allgatherv_disseminate(struct det_co * const co,
				      struct det_wr * const wr,
				      int mask,
				      int count)
{
	struct det_local_ds *snd_ds, *rcv_ds;
	int src, dst, err;

	src = (co->rank + mask) % co->size;
	dst = (co->rank - mask  + co->size) % co->size;

	snd_ds = wr->allgatherv.dst_ds_array;
	rcv_ds = &wr->allgatherv.dst_ds_array[mask];

	err = det_co_sendrecv(co, (unsigned long)wr, dst, src, count,
		snd_ds, count, rcv_ds, det_allgatherv_disseminate_cb);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgatherv_disseminate: det_co_sendrecv error %d\n",
			err);
		return err;
	}

	return 0;
}


static int det_allgatherv_dissemination(struct det_co * const co,
					struct det_wr * const wr)
{
	int mask, rem, err;

	/*
	Dissemination Algorithm:
	The Bruck algorithm for allgather is a variant of the
	dissemination algorithm for barrier.  Both algorithms
	take [lg p] steps in all cases, even for non-power-of-two
	number of processes.  In the dissemination algorithm
	for barrier, in each step k (0 <= k < [lg p]), process
	i sends a (zero-byte) message to process (i + 2^k) and
	receives a (zero-byte) message from process (i - 2^k)
	(with wrap-around).  If the same order were used to
	perform an allgather, it would require communicating
	noncontiguous data in each step in order to get the
	right data to the right process.  The Bruck algorithm
	avoids this problem nicely by a simple modifcation to
	the dissemination algorithm in which, in each step k,
	process i sends data to process (i - 2^k) and receives
	data from process (i + 2^k), instead of the other way
	around.  The result is that all communication is contiguous.
	*/
	if (wr->allgatherv.mask <= co->size / 2) {
		mask = wr->allgatherv.mask;

		/* Prepare for next pass. */
		wr->allgatherv.mask *= 2;

		/* The first floor(lg p) steps are done here. */
		err = det_allgatherv_disseminate(co, wr, mask, mask);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_dissemination: det_allgatherv_disseminate error %d\n",
				err);
			return err;
		}
	} else if ((rem = co->size - wr->allgatherv.mask)) {
		/*
		 * If size is not a power-of-two, one more step is needed.
		 * Note that rem is the number of data segments left to send.
		 * Set mask to size to trigger completion on next call.
		 */
		mask = wr->allgatherv.mask;
		wr->allgatherv.mask = co->size;

		err = det_allgatherv_disseminate(co, wr, mask, rem);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_dissemination: det_allgatherv_disseminate error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_dissemination: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}

	return 0;
}


static int det_allgatherv_disseminate_cb(struct det_co * const co)
{
	struct det_wc wc;
	u32 num_wc;
	int i, err;

	for (i = 0; i < co->cq.attr.threshold; i++) {
		num_wc = 1;
		err = det_poll_cq(&co->cq, &num_wc, &wc);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_disseminate_cb: rank %d poll cq error %d\n",
				co->rank, err);
			return err;
		}

		if (unlikely(wc.status != DET_WS_SUCCESS)) {
			printk(KERN_INFO
				"det_allgatherv_disseminate_cb: rank %d wc.status %d\n",
				co->rank, wc.status);
			return -EIO;
		}
	}

	err = det_allgatherv_dissemination(co, (struct det_wr *)(unsigned long)wc.id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgatherv_disseminate_cb: det_allgatherv_dissemination error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


static int det_allgatherv_ring(struct det_co * const co,
			       struct det_wr * const wr)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig_wr;
#endif
	int left, right, j, jnext, err;

	/*
	Ring Algorithm:
	In the ring algorithm, the data from each process is
	sent around a virtual ring of processes.  In the first
	step, each process i sends its contribution to process
	i + 1 and receives the contribution from process i - 1
	(with wrap-around).  From the second step onward each
	process i forwards to process i + 1 the data it received
	from process i - 1 in the previous step.  If p is the
	number of processes, the entire algorithm takes p - 1
	steps.  If n is the total amount of data to be gathered
	on each process, then at every step each process sends
	and receives n/p amount of data.
	*/
	left  = (co->size + co->rank - 1) % co->size;
	right = (co->rank + 1) % co->size;

#ifdef	DET_TRIGGERED_WR
	/* Setup static trig_wr fields for posting receives. */
	trig_wr.id	 = (unsigned long)wr;
	trig_wr.qp	 = co->qp_array[left];
	trig_wr.num_ds   = 1;
	trig_wr.type     = DET_WR_RECV;

	while (wr->allgatherv.i < co->size) {
#else
	if (wr->allgatherv.i < co->size) {
#endif
		j = wr->allgatherv.j;
		jnext = wr->allgatherv.mask;

#ifdef	DET_TRIGGERED_WR
		if (wr->allgatherv.i > 1) {
			/* Post the previous receive to trigger this send. */
			err = det_post_twr(&trig_wr, 0, co->qp_array[right]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_allgatherv_ring: det_post_twr error %d\n",
					err);
				return err;
			}
		}

		err = det_trig_send(co->qp_array[right], (unsigned long)wr,
				    &wr->allgatherv.dst_ds_array[j], 1,
				    (wr->allgatherv.i > 1) ? 1 : 0, NULL);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_ring: det_trig_send error %d\n",
				err);
			return err;
		}

		trig_wr.ds_array = &wr->allgatherv.dst_ds_array[jnext];
#endif
		/* Prepare for next pass. */
		wr->allgatherv.mask = (co->size + jnext - 1) % co->size;
		wr->allgatherv.j    = jnext;
		wr->allgatherv.i++;

#ifndef	DET_TRIGGERED_WR
		err = det_co_sendrecv(co, (unsigned long)wr, right, left, 1,
				      &wr->allgatherv.dst_ds_array[j], 1,
				      &wr->allgatherv.dst_ds_array[jnext],
				      det_allgatherv_ring_cb);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_ring: det_co_sendrecv error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_allgatherv_ring: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}
#else
	}

	err = det_post_twr(&trig_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgatherv_ring: final det_post_twr error %d\n",
			err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      wr->allgatherv.i);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgatherv_ring: det_next_action error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_allgatherv_ring_cb(struct det_co * const co)
{
	u64 id;
	int err;

	err = det_co_sendrecv_cb(co, &id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgatherv_ring_cb: det_complete_co_wr error %d\n",
			err);
		return err;
	}

	err = det_allgatherv_ring(co, (struct det_wr *)(unsigned long)id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_allgatherv_ring_cb: det_allgatherv_ring error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


static int __det_allgatherv(struct det_co * const co,
			    struct det_wr * const wr,
			    const struct det_local_ds * const src_ds,
			    const struct det_local_ds * const dst_ds_array)
{
	int i, err;

	if (src_ds) {
		err = det_local_copy(co, src_ds, &dst_ds_array[co->rank]);
		if (unlikely(err)) {
			printk(KERN_INFO
				"__det_allgatherv: det_local_copy error %d\n",
				err);
			return err;
		}
	}

	if ((wr->total_length < ALLGATHER_LONG_MSG) && is_pof2(co->size)) {
		/*
		 * Short or medium size message and power-of-two number
		 * of processes.  Use recursive doubling algorithm.
		 */

#ifndef	DET_TRIGGERED_WR
		/* Allocate a buffer to save the dst_ds_array. */
		i = sizeof(*dst_ds_array) * co->size;
		err = det_co_alloc_tmp(co, i);
		if (unlikely(err))
			return err;
		det_memcpy(co->tmp, (void *)dst_ds_array, i);
		wr->allgatherv.dst_ds_array = co->tmp;
#else
		wr->allgatherv.dst_ds_array =
			(struct det_local_ds *)dst_ds_array;
#endif
		wr->allgatherv.i    = 0;
		wr->allgatherv.mask = 1;
		err = det_allgatherv_doubling(co, wr);
	} else if (wr->total_length < ALLGATHER_SHORT_MSG) {
		/*
		 * Short message and non-power-of-two number of processes.
		 * Use Bruck algorithm (see description below).
		 */

		/* Allocate a buffer for the dst_ds_array. */
		i = sizeof(*dst_ds_array) * co->size;
		err = det_co_alloc_tmp(co, i);
		if (unlikely(err))
			return err;
		wr->allgatherv.dst_ds_array = co->tmp;

		/* Rotate data segments up by rank. */
		det_memcpy(wr->allgatherv.dst_ds_array,
			   (void *)&dst_ds_array[co->rank],
			   sizeof(*dst_ds_array) * (co->size - co->rank));
		det_memcpy(&wr->allgatherv.dst_ds_array[co->size - co->rank],
			   (void *)dst_ds_array,
			   sizeof(*dst_ds_array) * co->rank);

		wr->allgatherv.mask = 1;
		err = det_allgatherv_dissemination(co, wr);
	} else {
		/*
		 * Long message or medium-size message and non-power-of-two
		 * number of processes.  Use ring algorithm.
		 */

#ifndef	DET_TRIGGERED_WR
		/* Allocate a buffer to save the dst_ds_array. */
		i = sizeof(*dst_ds_array) * co->size;
		err = det_co_alloc_tmp(co, i);
		if (unlikely(err))
			return err;
		det_memcpy(co->tmp, (void *)dst_ds_array, i);
		wr->allgatherv.dst_ds_array = co->tmp;
#else
		wr->allgatherv.dst_ds_array =
			(struct det_local_ds *)dst_ds_array;
#endif
		wr->allgatherv.i    = 1;
		wr->allgatherv.j    = co->rank;
		wr->allgatherv.mask = (co->size + co->rank - 1) % co->size;
		err = det_allgatherv_ring(co, wr);
	}

	if (unlikely(err)) {
		printk(KERN_INFO "__det_allgatherv: error %d\n", err);
		return err;
	}

	return 0;
}


/*
 *  Refer to the MPICH MPI_Allgatherv code for the algorithm.
 */
int det_allgatherv(struct det_co * const co,
		   const __u64 id,
		   const struct det_local_ds * const src_ds,
		   const struct det_local_ds * const dst_ds_array,
		   const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int i, err;

	if (unlikely(!dst_ds_array))
		return -EINVAL;

	if (unlikely(src_ds && (src_ds->length != dst_ds_array[co->rank].length)))
		return -EINVAL;

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_ALLGATHERV;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = 0;
	for (i = 0; i < co->size; i++)
		wr->total_length += dst_ds_array[i].length;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	err = __det_allgatherv(co, wr, src_ds, dst_ds_array);
	if (unlikely(err)) {
		printk(KERN_INFO "det_allgatherv: __det_allgatherv error %d\n",
			err);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(det_allgatherv);


static int det_alltoall_local_copy(struct det_co * const co,
				   struct det_wr * const wr)
{
	struct det_local_ds ds[2];
	int offset, err;

	/* Copy the local data block. */
	offset = wr->alltoall.nbytes * co->rank;

	ds[0].l_key  = wr->alltoall.src_ds.l_key;
	ds[0].vaddr  = wr->alltoall.src_ds.vaddr + offset;
	ds[0].length = wr->alltoall.nbytes;

	ds[1].l_key  = wr->alltoall.dst_ds.l_key;
	ds[1].vaddr  = wr->alltoall.dst_ds.vaddr + offset;
	ds[1].length = wr->alltoall.nbytes;

	err = det_local_copy(co, &ds[0], &ds[1]);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_local_copy: det_local_copy error %d\n", err);
		return err;
	}

	return 0;
}


#ifdef	DET_USE_DIRECT_INDEXING

static int det_alltoall_direct_index(struct det_co * const co,
				     struct det_wr * const wr)
{
	struct det_local_ds *src_ds, *dst_ds, *snd_ds, *rcv_ds, tmp_ds[2];
	int i, j, src, dst, src_offset, dst_offset, err;

	if (wr->alltoall.pof2 >= co->size) {
		/*
		 * Do Phase 3 of the algorithm.
		 * Just complete the work request.
		 */
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoall_direct_index: det_complete_co_wr error %d\n",
				err);
			return err;
		}

		return 0;
	}

	src = (co->rank - wr->alltoall.pof2  + co->size) % co->size;
	dst = (co->rank + wr->alltoall.pof2) % co->size;

	/* Build the snd_ds array in the top half of the tmp buffer. */
	snd_ds = co->tmp;
	rcv_ds = co->tmp + (co->tmp_size / 2);

	/* Initialize the temporary data segment for staging forwarded data. */
	tmp_ds[0].l_key  = co->mr->attr.l_key;
	tmp_ds[0].vaddr  = co->mr->vaddr;

	/* The length is not used (set up below). */
	/* This tmp_ds[1] is used for local copies with vaddr set up below. */

	tmp_ds[1].l_key  = co->mr->attr.l_key;
	tmp_ds[1].length = wr->alltoall.nbytes;

	/*
	 * Build the send and receive ds arrays.
	 * Exchange all data blocks whose ith bit is set.
	 */
	j = 0;
	for (i = 1; i < co->size; i++) {
		if (!(i & wr->alltoall.pof2))
			continue;

		/* Send data from alltoall.src_ds, forward from tmp_ds. */
		if (pof2(ffs(i)-1) == wr->alltoall.pof2) {
			src_ds	   = &wr->alltoall.src_ds;
			src_offset = (co->rank + i) % co->size;
		} else {
			src_ds	   = &tmp_ds[0];
			src_offset = (co->rank - i + co->size) % co->size;
		}

		snd_ds[j].l_key  = src_ds->l_key;
		snd_ds[j].vaddr  = src_ds->vaddr +
				   wr->alltoall.nbytes * src_offset;
		snd_ds[j].length = wr->alltoall.nbytes;

		/* Receive data to alltoall.dst_ds, stage to tmp_ds. */
		dst_ds	   = (pof2(fls(i)-1) == wr->alltoall.pof2) ?
			     &wr->alltoall.dst_ds : &tmp_ds[0];
		dst_offset = (co->rank - i + co->size) % co->size;

		rcv_ds[j].l_key  = dst_ds->l_key;
		rcv_ds[j].vaddr  = dst_ds->vaddr +
				   wr->alltoall.nbytes * dst_offset;
		rcv_ds[j].length = wr->alltoall.nbytes;

		/* Cannot send/receive from/to the same buffer. */
		if ((src_ds == dst_ds) && (src_offset == dst_offset)) {
			/*
			 * Copy send data to the middle of the staging buffer.
			 * This copy prevents use of triggered work requests.
			 */
			tmp_ds[1].vaddr = co->mr->vaddr	   +
				wr->alltoall.dst_ds.length +	/* middle */
				wr->alltoall.nbytes * dst_offset;

			err = det_local_copy(co, &snd_ds[j], &tmp_ds[1]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_alltoall_direct_index: det_local_copy error %d\n",
					err);
				return err;
			}
			/* Send this data from the new location. */
			snd_ds[j] = tmp_ds[1];
		}

		j++;
	}
	wr->alltoall.pof2 *= 2;

	/* Pack the send data if it will eliminate PDUs. */
	if (j > MAX_SKB_FRAGS) {
		/*
		 * Copy send data to the top of staging the buffer.
		 */
		tmp_ds[1].vaddr = co->mr->vaddr	   +
				  wr->alltoall.dst_ds.length * 2;  /* top */
		for (i = 0; i < j; i++) {
			err = det_local_copy(co, &snd_ds[i], &tmp_ds[1]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_alltoall_direct_index: det_local_copy pack error %d\n",
					err);
				return err;
			}
			tmp_ds[1].vaddr += wr->alltoall.nbytes;
		}
		/* Send all data from the new location. */
		snd_ds[0].l_key  = co->mr->attr.l_key;
		snd_ds[0].vaddr  = co->mr->vaddr   +
				   wr->alltoall.dst_ds.length * 2; /* top */
		snd_ds[0].length = wr->alltoall.nbytes * j;
		i = 1;
	} else  {
		i = j;
	}

	err = det_co_sendrecv(co, (unsigned long)wr, dst, src, i, snd_ds,
			      j, rcv_ds, det_alltoall_direct_index_cb);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_direct_index: det_co_sendrecv error %d\n", err);
		return err;
	}

	return 0;
}


static int det_alltoall_direct_index_cb(struct det_co * const co)
{
	u64 uninitialized_var(id);
	int err;

	err = det_co_sendrecv_cb(co, &id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_direct_index_cb: det_complete_co_wr error %d\n",
			err);
		return err;
	}

	err = det_alltoall_direct_index(co, (struct det_wr *)(unsigned long)id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_direct_index_cb: det_alltoall_direct_index error %d\n",
			err);
		return err;
	}

	return 0;
}


/*
 * Direct indexing uses direct data placement.
 */
static int det_alltoall_direct_indexing(struct det_co * const co,
					struct det_wr * const wr)
{
	int err;

	/*
	 * Indexing Algorithm
	 * This algorithm by Jehoshua Bruck et al consists of three phases.
	 *
	 * Phase 1. Each process P sub-i independently rotates its n data
	 *	    blocks i steps upward in a cyclical manner.  For direct
	 *	    indexing, this is not required since data segments direct
	 *	    the data.  Instead, we copy the local data as the first
	 *	    step.
	 *
	 * Phase 2. Each process P sub-i rotates its jth data block j steps
	 *	    to the right in a cyclical manner.  This rotation is
	 *	    implemented by interprocess communication.
	 *
	 * Phase 3. Each process P sub-i independently rotates its n data
	 *	    blocks i steps downward in a cyclical manner.  For direct
	 *	    indexing, this is not required since data segments direct
	 *	    the data.
	 *
	 * Another good description of this algorighm can be found in
	 * the paper by Rajeev Thakur et al, Optimization of Collective
	 * Communication Operations in MPICH.
	 */

	/* Phase 1:  Copy the local data. */
	err = det_alltoall_local_copy(co, wr);
	if (unlikely(err))
		return err;

	/*
	 * Phase 2:  The communication phase.  It takes ceiling(lg p) steps.
	 * In each step i, each process sends to rank+2^i and receives from
	 * rank-2^i, and exchanges all data blocks whose ith bit is 1.
	 */

	/*
	 * Allocate a buffer for staging forwarded data.  We need 3 times
	 * the size since there may times when send data is moved to the
	 * middle third of the buffer to keep a receive from clobbering
	 * it and the top third to pack send data.
	 */
	err = det_co_alloc_mr(co, wr->alltoall.dst_ds.length * 3, 0);
	if (unlikely(err))
		return err;

	/* Allocate a tmp buffer for building the send and receive ds_arrays. */
	err = det_co_alloc_tmp(co, sizeof(struct det_local_ds) * co->size);
	if (unlikely(err))
		return err;

	wr->alltoall.pof2 = 1;
	err = det_alltoall_direct_index(co, wr);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_direct_indexing: det_alltoall_direct_index error %d\n",
			err);
		return err;
	}

	return 0;
}


#else	// DET_USE_DIRECT_INDEXING


/*
 * Copy indexing uses data copies to pack and move data.
 */
static int det_alltoall_copy_index(struct det_co * const co,
				   struct det_wr * const wr)
{
	struct det_local_ds src_ds, dst_ds;
	int i, block, src, dst, err;

	/*
	 * If this is not the first time through, unpack received
	 * data from the lower portion of the temporary buffer to
	 * the destination buffer before proceedeing.
	 */
	if (wr->alltoall.pof2 != 1) {
		src_ds.l_key  = co->mr->attr.l_key;
		dst_ds.l_key  = wr->alltoall.dst_ds.l_key;

		src_ds.length =
		dst_ds.length = wr->alltoall.nbytes;

		i = 0;
		for (block = 1; block < co->size; block++) {
			if (!(block & wr->alltoall.pof2/2))
				continue;

			src_ds.vaddr = co->mr->vaddr +
				       wr->alltoall.nbytes *
				       (wr->alltoall.count + i);
			dst_ds.vaddr = wr->alltoall.dst_ds.vaddr +
				       wr->alltoall.nbytes * block;

			err = det_local_copy(co, &src_ds, &dst_ds);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_alltoall_copy_index: det_local_copy 1 error %d\n",
					err);
				return err;
			}
			i++;
		}
	}

	if (wr->alltoall.pof2 < co->size) {

		dst = (co->rank + wr->alltoall.pof2) % co->size;
		src = (co->rank - wr->alltoall.pof2  + co->size) % co->size;

		src_ds.l_key  = wr->alltoall.dst_ds.l_key;
		dst_ds.l_key  = co->mr->attr.l_key;

		src_ds.length =
		dst_ds.length = wr->alltoall.nbytes;

		/*
		 * Exchange all data blocks whose ith bit is set.  Pack
		 * the data into the temporary buffer for transmission.
		 */
		wr->alltoall.count = 0;
		for (block = 1; block < co->size; block++) {
			if (!(block & wr->alltoall.pof2))
				continue;

			src_ds.vaddr = wr->alltoall.dst_ds.vaddr +
				       wr->alltoall.nbytes * block;
			dst_ds.vaddr = co->mr->vaddr +
				       wr->alltoall.nbytes * wr->alltoall.count;

			err = det_local_copy(co, &src_ds, &dst_ds);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_alltoall_copy_index: det_local_copy 2 error %d\n",
					err);
				return err;
			}
			wr->alltoall.count++;
		}

		wr->alltoall.pof2 *= 2;

		/*
		 * Build send and receive data segments.  We transmit the
		 * packed data from the top portion of the temporary buffer
		 * and receive to the lower portion of the temporary buffer.
		 */
		src_ds.l_key  =
		dst_ds.l_key  = co->mr->attr.l_key;

		src_ds.length =
		dst_ds.length = wr->alltoall.nbytes * wr->alltoall.count;

		src_ds.vaddr = co->mr->vaddr;
		dst_ds.vaddr = co->mr->vaddr +
			       wr->alltoall.nbytes * wr->alltoall.count;

		err = det_co_sendrecv(co, (unsigned long)wr, dst, src, 1,
			&src_ds, 1, &dst_ds, det_alltoall_copy_index_cb);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoall_copy_index: det_co_sendrecv error %d\n",
				err);
			return err;
		}
	} else {
		/*
		 * Do Phase 3 of the algorithm.  Rotate blocks in
		 * destination buffer upwards by (rank + 1) blocks.
		 * Need a temporary buffer of the same size as the
		 * destination.
		 */
		src_ds.l_key  = wr->alltoall.dst_ds.l_key;
		dst_ds.l_key  = co->mr->attr.l_key;

		src_ds.length =
		dst_ds.length = wr->alltoall.nbytes *
				(co->size - co->rank - 1);

		src_ds.vaddr  = wr->alltoall.dst_ds.vaddr +
				wr->alltoall.nbytes * (co->rank + 1);
		dst_ds.vaddr  = co->mr->vaddr;

		err = det_local_copy(co, &src_ds, &dst_ds);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoall_copy_index: det_local_copy 3 error %d\n",
				err);
			return err;
		}

		src_ds.length =
		dst_ds.length = wr->alltoall.nbytes * (co->rank + 1);

		src_ds.vaddr  = wr->alltoall.dst_ds.vaddr;
		dst_ds.vaddr  = co->mr->vaddr + 
				wr->alltoall.nbytes * (co->size - co->rank - 1);

		err = det_local_copy(co, &src_ds, &dst_ds);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoall_copy_index: det_local_copy 4 error %d\n",
				err);
			return err;
		}

		/*
		 * Blocks are in the reverse order now (co->size-1 to 0). 
		 * Reorder them to (0 to co->size-1) and store them in the
		 * destination buffer.
		 */
		src_ds.l_key = co->mr->attr.l_key;
		dst_ds.l_key = wr->alltoall.dst_ds.l_key;

		src_ds.length =
		dst_ds.length = wr->alltoall.nbytes;

		for (i = 0; i < co->size; i++) {
			src_ds.vaddr = co->mr->vaddr + wr->alltoall.nbytes * i;
			dst_ds.vaddr = wr->alltoall.dst_ds.vaddr +
				       wr->alltoall.nbytes * (co->size - i - 1);

			err = det_local_copy(co, &src_ds, &dst_ds);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_alltoall_copy_index: det_local_copy 5 error %d\n",
					err);
				return err;
			}
		}

		/*
		 * Now complete the work request.
		 */
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoall_copy_index: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}

	return 0;
}


static int det_alltoall_copy_index_cb(struct det_co * const co)
{
	u64 id;
	int err;

	err = det_co_sendrecv_cb(co, &id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_copy_index_cb: det_complete_co_wr error %d\n",
			err);
		return err;
	}

	err = det_alltoall_copy_index(co, (struct det_wr *)(unsigned long)id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_copy_index_cb: det_alltoall_index error %d\n",
			err);
		return err;
	}

	return 0;
}


static int det_alltoall_copy_indexing(struct det_co * const co,
				      struct det_wr * const wr)
{
	struct det_local_ds src_ds, dst_ds;
	int err;

	/*
	 * Indexing Algorithm
	 * This algorithm by Jehoshua Bruck et al consists of three phases.
	 *
	 * Phase 1. Each process P sub-i independently rotates its n data
	 *	    blocks i steps upward in a cyclical manner.
	 *
	 * Phase 2. Each process P sub-i rotates its jth data block j steps
	 *	    to the right in a cyclical manner.  This rotation is
	 *	    implemented by interprocess communication.
	 *
	 * Phase 3. Each process P sub-i independently rotates its n data
	 *	    blocks i steps downward in a cyclical manner.
	 *
	 * Another good description of this algorighm can be found in
	 * the paper by Rajeev Thakur et al, Optimization of Collective
	 * Communication Operations in MPICH.
	 */
	/*
	 * Allocate a temporary buffer for packing and unpacking data.
	 * The temporary buffer must be the same size as the destination.
	 */
	err = det_co_alloc_mr(co, wr->alltoall.dst_ds.length, 0);
	if (unlikely(err))
		return err;

	/*
	 * Do Phase 1 of the algorithim.  Shift the source data blocks
	 * on process i up by a distance of i blocks.  Store the result
	 * in the destination buffer.
	 */
	src_ds.l_key  = wr->alltoall.src_ds.l_key;
	dst_ds.l_key  = wr->alltoall.dst_ds.l_key;

	src_ds.length =
	dst_ds.length = wr->alltoall.nbytes * (co->size - co->rank);

	src_ds.vaddr  = wr->alltoall.src_ds.vaddr +
			wr->alltoall.nbytes * co->rank;
	dst_ds.vaddr  = wr->alltoall.dst_ds.vaddr;

	err = det_local_copy(co, &src_ds, &dst_ds);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_copy_indexing: det_local_copy 1 error %d\n",
			err);
		return err;
	}

	src_ds.length =
	dst_ds.length = wr->alltoall.nbytes * co->rank;

	src_ds.vaddr  = wr->alltoall.src_ds.vaddr;
	dst_ds.vaddr  = wr->alltoall.dst_ds.vaddr +
			wr->alltoall.nbytes * (co->size - co->rank);

	err = det_local_copy(co, &src_ds, &dst_ds);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_copy_indexing: det_local_copy 2 error %d\n",
			err);
		return err;
	}

	/* Input data is now stored in the destination buffer. */

	/*
	 * Now enter Phase 2, the communication phase.  It takes
	 * ceiling(lg p) steps.  In each step i, each process sends
	 * to rank+2^i and receives from rank-2^i, and exchanges
	 * all data blocks whose ith bit is 1.
	 */

	wr->alltoall.pof2 = 1;
	err = det_alltoall_copy_index(co, wr);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_copy_indexing: det_alltoall_copy_index error %d\n",
			err);
		return err;
	}

	return 0;
}


#endif	// DET_USE_DIRECT_INDEXING


static int det_alltoall_sendrecv(struct det_co * const co,
				 struct det_wr * const wr)
{
	struct det_local_ds src_ds, dst_ds;
	int i, dst, err;

	/* Copy the local data. */
	err = det_alltoall_local_copy(co, wr);
	if (unlikely(err))
		return err;

	/* Initialize the static fields. */
	src_ds.l_key  = wr->alltoall.src_ds.l_key;
	src_ds.length = wr->alltoall.nbytes;

	dst_ds.l_key  = wr->alltoall.dst_ds.l_key;
	dst_ds.length = wr->alltoall.nbytes;

	/* Post receives. */
	for (i = 1; i < co->size; i++) {

		dst = (co->rank + i) % co->size;

		dst_ds.vaddr = wr->alltoall.dst_ds.vaddr +
			       wr->alltoall.nbytes * dst;

		err = det_recv(co->qp_array[dst], 0, &dst_ds, 1);
		if (unlikely(err)) {
			printk(KERN_INFO "det_alltoall_sendrecv: det_recv error %d\n",
				err);
			return err;
		}
	}

	/* Post sends. */
	for (i = 1; i < co->size; i++) {

		dst = (co->rank + i) % co->size;

		src_ds.vaddr = wr->alltoall.src_ds.vaddr +
			       wr->alltoall.nbytes * dst;

		err = det_send(co->qp_array[dst], 0, &src_ds, 1,
			       0, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoall_sendrecv: det_send error %d\n",
				err);
			return err;
		}
	}

	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      (co->size - 1) * 2);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_sendrecv: det_next_action error %d\n",
			err);
		return err;
	}

	return 0;
}


static int det_alltoall_exchange(struct det_co * const co,
				 struct det_wr * const wr)
{
#ifdef	DET_TRIGGERED_WR
	struct det_twr trig_wr;
#endif
	struct det_local_ds src_ds, dst_ds;
	int src, dst, err;

	src_ds.l_key  = wr->alltoall.src_ds.l_key;
	src_ds.length = wr->alltoall.nbytes;

	dst_ds.l_key  = wr->alltoall.dst_ds.l_key;
	dst_ds.length = wr->alltoall.nbytes;

#ifdef	DET_TRIGGERED_WR
	/* Setup static trig_wr fields for posting receives. */
	trig_wr.id	 = (unsigned long)wr;
	trig_wr.ds_array = &dst_ds;
	trig_wr.num_ds   = 1;
	trig_wr.type     = DET_WR_RECV;

	while (wr->alltoall.count < co->size) {
#else
	if (wr->alltoall.count < co->size) {
#endif
		if (wr->alltoall.pof2) {
			/* Use exclusive-or algorithm. */
			src =
			dst = co->rank ^ wr->alltoall.count;
		} else {
			src = (co->rank - wr->alltoall.count  + co->size) % co->size;
			dst = (co->rank + wr->alltoall.count) % co->size;
		}

//printk("det_alltoall_exchange: rank %d send to rank %d recv from rank %d\n", co->rank, src, dst);

		src_ds.vaddr = wr->alltoall.src_ds.vaddr +
			       wr->alltoall.nbytes * dst;

#ifdef	DET_TRIGGERED_WR
		if (wr->alltoall.count > 1) {
			/*
			 * Post the previous receive to trigger this send.
			 * Must do this before clobbering the receive ds.
			 */
			err = det_post_twr(&trig_wr, 0, co->qp_array[dst]);
			if (unlikely(err)) {
				printk(KERN_INFO
					"det_alltoall_exchange: det_post_twr error %d\n",
					err);
				return err;
			}
		}

		err = det_trig_send(co->qp_array[dst], (unsigned long)wr,
				    &src_ds, 1,
				    (wr->alltoall.count > 1) ? 1 : 0, NULL);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoall_exchange: det_trig_send error %d\n",
				err);
			return err;
		}

		trig_wr.qp = co->qp_array[src];
#endif
		dst_ds.vaddr = wr->alltoall.dst_ds.vaddr +
			       wr->alltoall.nbytes * src;

		/* Prepare for next pass. */
		wr->alltoall.count++;

#ifndef	DET_TRIGGERED_WR
		err = det_co_sendrecv(co, (unsigned long)wr, dst, src, 1,
			&src_ds, 1, &dst_ds, det_alltoall_pairwise_cb);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoall_exchange: det_co_sendrecv error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoall_exchange: det_complete_co_wr error %d\n", err);
			return err;
		}
	}
#else
	}

	err = det_post_twr(&trig_wr, 0, NULL);
	if (unlikely(err)) {
		printk(KERN_INFO "det_alltoall_exchange: final det_post_twr error %d\n",
			err);
		return err;
	}

	/* Wait for all of the sends plus one receive to complete. */
	err = det_next_action(co, det_co_pollcomplete_cb, DET_CQ_THRESHOLD,
			      wr->alltoall.count);
	if (unlikely(err)) {
		printk(KERN_INFO "det_alltoall_exchange: det_next_action error %d\n",
			err);
		return err;
	}
#endif
	return 0;
}


#ifndef	DET_TRIGGERED_WR
static int det_alltoall_pairwise_cb(struct det_co * const co)
{
	u64 id;
	int err;

	err = det_co_sendrecv_cb(co, &id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_pairwise_cb: det_complete_co_wr error %d\n",
			err);
		return err;
	}

	err = det_alltoall_exchange(co, (struct det_wr *)(unsigned long)id);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_pairwise_cb: det_alltoall_exchange error %d\n",
			err);
		return err;
	}

	return 0;
}
#endif


static int det_alltoall_pairwise(struct det_co * const co,
				 struct det_wr * const wr)
{
	int err;

	/* Copy the local data. */
	err = det_alltoall_local_copy(co, wr);
	if (unlikely(err))
		return err;

	/* Do the pairwise exchanges. */
	wr->alltoall.count = 1;
	wr->alltoall.pof2  = is_pof2(co->size);

	err = det_alltoall_exchange(co, wr);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoall_pairwise: det_alltoall_exchange error %d\n",
			err);
		return err;
	}

	return 0;
}


static int __det_alltoall(struct det_co * const co,
			  struct det_wr * const wr,
			  const struct det_local_ds * const src_ds,
			  const struct det_local_ds * const dst_ds)
{
	int err;

	wr->alltoall.src_ds = *src_ds;
	wr->alltoall.dst_ds = *dst_ds;
	wr->alltoall.nbytes = dst_ds->length / co->size;

//
// TODO add support for Hans-Joachim Plum's recursive-halving/flush algorithm
//

	if ((dst_ds->length < ALLTOALL_SHORT_MSG) &&
	    (co->size >= ALLTOALL_MIN_PROCS)) {
		/*
		 * Use the indexing algorithm by Jehoshua Bruck et al,
		 * IEEE TPDS, Nov. 97
		 */
#ifdef	DET_USE_DIRECT_INDEXING
		/* Direct indexing uses direct data placement. */
		err = det_alltoall_direct_indexing(co, wr);
#else
		/* Copy indexing uses data copies to pack and move data. */
		err = det_alltoall_copy_indexing(co, wr);
#endif

	} else if (dst_ds->length < ALLTOALL_MEDIUM_MSG) {
		/*
		 * Medium-size message or (short messages for co->size less
		 * than ALLTOALL_MIN_PROCS), use send/recv with scattered
		 * destinations.
		 */
		err = det_alltoall_sendrecv(co, wr);
	} else {
		/*
		 * Long message, do a pairwise exchange.
		 */
		err = det_alltoall_pairwise(co, wr);
	}

	if (unlikely(err)) {
		printk(KERN_INFO "__det_alltoall: error %d\n", err);
		return err;
	}

	return 0;
}

/*
 *  Refer to the MPICH MPI_Alltoall code for the algorithm.
 */
int det_alltoall(struct det_co * const co,
		 const __u64 id,
		 const struct det_local_ds * const src_ds,
		 const struct det_local_ds * const dst_ds,
		 const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int err;

	if (unlikely(!dst_ds || (dst_ds->length && (dst_ds->length % co->size))))
		return -EINVAL;

	if (unlikely(!src_ds || (src_ds->length && (src_ds->length % co->size))))
		return -EINVAL;

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_ALLTOALL;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = dst_ds->length;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	err = __det_alltoall(co, wr, src_ds, dst_ds);
	if (unlikely(err)) {
		printk(KERN_INFO "det_alltoall: __det_alltoall error %d\n",
			err);
		return err;
	}

	return 0;
}
EXPORT_SYMBOL(det_alltoall);


/*
 *  Refer to the MPICH MPI_Alltoallv code for the algorithm.
 */
int det_alltoallv(struct det_co * const co,
		  const __u64 id,
		  const struct det_local_ds * const src_ds_array,
		  const struct det_local_ds * const dst_ds_array,
		  const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int i, count, n, err;

	if (unlikely(!src_ds_array || !dst_ds_array))
		return -EINVAL;

	if (unlikely(dst_ds_array[co->rank].length !=
		     src_ds_array[co->rank].length))
		return -EINVAL;

	err = det_reserve_sq_wqe(&co->qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_ALLTOALLV;
	wr->id = id;
	wr->num_ds = 0;
	wr->total_length = 0;
	for (i = 0; i < co->size; i++)
		wr->total_length += dst_ds_array[i].length;
	wr->flags = flags | DET_WR_CO_RESERVED | DET_WR_NO_TIMEOUT;
	wr->msg_id = co->qp.wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	det_append_sq_wqe(&co->qp);

	count = 0;

	for (i = 0; i < co->size; i++) {

		n = (co->rank + i) % co->size;
		if (!dst_ds_array[n].length || (n == co->rank))
			continue;

		err = det_recv(co->qp_array[n], 0, &dst_ds_array[n], 1);
		if (unlikely(err)) {
			printk(KERN_INFO "det_alltoallv: det_recv error %d\n",
				err);
			return err;
		}
		count++;
	}

	for (i = 0; i < co->size; i++) {

		n = (co->rank + i) % co->size;
		if (!src_ds_array[n].length || (n == co->rank))
			continue;

		err = det_send(co->qp_array[n], 0, &src_ds_array[n], 1, 0, 0);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoallv: det_send error %d\n", err);
			return err;
		}
		count++;
	}

	err = det_local_copy(co, &src_ds_array[co->rank],
				 &dst_ds_array[co->rank]);
	if (unlikely(err)) {
		printk(KERN_INFO
			"det_alltoallv: det_local_copy error %d\n", err);
		return err;
	}

	if (count) {
		err = det_next_action(co, det_co_pollcomplete_cb,
				      DET_CQ_THRESHOLD, count);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoallv: det_next_action error %d\n",
				err);
			return err;
		}
	} else {
		err = det_complete_co_wr(co, DET_WS_SUCCESS);
		if (unlikely(err)) {
			printk(KERN_INFO
				"det_alltoallv: det_complete_co_wr error %d\n",
				err);
			return err;
		}
	}

	return 0;
}
EXPORT_SYMBOL(det_alltoallv);


int det_process_broadcast_pkt(struct sk_buff *skb)
{
	union det_pdu *pdu = (union det_pdu *)skb->data;
	struct det_group *grp;
	struct det_co *co;
	int i;

	/* The join request is the only collective broadcast PDU supported. */
	if (det_pdu_base_type(pdu->hdr.opcode) != det_op_join)
		return 0;

	pdu->join.msg_id = NTOH32(pdu->join.msg_id);
	pdu->join.size	 = NTOH32(pdu->join.size);
	pdu->join.root	 = NTOH32(pdu->join.root);

	collective_grp_lock();
	list_for_each_entry(grp, &collective_grp_list, entry) {
		if (grp->tag == pdu->join.tag) {
			if (pdu->join.root > grp->size) {
				printk(
		"det_process_broadcast_pkt: invalid src rank %d size %d\n",
		pdu->join.root, grp->size);
			} else {
				atomic_inc(&grp->refcnt);
			}
			break;
		}
	}
	collective_grp_unlock();
	if (&grp->entry == &collective_grp_list)
		return 0;

	/* Pass this PDU to all local ranks (except the sender). */
	for (i = 0; i < grp->size; i++) {

		if (i == pdu->join.root)
			continue;

		group_lock(&grp->lock);
		co = grp->co[i];
		if (!co) {
			group_unlock(&grp->lock);
			continue;
		}
		atomic_inc(&co->qp.refcnt);
		group_unlock(&grp->lock);

		det_process_join(co, pdu, skb);

		if (atomic_dec_and_test(&co->qp.refcnt))
			complete(&co->qp.done);
	}

	if (atomic_dec_and_test(&grp->refcnt))
		complete(&grp->done);

	return 0;
}
