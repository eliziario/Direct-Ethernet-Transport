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

#define SCHED_CONTINUE		  1
#define SCHED_CONTINUE_RECORD	  0
#define SCHED_BREAK_RECORD	(-1)

int det_validate_ds(const struct det_pd * const pd,
		    const struct det_local_ds *ds_array,
		    struct det_ds *ds,
		    __u32 num_ds,
		    const enum det_access_ctrl access,
		    const int take_ref)
{
	struct det_mr *mr;
	struct det_ds *ds_start = ds;
	int total_length = 0;
	int i = 0;

	while (num_ds--) {
		wiremap_read_lock();
		mr = idr_find(&det_wire_map, ds_array->l_key);
		if (unlikely(!mr			     ||
			     (mr->base.type  != DET_TYPE_MR) ||
			     (mr->attr.l_key != ds_array->l_key))) {
			wiremap_read_unlock();
			total_length = -ENXIO;
			break;
		}
		atomic_inc(&mr->base.refcnt);
		wiremap_read_unlock();

		i++;
		ds->mr = mr;
		ds->in_use = 1;

		if (unlikely(pd != mr->attr.base.pd)) {
			total_length = -EPERM;
			break;
		}
		if (unlikely((ds_array->vaddr < mr->vaddr) ||
			    ((ds_array->vaddr + ds_array->length) >
			     (mr->vaddr + mr->attr.base.length)))) {
//printk("DS %d: ds_array->vaddr %llx ds_array->length %d mr->vaddr %llx mr->attr.base.length %d\n", i, (unsigned long long)ds_array->vaddr, ds_array->length, (unsigned long long)mr->vaddr, mr->attr.base.length);
			total_length = -ERANGE;
			break;
		}
		if (unlikely(!(mr->attr.base.access & access))) {
			total_length = -EACCES;
			break;
		}

		ds->l_key  = ds_array->l_key;
		ds->offset = ds_array->vaddr - mr->vaddr;
		ds->length = ds_array->length;

		total_length += ds_array->length;

		if (unlikely(!take_ref))
			det_clear_ds_ref(ds);

		ds_array++;
		ds++;
	}

	if (unlikely(total_length < 0))
		det_clear_ds_refs(ds_start, i);

	return total_length;
}


int det_send(struct det_qp * const qp,
	     const __u64 id,
	     const struct det_local_ds * const ds_array,
	     const __u32 num_ds,
	     const enum det_wr_flags flags,
	     const __u32 immediate_data)
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

	clk_cnt_update(SEND_BYTES, 0, total_length);

	wr->type = DET_WR_SEND;
	wr->total_length = (u32)total_length;
	wr->id = id;
	wr->flags = flags;
	wr->msg_id = qp->wirestate.sq_tx.next_msg_id++;
	atomic_set(&wr->state, WR_STATE_WAITING);

	wr->send.immediate_data = HTON32(immediate_data);
	wr->num_ds = num_ds;

	det_append_sq_wqe(qp);
	det_schedule(DET_SCHEDULE_NEW, qp);

	return 0;

out:
	det_release_sq_wqe(qp);
	return total_length;
}
EXPORT_SYMBOL(det_send);


int det_recv(struct det_qp * const qp,
	     const __u64 id,
	     const struct det_local_ds * const ds_array,
	     const __u32 num_ds)
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

	det_append_rq_wqe(qp);

	if (qp_is_co_member(qp)) {
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
//printk("Rank %d peek: pdu->msg_id %d wr->msg_id %d, rx->last_in_seq %d pdu->hdr.seq_num %d\n", qp_get_co(qp)->rank, det_get_msg_id(pdu), wr->msg_id, atomic_read(&rx->last_in_seq), pdu->hdr.seq_num);
			if (det_get_msg_id(pdu) != wr->msg_id)
				break;
//printk("Dequeue deferred skb for rank %d QP %d\n", qp_get_co(qp)->rank, qp->attr.local_qp_num);
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
	}

	return 0;
out:
	det_release_rq_wqe(qp);
	return total_length;
}
EXPORT_SYMBOL(det_recv);


int det_read(struct det_qp * const qp,
	     const __u64 id,
	     const struct det_local_ds * const ds_array,
	     const __u32 num_ds,
	     const net64_t remote_address,
	     const net32_t remote_key,
	     const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int total_length, err;

	if (unlikely(!qp->attr.max_or))
		return -ENOBUFS;

	if (unlikely(num_ds > qp->attr.sq_sges))
		return -E2BIG;

	err = det_reserve_sq_wqe(qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	total_length = det_validate_ds(qp->attr.pd, ds_array, wr->ds_array,
					num_ds, DET_AC_LOCAL_WRITE, 1);
	if (unlikely(total_length < 0))
		goto out;

        clk_cnt_update(READ_BYTES, 0, total_length);

	wr->type = DET_WR_RDMA_READ;
	wr->total_length = 0;
	wr->id = id;
	wr->flags = flags;
	wr->msg_id = qp->sq.next_msg_id;
	atomic_set(&wr->state, WR_STATE_WAITING);

	wr->read.remote_address = remote_address;
	wr->read.remote_key = remote_key;
	wr->read.remote_length = HTON32(total_length);

	wr->num_ds = num_ds;

	atomic_inc(&qp->or_posted);

	det_append_sq_wqe(qp);
	det_schedule(DET_SCHEDULE_NEW, qp);
	return 0;

out:
	det_release_sq_wqe(qp);
	return total_length;
}
EXPORT_SYMBOL(det_read);


int det_write(struct det_qp * const qp,
	      const __u64 id,
	      const struct det_local_ds * const ds_array,
	      const __u32 num_ds,
	      const net64_t remote_address,
	      const net32_t remote_key,
	      const enum det_wr_flags flags,
	      const __u32 immediate_data)
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

        clk_cnt_update(WRITE_BYTES, 0, total_length);

	wr->type = DET_WR_RDMA_WRITE;
	wr->total_length = (u32)total_length;
	wr->id = id;
	wr->flags = flags;
	atomic_set(&wr->state, WR_STATE_WAITING);

	if (flags & DET_WR_IMMEDIATE) {
		wr->msg_id = qp->wirestate.sq_tx.next_msg_id++;
		wr->write.immediate_data = HTON32(immediate_data);
	} else {
		wr->msg_id = 0;
	}

	wr->write.remote_address = remote_address;
	wr->write.remote_key = remote_key;

	wr->num_ds = num_ds;

	det_append_sq_wqe(qp);
	det_schedule(DET_SCHEDULE_NEW, qp);
	return 0;

out:
	det_release_sq_wqe(qp);
	return total_length;
}
EXPORT_SYMBOL(det_write);


int det_bind(struct det_qp * const qp,
	     const __u64 id,
	     struct det_mw * const mw,
	     struct det_mr * const mr,
	     net32_t * const r_key,
	     const __u64 vaddr,
	     const __u32 length,
	     const enum det_access_ctrl access,
	     const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int err;

	/* The QP and MW must belong to the same PD. */
	if (unlikely(qp->attr.pd != mw->attr.base.pd))
		return -EPERM;

	err = det_bind_mw(mw, mr, r_key, vaddr, length, access);
	if (unlikely(err))
		return err;

	err = det_reserve_sq_wqe(qp, &wr);
	if (unlikely(err))
		return err;

	wr->type = DET_WR_BIND;
	wr->total_length = 0;
	wr->id = id;
	wr->flags = flags;
	wr->msg_id = 0;	/* Bind is local - do not adjust wirestate. */

	/* Completed above by det_bind_mw(). */
	atomic_set(&wr->state, WR_STATE_COMPLETED);

	/* No need to fill these out since they are not used:
	wr->bind.mw = mw;
	wr->bind.mr = mr;
	wr->bind.r_key = r_key;
	wr->bind.vaddr = vaddr;
	wr->bind.length = length;
	wr->bind.access = access;
	*/
	wr->num_ds = 0;

	det_append_sq_wqe(qp);
	det_schedule(DET_SCHEDULE_NEW, qp);
	return 0;
}
EXPORT_SYMBOL(det_bind);


int det_comp_exch(struct det_qp * const qp,
		  const __u64 id,
		  const __u64 comp_operand,
		  const __u64 exch_operand,
		  const struct det_local_ds * const local_ds,
		  const net64_t remote_address,
		  const net32_t remote_key,
		  const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int total_length, err;

	if (unlikely(!qp->attr.max_or))
		return -ENOBUFS;

	if (unlikely(local_ds->length < sizeof(u64)))
		return -EOVERFLOW;

	err = det_reserve_sq_wqe(qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	total_length = det_validate_ds(qp->attr.pd, local_ds, wr->ds_array,
					1, DET_AC_LOCAL_WRITE, 1);
	if (unlikely(total_length < 0))
		goto out;

	wr->type = DET_WR_ATOMIC_COMP_EXCH;
	wr->total_length = 0;
	wr->id = id;
	wr->flags = flags;
	wr->msg_id = qp->sq.next_msg_id;
	atomic_set(&wr->state, WR_STATE_WAITING);

	wr->comp_exch.comp_operand = HTON64(comp_operand);
	wr->comp_exch.exch_operand = HTON64(exch_operand);
	wr->comp_exch.remote_address = remote_address;
	wr->comp_exch.remote_key = remote_key;

	wr->num_ds = 1;

	atomic_inc(&qp->or_posted);

	det_append_sq_wqe(qp);
	det_schedule(DET_SCHEDULE_NEW, qp);
	return 0;

out:
	det_release_sq_wqe(qp);
	return total_length;
}
EXPORT_SYMBOL(det_comp_exch);


int det_fetch_add(struct det_qp * const qp,
		  const __u64 id,
		  const __u64 add_operand,
		  const struct det_local_ds * const local_ds,
		  const net64_t remote_address,
		  const net32_t remote_key,
		  const enum det_wr_flags flags)
{
	struct det_wr *uninitialized_var(wr);
	int total_length, err;

	if (unlikely(!qp->attr.max_or))
		return -ENOBUFS;

	if (unlikely(local_ds->length < sizeof(u64)))
		return -EOVERFLOW;

	err = det_reserve_sq_wqe(qp, &wr);
	if (unlikely(err))
		return err;

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	total_length = det_validate_ds(qp->attr.pd, local_ds, wr->ds_array,
					1, DET_AC_LOCAL_WRITE, 1);
	if (unlikely(total_length < 0))
		goto out;

	wr->type = DET_WR_ATOMIC_FETCH_ADD;
	wr->total_length = 0;
	wr->id = id;
	wr->flags = flags;
	wr->msg_id = qp->sq.next_msg_id;
	atomic_set(&wr->state, WR_STATE_WAITING);

	wr->fetch_add.add_operand = HTON64(add_operand);
	wr->fetch_add.remote_address = remote_address;
	wr->fetch_add.remote_key = remote_key;

	wr->num_ds = 1;

	atomic_inc(&qp->or_posted);

	det_append_sq_wqe(qp);
	det_schedule(DET_SCHEDULE_NEW, qp);
	return 0;

out:
	det_release_sq_wqe(qp);
	return total_length;
}
EXPORT_SYMBOL(det_fetch_add);

#ifndef	CONFIG_DET_LOOPBACK

static int det_schedule_wq(struct det_qp * const qp,
			   struct det_wq * const wq,
			   struct det_tx_state * const tx,
			   int max_send,
			   int * const total)
{
	struct det_wr *wr;
	int sent, index, err;

	*total = 0;
	sent = 0;
	err = 0;

	while ((wq->next_active_wr != wq->tail) && det_tx_window(tx) && max_send) {

		index = wq->next_active_wr;
		wr = det_get_wr(wq, index);

#ifdef	DET_TRIGGERED_WR
		if (wr->trigger) {
			if (wr->trigger > 0) {
				wr->trigger = -wr->trigger;
				atomic_add(wr->trigger, &wq->gate);
			}
			if (atomic_read(&wq->gate) < 0)
				break;	/* Suspended */
		}
#endif
		/*
		 *  Ack processing can reschedule a WR that is in retry; only
		 *  process it if we are all caught up.  Also, do not start a
		 *  fenced WR until all prior RDMA read and atomic operations
		 *  have completed.
		 */
		if ((wr->sar.seg.timeout_cnt && det_tx_unacked_window(tx)) ||
		    ((wr->flags & DET_WR_FENCED) && atomic_read(&qp->or_depth) &&
		     (atomic_read(&wr->state) == WR_STATE_WAITING)))
			break;

		switch (wr->type) {
			case DET_WR_RDMA_READ:
			case DET_WR_ATOMIC_COMP_EXCH:
			case DET_WR_ATOMIC_FETCH_ADD:
				/*
				 *  Throttle IQ stream requests if needed. Exit
				 *  loop to keep sequence numbers sequencial.
				 */
				if (atomic_read(&wr->state) == WR_STATE_WAITING) {
					if (atomic_read(&qp->or_depth) == qp->attr.max_or)
						goto done;

					atomic_inc(&qp->or_depth);
				}

				/* fall through */
			case DET_WR_SEND:
			case DET_WR_RDMA_WRITE:
			case DET_WR_RDMA_READ_RESP:
			case DET_WR_ATOMIC_RESP:
			case DET_WR_JOIN:
			case DET_WR_BARRIER:
			case DET_WR_BCAST:
			case DET_WR_SCATTER:
			case DET_WR_SCATTERV:
			case DET_WR_GATHER:
			case DET_WR_GATHERV:
			case DET_WR_ALLGATHER:
			case DET_WR_ALLGATHERV:
			case DET_WR_ALLTOALL:
			case DET_WR_ALLTOALLV:
				sent = det_xmit_wr(
					qp, wq, wr,
					min((u32)max_send, det_tx_window(tx)),
					0,
					atomic_read(&tx->next_seq),
					&tx->next_seq);
				break;
			case DET_WR_BIND:
			{
				err = det_process_sq_completions(qp, wq);
				if (unlikely(err))
					return err;
				/*
				 * We normally drop the wq lock before
				 * notifying the CQ.  The bind operation
				 * breaks that convention.
				 */
				det_notify_cq(qp->attr.sq_cq);
				wq->next_active_wr = (wq->next_active_wr + 1) % wq->size;
				sent = 0;
				break;
			}
			case DET_WR_RECV:
			default:
				printk(KERN_ERR
		"DET scheduler botch: found wr type %d on scheduler queue\n",
					wr->type);
				return DET_AE_QP_FATAL;
		}

		/*
		 *  If an IQ stream request did not get started, need to
		 *  back off or_depth.
		 */
		if ((atomic_read(&wr->state) == WR_STATE_WAITING) &&
		    ((wr->type == DET_WR_RDMA_READ) ||
		     (wr->type == DET_WR_ATOMIC_COMP_EXCH) ||
		     (wr->type == DET_WR_ATOMIC_FETCH_ADD))) {

			atomic_dec(&qp->or_depth);
		}

		if (sent < 0) {
			/* return a nagative total */
			*total = -1;
			break;
		}

		/* adjust next tx sequence numuber and totals */
		*total += sent;
		max_send -= sent;

		/*
		 *  TX engine bumps next_active when finished sending a
		 *  whole WR.  Bail if he didn't this time around.
		 */
		if (wq->next_active_wr == index)
			break;
	}
done:
	return err;
}


static int det_schedule_timeout_wq(struct det_qp * const qp,
				   struct det_wq * const wq,
				   struct det_tx_state * const tx,
				   const int max_send,
				   int * const sent)
{
	struct det_wr *wr;
	u32 target, from;

	*sent = 0;

	/*  Don't bother processing a zero length queue */
	if (wq->size == 0)
		goto done;

	/*
	 *  If queue is empty, there's nothing to retry
	 */
	target = (wq->head + wq->completion_cnt) % wq->size;
	if (target == wq->tail)
		goto done;

	/*
	 *  If this work request hasn't been started, we're done
	 */
	wr = det_get_wr(wq, target);
	if (atomic_read(&wr->state) == WR_STATE_WAITING) {
		/*
		 *  Check to see if this queue has backlogged work
		 */
		if (target == wq->next_active_wr)
			return det_schedule_wq(qp, wq, tx, max_send, sent);
		goto done;
	}

	/*
	 *  Do a sanity check
	 */
	if (unlikely((wr->type == DET_WR_RECV) || (wr->type == DET_WR_BIND))) {
		printk(KERN_ERR
	"DET scheduler timeout botch: found wr type %d on scheduler queue\n",
			wr->type);
		return DET_AE_QP_FATAL;
	}

	/*
	 *  If this is a request/response type which has had the request
	 *  acked, check that inbound progress is still being made.
	 */
	if (atomic_read(&wr->state) == WR_STATE_WAITING_FOR_RESP) {
		if (wr->sar.rea.last_seen_seq == tx->last_timeout_seq) {
			wr->sar.seg.timeout_cnt++;
			if (wr->sar.seg.timeout_cnt > det_max_retries) {
				printk(KERN_NOTICE
			"DET reply timed out: type=%d last=%d state=%d\n",
						wr->type,
						wr->sar.rea.last_seen_seq,
						atomic_read(&wr->state));
				return DET_AE_ACK_TIMEOUT;
			}
		} else {
			det_reset_timeout(wr);
		}
		tx->last_timeout_seq = wr->sar.rea.last_seen_seq;
		goto ack;
	}

	/*
	 *  If we're all caught up or making progress, leave retry state
	 */
	if ((det_tx_unacked_window(tx) == 0) ||
	    (atomic_read(&tx->last_ack_seq_recvd) != tx->last_timeout_seq)) {
		det_reset_timeout(wr);
		goto done;
	}

	wr->sar.seg.timeout_cnt++;
	if (!(wr->flags & DET_WR_NO_TIMEOUT) &&
	     (wr->sar.seg.timeout_cnt > det_max_retries)) {
		/*
		 *  Maximum retries
		 */
		printk(KERN_NOTICE
	"DET reties exhausted: type=%d last=%d next=%d win=%d state=%d\n",
			wr->type,
			atomic_read(&tx->last_ack_seq_recvd),
			wr->sar.seg.next_seq,
			det_tx_unacked_window(tx),
			atomic_read(&wr->state));
		return DET_AE_ACK_TIMEOUT;
	}

	/*
	 *  If it's not time for a retry, we're done
	 */
	if (wr->sar.seg.timeout_cnt != wr->sar.seg.timeout_trigger)
		goto done;

	/* geometric back-off */
	wr->sar.seg.timeout_trigger *= 2;
	if ((wr->flags & DET_WR_NO_TIMEOUT) &&
	    (wr->sar.seg.timeout_trigger > MAX_DET_TIMER_PERIOD)) {
		wr->sar.seg.timeout_trigger = MAX_DET_TIMER_PERIOD;
		wr->sar.seg.timeout_cnt = 0;
	}

	from = atomic_read(&tx->last_ack_seq_recvd) + 1;
	*sent = det_xmit_wr(qp, wq, wr, 1, 1, from, &wr->sar.seg.last_timeout_seq_sent);
	DET_STAT(timeouts++);

	/*
	 *  To reduce the number of possible redundant PDU transmits,
	 *  we only retransmit one wr per timeout. The thought being
	 *  that a large sequencial block of PDUs are rarely lost.
	 *
	 *  If we decide to change that assumption, the
	 *  det_tx_unacked_window macro might have to change and we
	 *  can't use last_ack_seq_recvd for each call to det_xmit_wr()
	 */
done:
	tx->last_timeout_seq = atomic_read(&tx->last_ack_seq_recvd);
ack:
	/*
	 * Acknowledge any receive side window on this QP.
	 */
	if (det_timer_ack &&
	    (det_rx_window(&qp->wirestate.sq_rx) ||
	     det_rx_window(&qp->wirestate.iq_rx))) {
		det_send_ack(qp);
		DET_STAT(timer_acks++);
	}

	return 0;
}


static int det_schedule_retry_wq(struct det_qp * const qp,
				 struct det_wq * const wq,
				 const struct det_tx_state * const tx,
				 const int max_send,
				 int * const sent)
{
	struct det_wr *wr;
	u32 target, window, from, edge;

	*sent = 0;

	/*  Don't bother processing a zero length queue */
	if (wq->size == 0)
		return 0;

	/*
	 *  If queue is empty, there's nothing to retry
	 */
	target = (wq->head + wq->completion_cnt) % wq->size;
	if (target == wq->tail)
		return 0;

	/*
	 *  If this work request hasn't been started, we're done
	 */
	wr = det_get_wr(wq, target);
	if (atomic_read(&wr->state) == WR_STATE_WAITING)
		return 0;

	/*
	 *  Do a sanity check
	 */
	if (unlikely((wr->type == DET_WR_RECV) || (wr->type == DET_WR_BIND))) {
		printk(KERN_ERR
	"DET scheduler retry botch: found wr type %d on scheduler queue\n",
			wr->type);
		return DET_AE_QP_FATAL;
	}

	/*
	 *  The snack edge must be within or after this wr as well as
	 *  after the last received ack.
	 */
	from = atomic_read(&tx->last_ack_seq_recvd) + 1;
	edge = atomic_read(&tx->snack_edge);
	if (seq_before(edge, wr->sar.seg.starting_seq) || seq_before(edge, from))
	    return 0;

	window = min((u32)max_send, det_seq_window(from, edge));
	*sent = det_xmit_wr(qp, wq, wr, window, 1, from, NULL);

	return 0;
}

static int det_schedule_qp(struct det_qp * const qp,
			   const enum det_schedule_op op)
{
	int sq_total, iq_total, sent, err, max_send, result;

	/* Ignore loopback QPs that may be scheduled by retry processing. */
	if (qp->loopback)
		return SCHED_CONTINUE;

	err = 0;
	sent = 0;
	result = SCHED_CONTINUE;

	if (!(max_send = atomic_read(&qp->scheduler->available)))
		return SCHED_BREAK_RECORD;


	if (qp->attr.max_ir) {
		iq_total = max_send / 2;
		sq_total = max_send - iq_total;
		if (!iq_total)
			result = SCHED_BREAK_RECORD;
	} else {
		iq_total = 0;
		sq_total = max_send;
	}

	if (det_sched_type == DET_SCHED_BLOCKING) {
		sq_lock_bh(&qp->sq.lock);
		goto sched_sq;
	} else if (sq_trylock_bh(&qp->sq.lock)) {
sched_sq:
		if (op == DET_SCHEDULE_RETRY)
			err = det_schedule_retry_wq(qp,
						    &qp->sq,
						    &qp->wirestate.sq_tx,
						    sq_total,
						    &sent);
		else if (op == DET_SCHEDULE_NEW)
			err = det_schedule_wq(qp,
					      &qp->sq,
					      &qp->wirestate.sq_tx,
					      sq_total,
					      &sent);
		else if (op == DET_SCHEDULE_TIMEOUT)
			err = det_schedule_timeout_wq(qp,
						      &qp->sq,
						      &qp->wirestate.sq_tx,
						      sq_total,
						      &sent);
		sq_unlock_bh(&qp->sq.lock);

		if (unlikely(err))
			goto out;

		if (sent < 0)
			return SCHED_BREAK_RECORD;
	} else {
		result = SCHED_CONTINUE_RECORD;
	}

	if (!qp->attr.max_ir)
		return result;

	iq_total += sq_total - sent;
	if (!iq_total)
		return result;

	if (det_sched_type == DET_SCHED_BLOCKING) {
		iq_lock_bh(&qp->iq.lock);
		goto sched_iq;
	} else if (iq_trylock_bh(&qp->iq.lock)) {
sched_iq:
		if (op == DET_SCHEDULE_RETRY)
			err = det_schedule_retry_wq(qp,
						    &qp->iq,
						    &qp->wirestate.iq_tx,
						    iq_total,
						    &sent);
		else if (op == DET_SCHEDULE_NEW)
			err = det_schedule_wq(qp,
					      &qp->iq,
					      &qp->wirestate.iq_tx,
					      iq_total,
					      &sent);
		else if (op == DET_SCHEDULE_TIMEOUT)
			err = det_schedule_timeout_wq(qp,
						      &qp->iq,
						      &qp->wirestate.iq_tx,
						      iq_total,
						      &sent);
		iq_unlock_bh(&qp->iq.lock);

		if (unlikely(err))
			goto out;
		if (sent < 0)
			return SCHED_BREAK_RECORD;
	} else {
		result = SCHED_CONTINUE_RECORD;
	}
	return result;

out:
	det_qp_internal_disconnect(qp, err);
	return SCHED_BREAK_RECORD;
}


/*
 * The det_schedule_op parameter defines the void *arg pointer type.
 * If det_schedule_op is DET_SCHEDULE_TIMEOUT then *arg is assumed
 * to be a struct det_scheduler * pointer, otherwise it is assumed
 * to be a struct det_qp * pointer.
 */
void det_schedule(enum det_schedule_op op,
		  const void * const arg)
{
	struct det_qp *qp;
	struct det_scheduler *scheduler;
	struct list_head processed;
	int result, loop_safety;

	switch(op) {
		case DET_SCHEDULE_NEW:
			qp = (struct det_qp *)arg;
			if (qp->loopback)
				return det_loopback_sq(qp);
			scheduler = qp->scheduler;
			break;
		case DET_SCHEDULE_RETRY:
			qp = (struct det_qp *)arg;
			scheduler = qp->scheduler;
			break;
		case DET_SCHEDULE_TIMEOUT:
			qp = NULL;
			scheduler = (struct det_scheduler *)arg;
			break;
		default:
			assert(0);
			return;
	}

	/*
	 *  Order of evaluation is important.  Must check stopped before
	 *  dec_and_test
	 */
	if (atomic_read(&scheduler->stopped)) {
		op == DET_SCHEDULE_TIMEOUT ? atomic_inc(&scheduler->was_timeout) :
		op == DET_SCHEDULE_NEW     ? atomic_inc(&scheduler->was_new)	 :
					     atomic_inc(&scheduler->was_retry);
		return;
	}

	loop_safety = 0;

	/*
	 *  If there is no work currently scheduled, and this is not
	 *  timeout scheduling, go directly to scheduling this qp.
	 */
	if (qp && (op != DET_SCHEDULE_TIMEOUT)) {
		result = det_schedule_qp(qp, op);
		if (result == SCHED_BREAK_RECORD)
			goto out;
		goto done;
	}

reschedule:

#ifdef foo
	if (loop_safety > 50) {
		printk("scheduler loops exceeded: %d\n", loop_safety);
		return;
	}
#endif

	/*
	 *  Bail if the scheduler is busy.
	 */
	if (!sched_obj_trylock(&scheduler->lock))
		goto out;

	/*
	 *  Iterate all qp's on this NIC.  As a qp is serviced, move it
	 *  to the processed list.  When we exhaust our pool of skbs 
	 *  or we've gone through all qp's, put the processed qp's at the
	 *  end of the scheduler list.
	 */
	INIT_LIST_HEAD(&processed);
	while (!list_empty(&scheduler->qp_list)) {
		qp = list_entry(scheduler->qp_list.next, typeof(*qp),
				scheduler_entry);

		result = det_schedule_qp(qp, op);
		if (result == SCHED_BREAK_RECORD) {
			DET_STAT(sched_exhaust++);

			list_splice(&processed, scheduler->qp_list.prev);
			sched_obj_unlock(&scheduler->lock);
			goto out;

		}
		if (result == SCHED_CONTINUE_RECORD) {
			op == DET_SCHEDULE_TIMEOUT ? atomic_inc(&scheduler->was_timeout) :
			op == DET_SCHEDULE_NEW     ? atomic_inc(&scheduler->was_new)	 :
						     atomic_inc(&scheduler->was_retry);
		}

		list_move_tail(&qp->scheduler_entry, &processed);
	}
	list_splice(&processed, scheduler->qp_list.prev);

	sched_obj_unlock(&scheduler->lock);

	loop_safety++;

	/*
	 *  If someone was prevented from scheduling work, run it again.
	 */
done:
	qp = NULL;	/* qp is no longer valid */
	if (atomic_read(&scheduler->was_retry)) {
		atomic_set(&scheduler->was_retry, 0);
		op = DET_SCHEDULE_RETRY;
		goto reschedule;
	} else if (atomic_read(&scheduler->was_new)) {
		atomic_set(&scheduler->was_new, 0);
		op = DET_SCHEDULE_NEW;
		goto reschedule;
	} else if (atomic_read(&scheduler->was_timeout)) {
		/*
		 *  We want to make sure that we don't make timeout
		 *  scheduler passes more than once a timeout period.
		 */
		atomic_set(&scheduler->was_timeout, 0);
		if (op != DET_SCHEDULE_TIMEOUT) {
			op = DET_SCHEDULE_TIMEOUT;
			goto reschedule;
		}
	}

	return;
out:
	/*
	 *  Note the scheduler operation type.
	 */
	op == DET_SCHEDULE_TIMEOUT ? atomic_inc(&scheduler->was_timeout) :
	op == DET_SCHEDULE_NEW     ? atomic_inc(&scheduler->was_new)	 :
				     atomic_inc(&scheduler->was_retry);
	return;
}

#endif	/* CONFIG_DET_LOOPBACK */
