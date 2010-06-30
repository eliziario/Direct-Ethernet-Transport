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

#include <linux/proc_fs.h>
#include <asm/delay.h>
#include "det_driver.h"

#if	BITS_PER_LONG == 32
#define U64 "ll"
#define U64_PRINT_TYPE	unsigned  long long
#define PVAL U64
#define PERF_CNTR_DIV(n, d)	(DET_CNTR)div_long_long_rem( n, d, &junk )
long junk;

#elif	BITS_PER_LONG == 64
#define U64 "l"
#define U64_PRINT_TYPE	unsigned  long
#define PVAL U64
#define PERF_CNTR_DIV(n, d) (n / d)
#else
#error	BITS_PER_LONG is not defined as 32 or 64
#endif

#ifdef DET_STATS
struct det_stats det_statistics;
#define PERF_MIN(i)	DET_STAT(timings[i].min) == -1 ? 0 : \
			DET_STAT(timings[i].min)
#define PERF_MAX(i)	DET_STAT(timings[i].max)
#define PERF_CNT(i)	DET_STAT(timings[i].cnt)
#define PERF_AVG(i)	DET_STAT(timings[i].cnt) ? \
				PERF_CNTR_DIV(DET_STAT(timings[i].total), \
					      DET_STAT(timings[i].cnt)) : 0
#endif

#ifdef	CONFIG_PROC_FS

static char *indents[] = {
"",
"   ",
"      ",
"         ",
"            ",
"               ",
"                  ",
"                     "
};

static char *wr_type2str[] = {
	"INVALID",
	"SEND",
	"WRITE",
	"READ",
	"CMP_EXCH",
	"FETCH_ADD",
	"RECV",
	"BIND",
	"JOIN",
	"BARRIER",
	"BCAST",
	"SCATTER",
	"SCATTERV",
	"GATHER",
	"GATHERV",
	"ALLGATHER",
	"ALLGATHERV",
	"ALLTOALL",
	"ALLTOALLV",
	"READ_RESP",
	"ATOMIC_RESP"
};

static char *wr_state2str[] = {
	"WAITING",
	"STARTED",
	"WAITING FOR ACK",
	"WAITING FOR RESP",
	"LAST SEEN",
	"COMPLETED"
};

static char *wc_status2str[] = {
	"SUCCESS",
	"FLUSHED",
	"EXCEEDED",
	"PROTECTION ERR",
	"BOUNDS ERR",
	"ACCESS ERR",
	"WRAP ERR"
};

static char *qp_state2str[] = {
	"IDLE",
	"CONNECTED",
	"DISCONNECTED",
	"ERROR"
};

static struct proc_dir_entry *proc_net_det = NULL;


#define get_wr_type(n)						\
	(((n) > sizeof(wr_type2str)/sizeof(char *)) ?		\
		"INVALID" : wr_type2str[(n)])
#define get_wr_state(n)						\
	(((n) > sizeof(wr_state2str)/sizeof(char *)) ?		\
		"INVALID" : wr_state2str[(n)])
#define get_ds_type(n)						\
	(((n) == DET_TYPE_MR) ?					\
		"MR" : (((n) == DET_TYPE_MW) ? "MW" : "INVALID TYPE"))
#define get_cq_state(n)						\
	(((n) == DET_CQ_READY) ?				\
		"READY" : (((n) == DET_CQ_ERROR) ? "ERROR" : "INVALID STATE"))
#define get_wc_status(n)					\
	(((n) > sizeof(wc_status2str)/sizeof(char *)) ?		\
		"INVALID" : wc_status2str[(n)])
#define get_qp_state(n)						\
	(((n) > sizeof(qp_state2str)/sizeof(char *)) ?		\
		"INVALID" : qp_state2str[(n)])

static int my_delay_trylock(det_spinlock_t *lock)
{
	int i;
	for (i = 0; i < 1000; i++) {
		if (det_spin_trylock_bh(lock))
			return 1;
		udelay(100);
	}
	return 0;
}

static void my_unlock(det_spinlock_t *lock)
{
	det_unlock_bh(lock);
}

/*
 * Dump a WR SAR by type.
 */
static int dump_sar(const struct det_sar_state * const sar,
		    const enum det_wr_type type,
		    const int indent)
{
	int l = 0;

	l += printk(KERN_INFO "%sREA: cur_ds %p cur_off %-6d "
		"last_seen_seq %-7d last_packet_seq %d final_len %d "
		"opcode %04x immed_data %d\n",
		indents[indent],
		sar->rea.current_ds,
		sar->rea.current_ds_offset,
		sar->rea.last_seen_seq,
		sar->rea.last_packet_seq,
		sar->rea.final_length,
		sar->rea.opcode,
		sar->rea.immediate_data);
	l += printk(KERN_INFO "%sSEG: cur_mr %p   "
		"cur_ds %p cur_pg_index %-3d cur_pg_off %-4d "
		"wr_len_remain %-6d ds_len_reamin %-6d\n",
		indents[indent],
		sar->seg.current_mr,
		sar->seg.current_ds,
		sar->seg.current_page_index,
		sar->seg.current_page_offset,
		sar->seg.wr_length_remaining,
		sar->seg.ds_length_remaining);
	l += printk(KERN_INFO "%s     start_seq %-7d end_seq %-7d "
		"next_seq %-7d timeout_cnt %-3d timeout_trigger %d\n",
		indents[indent],
		sar->seg.starting_seq,
		sar->seg.ending_seq,
		sar->seg.next_seq,
		sar->seg.timeout_cnt,
		sar->seg.timeout_trigger);
	return l;
}


/*
 * Dump TX wirestate.
 */
static int dump_tx_state(char * const name,
			 const struct det_tx_state * const tx,
			 const int indent)
{
	int l = 0;

	l += printk(KERN_INFO
		"%s%s next_seq %-7d    "
		"last_ack_seq_recvd %-7d    "
		"last_timeout_seq %-7d      "
		"next_msg_id %-7d\n",
		indents[indent],
		name,
		atomic_read(&tx->next_seq),
		atomic_read(&tx->last_ack_seq_recvd),
		tx->last_timeout_seq,
		tx->next_msg_id);

	return l;
}


/*
 * Dump RX wirestate.
 */
static int dump_rx_state(char * const name,
			 const struct det_rx_state * const rx,
			 const int indent)
{
	int l = 0;

	l += printk(KERN_INFO
		"%s%s last_in_seq %-7d last_acked %-7d\n",
		indents[indent],
		name,
		atomic_read(&rx->last_in_seq),
		rx->last_seq_acked);

	l += printk(KERN_INFO
		"%s      first_snack %-7d last_snack %-7d snacked %d\n",
		indents[indent],
		rx->first_snack_seq,
		rx->last_snack_seq,
		rx->snacked);
	
	return l;
}


/*
 * Dump QP wirestate.
 */
static int dump_wirestate(const struct det_wirestate * const ws,
			  const int indent)
{
	int l = 0;

	l += dump_tx_state("SQ_TX", &ws->sq_tx, indent);
	l += dump_rx_state("SQ_RX", &ws->sq_rx, indent);
	l += dump_tx_state("IQ_TX", &ws->iq_tx, indent);
	l += dump_rx_state("IQ_RX", &ws->iq_rx, indent);

	return l;
}


/*
 * Dump a DS.
 */
static int dump_ds(struct det_ds *ds,
		   int num,
		   const int indent)
{
	int l = 0;

	while (num--) {
		l += printk(KERN_INFO "%sDS %p: %s id %x refcnt %d "
			"off %-7d len %-7d l_key %08x in_use %d\n",
			indents[indent],
			ds,
			get_ds_type(ds->mr->base.type),
			ds->mr->base.id,
			atomic_read(&ds->mr->base.refcnt),
			ds->offset,
			ds->length,
			ds->l_key,
			ds->in_use);
		ds++;
	}

	return l;
}


/*
 * Dump a WR.
 */
static int dump_wr(struct det_wr * const wr,
		   const int verbose,
		   const int indent)
{
	int l = 0;

	l += printk(KERN_INFO
		"%sWR %p: %s - %s total_len=%-7d id=%"U64"x flags=%x "
		"num_ds=%d msg_id=%d"
#ifdef DET_TRIGGERED_WR
		" trigger=%d signal=%p" 
#endif
		"\n",
		indents[indent],
		wr,
		get_wr_type(wr->type),
		get_wr_state(atomic_read(&wr->state)),
		wr->total_length,
		(U64_PRINT_TYPE)wr->id,
		wr->flags,
		wr->num_ds,
		wr->msg_id
#ifdef DET_TRIGGERED_WR
		, wr->trigger,
		wr->signal
#endif
		);

	l += dump_sar(&wr->sar, wr->type, indent+1);
	if (verbose)
		l += dump_ds(wr->ds_array, wr->num_ds, indent+1);

	return l;
}


/*
 * Dump all WQs and all uncompleted WRs.
 */
static int dump_wq(struct det_wq * const wq,
		   char * const qname,
		   const int verbose,
		   const int indent)
{
	int i;
	int l = 0;

	l += printk(KERN_INFO
		"%s%s: head %-5d tail %-5d depth %-5d size "
		"%-5d compl_cnt %-5d reap_cnt %-5d next_active %-5d"
#ifdef DET_TRIGGERED_WR
		" gate %d"
#endif
		"\n",
		indents[indent],
		qname,
		wq->head,
		wq->tail,
		wq->depth,
		wq->size,
		wq->completion_cnt,
		wq->reap_cnt,
		wq->next_active_wr
#ifdef DET_TRIGGERED_WR
		, atomic_read(&wq->gate)
#endif
		);

	if (wq->size == 0)
		return l;

	i = (verbose) ? wq->head : (wq->head + wq->completion_cnt) % wq->size;

	while (i != wq->tail) {
		l += dump_wr(det_get_wr(wq, i), verbose, indent+1);
		i = (i + 1) % wq->size;
	}

	return l;
}


/*
 * Dump a WC.
 */
static int dump_wc(struct det_wc * const wc,
		   const int indent)
{
	int l = 0;

	l += printk(KERN_INFO
		"%s WQE: %s %s flags 0x%x reap_cnt %d length %d "
		"immed_data 0x%x id %"U64"x\n",
		indents[indent],
		get_wr_type(wc->type)/*same as wr types*/,
		get_wc_status(wc->status),
		wc->flags,
		wc->reap_cnt,
		wc->length,
		wc->immediate_data,
		(U64_PRINT_TYPE)wc->id);

	return l;
}


/*
 * Dump a CQ.
 */
static int dump_cq(struct det_cq * const cq,
		   char * const name,
		   const int indent)
{
	int i, l = 0;

	l += printk(KERN_INFO
		"%s%s %p: %s head %-5d tail %-5d depth %-5d size "
		"%-5d arm 0x%x threshold %d id %x valid %d refcnt %d\n",
		indents[indent],
		name,
		cq,
		get_cq_state(cq->attr.state),
		cq->head,
		cq->tail,
		atomic_read(&cq->depth),
		cq->attr.size,
		cq->attr.arm,
		cq->attr.threshold,
		cq->id,
		cq->valid,
		atomic_read(&cq->refcnt));

	if (cq->attr.size == 0)
		return l;

	for (i = cq->head; i != cq->tail; i = (i + 1) % cq->attr.size)
		l += dump_wc(&cq->wc_array[i], indent+1);

	return l;
}


/*
 * Dump a QP.
 */
static int dump_qp(struct det_qp * const qp,
		   const int indent)
{
	int l = 0;

	qp_lock_bh(&qp->lock); /* Prevents changing QP state */

	l += printk(KERN_INFO
		"%sQP %p %s loc_qp_num %x rem_qp_num %x "
		"(%02x:%02x:%02x:%02x:%02x:%02x) loopback %d co %p\n",
		indents[indent],
		qp,
		get_qp_state(qp->attr.state),
		qp->attr.local_qp_num,
		qp->attr.remote_qp_num,
		qp->attr.remote_mac.addr[0],
		qp->attr.remote_mac.addr[1],
		qp->attr.remote_mac.addr[2],
		qp->attr.remote_mac.addr[3],
		qp->attr.remote_mac.addr[4],
		qp->attr.remote_mac.addr[5],
		qp->loopback,
		qp->co);

	qp_unlock_bh(&qp->lock);

	l += printk(KERN_INFO
		"%s---------- Wirestate -----------\n", indents[indent]);
	l += dump_wirestate(&qp->wirestate, indent+1);

	l += printk(KERN_INFO
		"%s---------- Work Queues -----------\n", indents[indent]);
	if (unlikely(atomic_read(&qp->resize))) {
		l += printk(KERN_INFO
			"%sQP is being resized - cannot access work queues\n",
			indents[indent+1]);
	} else {
		l += printk(KERN_INFO "%s(or_posted %d or_depth %d max_or %d)\n",
			indents[indent+1],
			atomic_read(&qp->or_posted),
			atomic_read(&qp->or_depth),
			qp->attr.max_or);

		sq_lock_bh(&qp->sq.lock);
		l += dump_wq(&qp->sq, "SQ", 0, indent+1);
		sq_unlock_bh(&qp->sq.lock);

		rq_lock_bh(&qp->rq.lock);
		l += dump_wq(&qp->rq, "RQ", 0, indent+1);
		rq_unlock_bh(&qp->rq.lock);

		iq_lock_bh(&qp->iq.lock);
		l += dump_wq(&qp->iq, "IQ", 0, indent+1);
		iq_unlock_bh(&qp->iq.lock);
	}

	l += printk(KERN_INFO
		"%s---------- Completion Queues -----------\n", indents[indent]);
	if (qp->attr.sq_cq) {
		cq_lock_bh(&qp->attr.sq_cq->lock); /* Prevents CQ resize */
		l += dump_cq(qp->attr.sq_cq, "SCQ", indent+1);
		cq_unlock_bh(&qp->attr.sq_cq->lock);
	}

	if (qp->attr.rq_cq) {
		cq_lock_bh(&qp->attr.rq_cq->lock); /* Prevents CQ resize */
		l += dump_cq(qp->attr.rq_cq, "RCQ", indent+1);
		cq_unlock_bh(&qp->attr.rq_cq->lock);
	}

	return l;
}

/*
 * Dump a PD.
 */
static int dump_pd(struct det_pd * const pd,
		   const int indent)
{
	return
	printk(KERN_INFO "%s%p id %x refcnt %d nic %p\n",
			indents[indent],
			pd,
			pd->id,
			atomic_read(&pd->refcnt),
			pd->nic);
}

/*
 * Dump a nic.
 */
static int dump_nic(struct det_nic * const nic,
		    const int indent)
{
	return
	printk(KERN_INFO "%s%p id %x refcnt %d scheduler %p event_cb %p\n",
			indents[indent],
			nic,
			nic->id,
			atomic_read(&nic->refcnt),
			nic->scheduler,
			nic->event_cb);
}

/*
 * Dump a event.
 */
static int dump_event(struct det_event * const event,
		      const int indent)
{
	return
	printk(KERN_INFO "%s%p id %x refcnt %d waitcnt %d\n",
			indents[indent],
			event,
			event->id,
			atomic_read(&event->refcnt),
			atomic_read(&event->waitcnt));
}

/*
 * Dump a CO.
 */
static int dump_co(struct det_co * const co,
		   const int indent)
{
	return
	printk(KERN_INFO "%s%p id %x size %d rank %d mr %p\n",
			indents[indent],
			co,
			co->id,
			co->size,
			co->rank,
			co->mr);
}

/*
 * Dump a mr.
 */
static int dump_mr(struct det_mr * const mr,
		   const int indent)
{
	return
	printk(KERN_INFO
		"%s%p id %x refcnt %d windows %d len %d vaddr %"U64"x l_key %x r_key %x, access 0x%x\n",
		indents[indent],
		mr,
		mr->base.id,
		atomic_read(&mr->base.refcnt),
		atomic_read(&mr->windows),
		mr->attr.base.length,
		(U64_PRINT_TYPE)mr->vaddr,
		mr->attr.l_key,
		mr->attr.base.r_key,
		mr->attr.base.access);
}

/*
 * Dump a mw.
 */
static int dump_mw(struct det_mw * const mw,
		   const int indent)
{
	return
	printk(KERN_INFO "%s%p id %x refcnt %d mr_offset %d mr %p\n",
		indents[indent],
		mw,
		mw->base.id,
		atomic_read(&mw->base.refcnt),
		mw->mr_offset,
		mw->mr);
}

static int dump_pdu_hdr(union det_pdu *pdu, char *name, char *page)
{
	return
	printk(KERN_INFO "    %s: len %d dst %x src %x seq %d %d/%d ",
		name, pdu->hdr.length, pdu->hdr.dst_qp, pdu->hdr.src_qp,
		pdu->hdr.seq_num, pdu->hdr.sq_ack_num, pdu->hdr.iq_ack_num);
}

static int dump_pdu(union det_pdu *pdu, char *page)
{
	int l = 0;
	switch (det_pdu_base_type(pdu->hdr.opcode)) {
		case det_op_send:
			l += dump_pdu_hdr(pdu, "SEND", page);
			l += printk("id %d len %d offset %d immed %d\n",
				pdu->send.msg_id, pdu->send.msg_length,
				pdu->send.msg_offset, pdu->send.immed_data);
			break;
		case det_op_write:
			l += dump_pdu_hdr(pdu, "WRITE", page);
			l += printk("id %d addr %"U64"x key %x immed %d\n",
				pdu->write.msg_id,
				(U64_PRINT_TYPE)pdu->write.rdma_address,
				pdu->write.rdma_key, pdu->write.immed_data);
			break;
		case det_op_read:
			l += dump_pdu_hdr(pdu, "READ", page);
			l += printk("id %d addr %"U64"x key %x len %d\n",
				pdu->read_req.rdma_id,
				(U64_PRINT_TYPE)pdu->read_req.rdma_address,
				pdu->read_req.rdma_key, pdu->read_req.rdma_length);
		case det_op_read_resp:
			l += dump_pdu_hdr(pdu, "READ_RESP", page);
			l += printk("id %d offset %d\n",
				pdu->read_rsp.rdma_id, pdu->read_rsp.rdma_offset);
			break;
		default:
			l += printk(KERN_INFO "Unsupported PDU type 0x%x\n",
						det_pdu_base_type(pdu->hdr.opcode));
	}
	return l;
}

/*
 * Dump skb queue
 */
static int dump_skb_queue(struct sk_buff_head *queue, char *page)
{
	struct sk_buff *skb;
	int l = 0;

	skb = queue->next;
	while(skb != (struct sk_buff *)queue) {
		l += dump_pdu((union det_pdu*)skb->data, page);
		skb = skb->next;
	}
	return l;
}

static int det_proto_read(char *page,
			  char **start,
			  off_t offset,
			  int count,
			  int *eof,
			  void *private_data)
{
	struct det_scheduler *scheduler;
	struct det_qp *qp;
	int l = 0;

	if (offset)
		return 0;

	printk(KERN_INFO "Protocol dump start\n");

	det_user_lock();
	sched_list_lock();
	list_for_each_entry(scheduler, &scheduler_list, entry) {
		l += printk(KERN_INFO
			"NIC %s %02x:%02x:%02x:%02x:%02x:%02x "
			"qp count %d sched_stopped %d outstanding skbs %d\n",
			     scheduler->netdev->name,
			     scheduler->netdev->dev_addr[0],
			     scheduler->netdev->dev_addr[1],
			     scheduler->netdev->dev_addr[2],
			     scheduler->netdev->dev_addr[3],
			     scheduler->netdev->dev_addr[4],
			     scheduler->netdev->dev_addr[5],
			     scheduler->count,
			     atomic_read(&scheduler->stopped),
			     scheduler->schedule_max - atomic_read(&scheduler->available));
		sched_obj_lock(&scheduler->lock); /* Prevents destroy of QP */
		list_for_each_entry(qp, &scheduler->qp_list, scheduler_entry)
			l += dump_qp(qp, 1);
		sched_obj_unlock(&scheduler->lock);
	}
	sched_list_unlock();
	det_user_unlock();

	printk(KERN_INFO "Protocol dump complete\n");

	l = sprintf(page, "%d byte%c sent to /var/log/messages.\n",
		l, (l == 1) ? '\0' : 's');

	*eof = 1;

	return l;
}


static int det_dev_read(char *page,
		  	char **start,
			off_t offset,
			int count,
			int *eof,
			void *private_data)
{
	extern rwlock_t detdev_list_lock;
	extern struct list_head detdev_list;

	struct det_device *detdev;
	struct det_mr *mr;
	struct det_event *event;
	struct det_pd *pd;
	struct det_mw *mw;
	struct det_qp *qp;
	struct det_cq *cq;
	struct det_nic *nic;
	struct det_co *co;
	
	int l = 0;

	if (offset)
		return 0;

	printk(KERN_INFO "DET device dump start\n");

	det_user_lock();
	read_lock(&detdev_list_lock);
	list_for_each_entry(detdev, &detdev_list, entry) {
		l += printk(KERN_INFO "%sDET Device %p\n", indents[1], detdev);

		l += printk(KERN_INFO "%snic list\n", indents[1]);
		list_for_each_entry(nic, &detdev->nic_list, entry)
			l += dump_nic(nic, 2);

		l += printk(KERN_INFO "%s%d pd entries\n", indents[1], detdev->pd_cnt);
		list_for_each_entry(pd, &detdev->pd_list, entry)
			l += dump_pd(pd, 2);

		l += printk(KERN_INFO "%s%d mr entries\n", indents[1], detdev->mr_cnt);
		list_for_each_entry(mr, &detdev->mr_list, base.entry)
			l += dump_mr(mr, 2);

		l += printk(KERN_INFO "%s%d mw entries\n", indents[1], detdev->mw_cnt);
		list_for_each_entry(mw, &detdev->mw_list, base.entry)
			l += dump_mw(mw, 2);

		l += printk(KERN_INFO "%s%d cq entries\n", indents[1], detdev->cq_cnt);
		list_for_each_entry(cq, &detdev->cq_list, entry)
			l += dump_cq(cq, "RAW", 2);

		l += printk(KERN_INFO "%s%d qp entries\n", indents[1], detdev->qp_cnt);
		list_for_each_entry(qp, &detdev->qp_list, entry)
			l += dump_qp(qp, 2);

		l += printk(KERN_INFO "%s%d co entries\n", indents[1], detdev->co_cnt);
		list_for_each_entry(co, &detdev->co_list, entry)
			l += dump_co(co, 2);

		l += printk(KERN_INFO "event list\n");
		list_for_each_entry(event, &detdev->event_list, entry)
			l += dump_event(event, 2);
	}
	read_unlock(&detdev_list_lock);
	det_user_unlock();

	printk(KERN_INFO "DET device dump complete\n");

	l = sprintf(page, "%d byte%c sent to /var/log/messages.\n",
		l, (l == 1) ? '\0' : 's');
	*eof = 1;

	return l;
}


void det_dump_locks(void)
{
	extern struct list_head detdev_list;

	struct det_device *detdev;
	struct det_event *event;
	struct det_qp *qp;
	struct det_cq *cq;
	struct det_co *co;
	struct det_mr *mr;
	struct det_scheduler *scheduler;
	
	list_for_each_entry(scheduler, &scheduler_list, entry) {
		if (spin_is_locked(&scheduler->lock.lock))
			det_lock_print(&scheduler->lock, "scheduler lock");
		if (spin_is_locked(&scheduler->atomic_lock.lock))
			det_lock_print(&scheduler->atomic_lock, "atomic lock");
	}

	list_for_each_entry(detdev, &detdev_list, entry) {
		list_for_each_entry(mr, &detdev->mr_list, base.entry)
			if (spin_is_locked(&mr->lock.lock))
				det_lock_print(&mr->lock, "mr lock");

		list_for_each_entry(cq, &detdev->cq_list, entry)
			if (spin_is_locked(&cq->lock.lock))
				det_lock_print(&cq->lock, "cq lock");

		list_for_each_entry(qp, &detdev->qp_list, entry) {
			if (spin_is_locked(&qp->lock.lock))
				det_lock_print(&qp->lock, "qp lock");
			if (spin_is_locked(&qp->sq.lock.lock))
				det_lock_print(&qp->sq.lock, "sq lock");
			if (spin_is_locked(&qp->iq.lock.lock))
				det_lock_print(&qp->iq.lock, "iq lock");
			if (spin_is_locked(&qp->rq.lock.lock))
				det_lock_print(&qp->rq.lock, "rq lock");
			if (spin_is_locked(&qp->wirestate.lock.lock))
				det_lock_print(&qp->wirestate.lock, "wirestate lock");
		}

		list_for_each_entry(co, &detdev->co_list, entry)
			if (spin_is_locked(&co->lock.lock))
				det_lock_print(&co->lock, "co lock");

		list_for_each_entry(event, &detdev->event_list, entry)
			if (spin_is_locked(&event->lock.lock))
				det_lock_print(&event->lock, "event lock");
	}
}


static int det_lock_read(char *page,
		  	 char **start,
			 off_t offset,
			 int count,
			 int *eof,
			 void *private_data)
{
	int l = 0;

	if (offset)
		return 0;

	printk(KERN_INFO "DET lock dump start\n");
	det_dump_locks();
	printk(KERN_INFO "DET lock dump complete\n");

	l = sprintf(page, "Output sent to /var/log/messages.\n");
	*eof = 1;

	return l;
}


#ifdef DET_STATS
static int det_stats_read(char *page,
			  char **start,
			  off_t offset,
			  int count,
			  int *eof,
			  void *private_data)
{
	int l = 0;

	if (offset)
		return 0;

	l += sprintf(page + l,
		"DET Statistics:\n"
		"    rx_pkts %lu tx_pkts %lu loopback_pkts %lu trace %lu\n"
		"    rx_snack %lu tx_snack %lu busted_snacks %lu zero_tx %lu sched: exhaust %lu abort %lu\n"
		"    timer_acks %lu tmouts %lu retries %lu dups %lu tx_errors %lu inv_qp %lu bad_addr %lu\n"
		"    total wr %lu : send %lu write %lu read %lu cmp %lu fetch %lu recv %lu bind %lu\n"
		"    join %lu barrier %lu bcast %lu scatter %lu scatterv %lu gather %lu gatherv %lu\n"
		"    allgather %lu allgatherv %lu alltoall %lu alltoallv %lu co_deferred %lu lb_deferred %lu\n",
		     DET_STAT(packets_recvd),
		     DET_STAT(packets_sent),
		     DET_STAT(loopback),
		     DET_STAT(code_trace),
		     DET_STAT(snacks_recvd),
		     DET_STAT(snacks_sent),
		     DET_STAT(busted_snacks),
		     DET_STAT(zero_tx_limit),
		     DET_STAT(sched_exhaust),
		     DET_STAT(sched_abort),
		     DET_STAT(timer_acks),
		     DET_STAT(timeouts),
		     DET_STAT(retries),
		     DET_STAT(duplicates),
		     DET_STAT(tx_errors),
		     DET_STAT(invalid_qp),
		     DET_STAT(bad_addr),
		     DET_STAT(wr_types[DET_WR_SEND])             +
		     DET_STAT(wr_types[DET_WR_RDMA_WRITE])       +
		     DET_STAT(wr_types[DET_WR_RDMA_READ])        +
		     DET_STAT(wr_types[DET_WR_ATOMIC_COMP_EXCH]) +
		     DET_STAT(wr_types[DET_WR_ATOMIC_FETCH_ADD]) +
		     DET_STAT(wr_types[DET_WR_RECV])             +
		     DET_STAT(wr_types[DET_WR_BIND])		 +
		     DET_STAT(wr_types[DET_WR_JOIN])		 +
		     DET_STAT(wr_types[DET_WR_BARRIER])		 +
		     DET_STAT(wr_types[DET_WR_BCAST])		 +
		     DET_STAT(wr_types[DET_WR_SCATTER])		 +
		     DET_STAT(wr_types[DET_WR_SCATTERV])	 +
		     DET_STAT(wr_types[DET_WR_GATHER])		 +
		     DET_STAT(wr_types[DET_WR_GATHERV])		 +
		     DET_STAT(wr_types[DET_WR_ALLGATHER])	 +
		     DET_STAT(wr_types[DET_WR_ALLGATHERV])	 +
		     DET_STAT(wr_types[DET_WR_ALLTOALL])	 +
		     DET_STAT(wr_types[DET_WR_ALLTOALLV]),
		     DET_STAT(wr_types[DET_WR_SEND]),
		     DET_STAT(wr_types[DET_WR_RDMA_WRITE]),
		     DET_STAT(wr_types[DET_WR_RDMA_READ]),
		     DET_STAT(wr_types[DET_WR_ATOMIC_COMP_EXCH]),
		     DET_STAT(wr_types[DET_WR_ATOMIC_FETCH_ADD]),
		     DET_STAT(wr_types[DET_WR_RECV]),
		     DET_STAT(wr_types[DET_WR_BIND]),
		     DET_STAT(wr_types[DET_WR_JOIN]),
		     DET_STAT(wr_types[DET_WR_BARRIER]),
		     DET_STAT(wr_types[DET_WR_BCAST]),
		     DET_STAT(wr_types[DET_WR_SCATTER]),
		     DET_STAT(wr_types[DET_WR_SCATTERV]),
		     DET_STAT(wr_types[DET_WR_GATHER]),
		     DET_STAT(wr_types[DET_WR_GATHERV]),
		     DET_STAT(wr_types[DET_WR_ALLGATHER]),
		     DET_STAT(wr_types[DET_WR_ALLGATHERV]),
		     DET_STAT(wr_types[DET_WR_ALLTOALL]),
		     DET_STAT(wr_types[DET_WR_ALLTOALLV]),
		     DET_STAT(co_deferred),
		     DET_STAT(co_lb_deferred)
		     );
	*eof = 1;
	return l;
}
#endif


#ifdef DET_PERF
static int det_perf_read(char *page,
			 char **start,
			 off_t offset,
			 int count,
			 int *eof,
			 void *private_data)
{
	int l = 0;

	if (offset)
		return 0;

	l += sprintf(page + l,
		"                  min        max        avg          cnt\n"
		"READ_REQ      %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"WRITE_REQ     %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"SEND_REQ      %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"POLL_REQ_HIT  %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"POLL_REQ_MISS %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"LOOPBACK_PATH %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"LOOPBACK_COPY %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"RECV_PATH     %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"RECV_COPY     %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"SKB_RECV      %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"RX_COMP_RQ    %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"RX_COMP_IQ    %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"ATOMIC_COPY   %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"SCHED_DELAY   %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"WR_SQ_XMITED  %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"WR_SQ_CMPLT   %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"WR_IQ_XMITED  %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"WR_IQ_CMPLT   %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"TX_FRAG       %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"TIMER_THREAD  %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"ECHO_LATENCY  %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"POST_SNDRCV   %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"SNDRCV_COMPLT %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"SEND_BYTES    %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"READ_BYTES    %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"WRITE_BYTES   %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"GP_0          %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"GP_1          %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"GP_2          %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
//		"GP_3          %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		,PERF_MIN(PERF_READ),    PERF_MAX(PERF_READ)
		,PERF_AVG(PERF_READ),    PERF_CNT(PERF_READ)
		,PERF_MIN(PERF_WRITE),   PERF_MAX(PERF_WRITE)
		,PERF_AVG(PERF_WRITE),   PERF_CNT(PERF_WRITE)
		,PERF_MIN(PERF_SEND),    PERF_MAX(PERF_SEND)
		,PERF_AVG(PERF_SEND),    PERF_CNT(PERF_SEND)
		,PERF_MIN(PERF_POLL_HIT), PERF_MAX(PERF_POLL_HIT)
		,PERF_AVG(PERF_POLL_HIT), PERF_CNT(PERF_POLL_HIT)
		,PERF_MIN(PERF_POLL_MISS),PERF_MAX(PERF_POLL_MISS)
		,PERF_AVG(PERF_POLL_MISS),PERF_CNT(PERF_POLL_MISS)
//		,PERF_MIN(LOOPBACK_PATH),PERF_MAX(LOOPBACK_PATH)
//		,PERF_AVG(LOOPBACK_PATH),PERF_CNT(LOOPBACK_PATH)
//		,PERF_MIN(LOOPBACK_COPY),PERF_MAX(LOOPBACK_COPY)
//		,PERF_AVG(LOOPBACK_COPY),PERF_CNT(LOOPBACK_COPY)
		,PERF_MIN(RECV_PATH),    PERF_MAX(RECV_PATH)
		,PERF_AVG(RECV_PATH),    PERF_CNT(RECV_PATH)
		,PERF_MIN(RECV_COPY),    PERF_MAX(RECV_COPY)
		,PERF_AVG(RECV_COPY),    PERF_CNT(RECV_COPY)
//		,PERF_MIN(SKB_RECV),     PERF_MAX(SKB_RECV)
//		,PERF_AVG(SKB_RECV),     PERF_CNT(SKB_RECV)
//		,PERF_MIN(RX_COMP_RQ),   PERF_MAX(RX_COMP_RQ)
//		,PERF_AVG(RX_COMP_RQ),   PERF_CNT(RX_COMP_RQ)
//		,PERF_MIN(RX_COMP_IQ),   PERF_MAX(RX_COMP_IQ)
//		,PERF_AVG(RX_COMP_IQ),   PERF_CNT(RX_COMP_IQ)
//		,PERF_MIN(ATOMIC_COPY),  PERF_MAX(ATOMIC_COPY)
//		,PERF_AVG(ATOMIC_COPY),  PERF_CNT(ATOMIC_COPY)
//		,PERF_MIN(SCHED_DELAY),  PERF_MAX(SCHED_DELAY)
//		,PERF_AVG(SCHED_DELAY),  PERF_CNT(SCHED_DELAY)
		,PERF_MIN(WR_SQ_XMIT),   PERF_MAX(WR_SQ_XMIT)
		,PERF_AVG(WR_SQ_XMIT),   PERF_CNT(WR_SQ_XMIT)
		,PERF_MIN(WR_SQ_CMPLT),  PERF_MAX(WR_SQ_CMPLT)
		,PERF_AVG(WR_SQ_CMPLT),  PERF_CNT(WR_SQ_CMPLT)
//		,PERF_MIN(WR_IQ_XMIT),   PERF_MAX(WR_IQ_XMIT)
//		,PERF_AVG(WR_IQ_XMIT),   PERF_CNT(WR_IQ_XMIT)
//		,PERF_MIN(WR_IQ_CMPLT),  PERF_MAX(WR_IQ_CMPLT)
//		,PERF_AVG(WR_IQ_CMPLT),  PERF_CNT(WR_IQ_CMPLT)
//		,PERF_MIN(TX_FRAG),      PERF_MAX(TX_FRAG)
//		,PERF_AVG(TX_FRAG),      PERF_CNT(TX_FRAG)
//		,PERF_MIN(TIMER_THREAD), PERF_MAX(TIMER_THREAD)
//		,PERF_AVG(TIMER_THREAD), PERF_CNT(TIMER_THREAD)
//		,PERF_MIN(PERF_ECHO),    PERF_MAX(PERF_ECHO)
//		,PERF_AVG(PERF_ECHO),    PERF_CNT(PERF_ECHO)
//		,PERF_MIN(POST_SNDRCV),  PERF_MAX(POST_SNDRCV)
//		,PERF_AVG(POST_SNDRCV),  PERF_CNT(POST_SNDRCV)
//		,PERF_MIN(SNDRCV_COMPLT),PERF_MAX(SNDRCV_COMPLT)
//		,PERF_AVG(SNDRCV_COMPLT),PERF_CNT(SNDRCV_COMPLT)
		,PERF_MIN(SEND_BYTES),   PERF_MAX(SEND_BYTES)
		,PERF_AVG(SEND_BYTES),   PERF_CNT(SEND_BYTES)
		,PERF_MIN(READ_BYTES),   PERF_MAX(READ_BYTES)
		,PERF_AVG(READ_BYTES),   PERF_CNT(READ_BYTES)
		,PERF_MIN(WRITE_BYTES),  PERF_MAX(WRITE_BYTES)
		,PERF_AVG(WRITE_BYTES),  PERF_CNT(WRITE_BYTES)
		,PERF_MIN(GP_0),         PERF_MAX(GP_0)
		,PERF_AVG(GP_0),         PERF_CNT(GP_0)
		,PERF_MIN(GP_1),         PERF_MAX(GP_1)
		,PERF_AVG(GP_1),         PERF_CNT(GP_1)
//		,PERF_MIN(GP_2),         PERF_MAX(GP_2)
//		,PERF_AVG(GP_2),         PERF_CNT(GP_2)
//		,PERF_MIN(GP_3),         PERF_MAX(GP_3)
//		,PERF_AVG(GP_3),         PERF_CNT(GP_3)
		);

	*eof = 1;
	return l;
}
#endif


#ifdef DET_PROFILE_LOCKS
static int det_perf_lock_read(char *page,
			      char **start,
			      off_t offset,
			      int count,
			      int *eof,
			      void *private_data)
{
	int l = 0;

	if (offset)
		return 0;

	l += sprintf(page + l,
#ifdef DET_USER_LOCK
		"USER_LOCK     %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n",
		PERF_MIN(USER_LOCK),    PERF_MAX(USER_LOCK),
		PERF_AVG(USER_LOCK),    PERF_CNT(USER_LOCK)
#else
		"                  min        max        avg          cnt\n"
		"WIRE_MAP_RD   %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"WIRE_MAP_WR   %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"WIRE_STATE    %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"SQ_LOCK       %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"IQ_LOCK       %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"WQ_LOCK       %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"QP_LOCK       %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n"
		"RQ_LOCK       %7"PVAL"u %10"PVAL"u %10"PVAL"u %12"PVAL"u\n",
		PERF_MIN(WIRE_MAP_RD),  PERF_MAX(WIRE_MAP_RD),
		PERF_AVG(WIRE_MAP_RD),  PERF_CNT(WIRE_MAP_RD),
		PERF_MIN(WIRE_MAP_WR),  PERF_MAX(WIRE_MAP_WR),
		PERF_AVG(WIRE_MAP_WR),  PERF_CNT(WIRE_MAP_WR),
		PERF_MIN(WIRE_STATE),   PERF_MAX(WIRE_STATE),
		PERF_AVG(WIRE_STATE),   PERF_CNT(WIRE_STATE),
		PERF_MIN(SQ_LOCK),      PERF_MAX(SQ_LOCK),
		PERF_AVG(SQ_LOCK),      PERF_CNT(SQ_LOCK),
		PERF_MIN(IQ_LOCK),      PERF_MAX(IQ_LOCK),
		PERF_AVG(IQ_LOCK),      PERF_CNT(IQ_LOCK),
		PERF_MIN(WQ_LOCK),      PERF_MAX(WQ_LOCK),
		PERF_AVG(WQ_LOCK),      PERF_CNT(IQ_LOCK),
		PERF_MIN(QP_LOCK),      PERF_MAX(QP_LOCK),
		PERF_AVG(QP_LOCK),      PERF_CNT(QP_LOCK),
		PERF_MIN(RQ_LOCK),      PERF_MAX(RQ_LOCK),
		PERF_AVG(RQ_LOCK),      PERF_CNT(RQ_LOCK)
#endif
		);

	*eof = 1;
	return l;
}
#endif


static int chk_valid_tx_state(struct det_tx_state * const tx,
			      char * const state_name,
			      char * const qp_name,
			      char *page)
{
	int l = 0;

	if (det_tx_unacked_window(tx))
		l += printk(KERN_INFO "%s unacked %s window %d\n",
			qp_name, state_name, det_tx_unacked_window(tx));

	return l;
}


static int chk_valid_rx_state(struct det_qp * const qp,
			      struct det_rx_state * const rx,
			      char * const name,
			      char * const qp_name,
			      char *page)
{
	int l = 0;

	if (det_seq_window(atomic_read(&rx->last_in_seq), rx->last_seq_acked))
		l += printk(KERN_INFO "%s %s window %d\n", qp_name, name, 
			det_seq_window(atomic_read(&rx->last_in_seq),
				       rx->last_seq_acked));
	if (rx->snacked)
		l += printk(KERN_INFO "%s %s snack window %d\n", qp_name, name,
			det_seq_window(rx->first_snack_seq, rx->last_snack_seq));
	if (!skb_queue_empty(&rx->snack_deferred)) {
		l += printk(KERN_INFO "%s %s has SNACK deferred skbs\n",
			qp_name, name);
		l += dump_skb_queue(&rx->snack_deferred, page);
	}
	rq_lock_bh(&qp->rq.lock);
	if (!skb_queue_empty(&rx->co_deferred)) {
		l += printk(KERN_INFO "%s %s has CO deferred skbs\n",
			qp_name, name);
		l += dump_skb_queue(&rx->co_deferred, page);
	}
	rq_unlock_bh(&qp->rq.lock);

	return l;
}


static int chk_valid_wq(struct det_wq * const wq,
			char * const name,
			char * const qp_name,
			char *page)
{
	struct det_wr *wr;
	int l = 0;
	int i;

	if (wq->size == 0)
		return 0;

	if (!my_delay_trylock(&wq->lock)) {
		l += sprintf(page + l, "%s %s lock is busy\n", qp_name, name);
		return l;
	}

	i = (wq->head + wq->completion_cnt) % wq->size;
	if (i == wq->tail)
		goto leave;

#ifdef DET_TRIGGERED_WR
	l += printk(KERN_INFO "%s %s gate %d entries: ",
		    qp_name, name, atomic_read(&wq->gate));
#else
	l += printk(KERN_INFO "%s %s entries: ", qp_name, name);
#endif
	while (i != wq->tail) {
		wr = det_get_wr(wq, i);
		l += printk("%s %s id %d len %d flags %x "
#ifdef DET_TRIGGERED_WR
			"trigger %d signal %p "
#endif
		       "seg: remainig %d start %d next %d ending %d last tm %d "
		       "rea: last seen %d last %d\n",
			get_wr_type(wr->type),
			get_wr_state(atomic_read(&wr->state)),
			wr->msg_id,
			wr->total_length,
			wr->flags,
#ifdef DET_TRIGGERED_WR
			wr->trigger,
			wr->signal,
#endif
			wr->sar.seg.wr_length_remaining,
			wr->sar.seg.starting_seq,
			wr->sar.seg.next_seq,
			wr->sar.seg.ending_seq,
			atomic_read(&wr->sar.seg.last_timeout_seq_sent),
			wr->sar.rea.last_seen_seq,
			wr->sar.rea.last_packet_seq);

		i = (i + 1) % wq->size;
	}
leave:
	my_unlock(&wq->lock);

	return l;
}


static int det_active_read(char *page,
			   char **start,
			   off_t offset,
			   int count,
			   int *eof,
			   void *private_data)
{
	struct det_scheduler *scheduler;
	struct det_qp *qp;
	int l = 0;
	char qp_name[128];

	if (offset)
		return 0;

	l += printk(KERN_INFO "Protocol activity check start\n");

#ifdef DET_USER_LOCK
	/* det_user_lock() */
	if (my_delay_trylock(&__det_user_lock__)) {
		l += sprintf(page + l, "user lock is busy\n");
		goto leave;
	}
#endif

	/*sched_list_lock();*/
	if (!my_delay_trylock(&scheduler_list_lock)) {
		l += sprintf(page, "scheduler list lock is busy\n");
		goto leave;
	}

	list_for_each_entry(scheduler, &scheduler_list, entry) {
		if (det_spin_is_locked(&scheduler->lock))
			l += printk(KERN_INFO "scheduler busy\n");
		if (atomic_read(&scheduler->stopped))
			l += printk(KERN_INFO "scheduler stopped\n");

		/* Prevents destroy of QP */
		/* sched_obj_lock(&scheduler->lock); */
		if (!my_delay_trylock(&scheduler->lock)) {
			l += printk(KERN_INFO "scheduler object lock is busy\n");
			continue;
		}

		list_for_each_entry(qp, &scheduler->qp_list, scheduler_entry) {
			sprintf(qp_name, "QP src %x dst %x",
					qp->attr.local_qp_num,
					qp->attr.remote_qp_num);
			/* Prevents changing QP state */
			/* qp_lock_bh(&qp->lock); */
			if (!my_delay_trylock(&qp->lock)) {
				l += printk(KERN_INFO "%s lock is busy\n", qp_name);
				continue;
			}

			if (qp->attr.state != DET_QP_CONNECTED)
				l += printk(KERN_INFO "%s state %s\n", qp_name,
						get_qp_state(qp->attr.state));
			qp_unlock_bh(&qp->lock);
			
			l += chk_valid_tx_state(&qp->wirestate.sq_tx, "SQ_TX",
						qp_name, page+l);
			l += chk_valid_rx_state(qp, &qp->wirestate.sq_rx, "SQ_RX",
						qp_name, page+l);
			l += chk_valid_tx_state(&qp->wirestate.iq_tx, "IQ_TX",
						qp_name, page+l);
			l += chk_valid_rx_state(qp, &qp->wirestate.iq_rx, "IQ_RX",
						qp_name, page+l);
			l += chk_valid_wq(&qp->sq, "SQ", qp_name, page+l);
			l += chk_valid_wq(&qp->rq, "RQ", qp_name, page+l);
			l += chk_valid_wq(&qp->iq, "IQ", qp_name, page+l);
		}
		my_unlock(&scheduler->lock);
	}
	/*sched_list_unlock();*/
	my_unlock(&scheduler_list_lock);
	l += printk(KERN_INFO "Protocol activity check complete\n");
	l = sprintf(page, "%d byte%c sent to /var/log/messages.\n",
		l, (l == 1) ? '\0' : 's');

#ifdef DET_USER_LOCK
	/* det_user_unlock() */
	my_unlock(&__det_user_lock__);
#endif

leave:
	*eof = 1;
	return l;
}


int det_stats_write(struct file *file,
		    const char __user *buffer,
		    unsigned long count,
		    void *data)
{
	det_reset_statistics(&det_statistics);
	return count;
}


static int det_config_read(char *page,
			   char **start,
			   off_t offset,
			   int count,
			   int *eof,
			   void *private_data)
{
	*eof = 1;
	return sprintf(page,
#ifdef CONFIG_DET_LOOPBACK
		"LOOPBACK "
#endif
#ifdef CONFIG_DET_SEQUESTER
		"SEQUESTER "
#endif
#ifdef CONFIG_DET_DOORBELL
		"DOORBELL "
#endif
#ifdef CONFIG_DET_PROFILING
		"PROFILING "
#endif
#ifdef CONFIG_DET_DEBUG
		"DET_DEBUG "
#endif
#ifdef DET_TRIGGERED_WR
		"TRIGGERED_WR "
#endif
#ifdef DET_USER_LOCK
		"USER_LOCK "
#endif
#ifdef DET_STATS
		"STATS "
#endif
#ifdef DET_PERF
		"PERF "
#endif
#ifdef DET_TASKLET
		"TASKLET "
#endif
#ifdef DET_LOCK_DEBUG
		"LOCK_DEBUG "
#endif
#ifdef DET_PROFILE_LOCKS
		"LOCK_PROFILING "
#endif
	"\n");
}

static int det_mr_read(char *page,
		       char **start,
		        off_t offset,
		        int count,
		        int *eof,
		       void *private_data)
{
	extern rwlock_t detdev_list_lock;
	extern struct list_head detdev_list;

	int l = 0;
	struct det_device *detdev;
	struct det_mr *mr;

	det_user_lock();
	read_lock(&detdev_list_lock);
	list_for_each_entry(detdev, &detdev_list, entry) {
		l += printk(KERN_INFO "%s%d mr entries\n", indents[1], detdev->mr_cnt);
		list_for_each_entry(mr, &detdev->mr_list, base.entry)
			l += dump_mr(mr, 2);
	}
	read_unlock(&detdev_list_lock);
	det_user_unlock();

	l = sprintf(page, "%d byte%c sent to /var/log/messages.\n",
		l, (l == 1) ? '\0' : 's');
	*eof = 1;
	return l;
}

int det_create_procfs(char * const alias)
{
	struct proc_dir_entry* entry;

	/* Create a /proc/net entry for this driver. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	proc_net_det = proc_mkdir(alias, init_net.proc_net);
#else
	proc_net_det = proc_mkdir(alias, proc_net);
#endif
	if (unlikely(!proc_net_det))
		return -ENODEV;
	proc_net_det->owner = THIS_MODULE;

	/* Create a proto entry. */
	entry = create_proc_read_entry("proto",
					S_IRUGO,
					proc_net_det,
					det_proto_read,
					NULL);

	if (likely(entry))
		entry->owner = THIS_MODULE;

	entry = create_proc_read_entry("dev",
					S_IRUGO,
					proc_net_det,
					det_dev_read,
					NULL);

	if (likely(entry))
		entry->owner = THIS_MODULE;

#ifdef DET_PERF
	/* Create performance counter entry */
	entry = create_proc_read_entry("perf",
					S_IRUGO | S_IWUGO,
					proc_net_det,
					det_perf_read,
					NULL);
	if (likely(entry)) {
		entry->owner = THIS_MODULE;
		entry->write_proc = det_stats_write;
	}
#endif
#ifdef DET_PROFILE_LOCKS
	/* Create performance counter entry */
	entry = create_proc_read_entry("lock_stats",
					S_IRUGO | S_IWUGO,
					proc_net_det,
					det_perf_lock_read,
					NULL);
	if (likely(entry)) {
		entry->owner = THIS_MODULE;
		entry->write_proc = det_stats_write;
	}
#endif
#ifdef DET_STATS
	/* Create a statistics entry. */
	entry = create_proc_read_entry("stats",
					S_IRUGO | S_IWUGO,	/* S_IWUSR */
					proc_net_det,
					det_stats_read,
					NULL);
	if (likely(entry)) {
		entry->owner = THIS_MODULE;
		entry->write_proc = det_stats_write;
	}
#endif
	/* Create performance counter entry */
	entry = create_proc_read_entry("active",
					S_IRUGO,
					proc_net_det,
					det_active_read,
					NULL);
	if (likely(entry)) {
		entry->owner = THIS_MODULE;
	}

	entry = create_proc_read_entry("lock_dump",
					S_IRUGO,
					proc_net_det,
					det_lock_read,
					NULL);

	if (likely(entry)) {
		entry->owner = THIS_MODULE;
	}

	/* Tunable entry. */
	entry = create_proc_read_entry("config",
					S_IRUGO | S_IWUGO,	/* S_IWUSR */
					proc_net_det,
					det_config_read,
					NULL);
	if (likely(entry)) {
		entry->owner = THIS_MODULE;
	}

	entry = create_proc_read_entry("mr",
					S_IRUGO | S_IWUGO,	/* S_IWUSR */
					proc_net_det,
					det_mr_read,
					NULL);
	if (likely(entry)) {
		entry->owner = THIS_MODULE;
	}

	return 0;
}


void det_delete_procfs(char * const alias)
{
	remove_proc_entry("mr", proc_net_det);
	remove_proc_entry("config", proc_net_det);
	remove_proc_entry("lock_dump", proc_net_det);
#ifdef DET_PERF
	remove_proc_entry("perf", proc_net_det);
#endif
#ifdef DET_PROFILE_LOCKS
	remove_proc_entry("lock_stats", proc_net_det);
#endif
#ifdef DET_STATS
	remove_proc_entry("stats", proc_net_det);
#endif
	remove_proc_entry("active", proc_net_det);
	remove_proc_entry("dev", proc_net_det);
	remove_proc_entry("proto", proc_net_det);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	remove_proc_entry(alias, init_net.proc_net);
#else
	remove_proc_entry(alias, proc_net);
#endif
}


#else	/* CONFIG_PROC_FS */


int det_create_procfs(char * const alias)
{
	return 0;
}

void det_delete_procfs(char * const alias)
{
}

#endif	/* CONFIG_PROC_FS */
