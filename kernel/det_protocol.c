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


#ifndef	CONFIG_DET_LOOPBACK

static void det_check_loopback(struct sk_buff *skb);

static inline void det_free_skb(struct sk_buff* skb)
{
	kfree_skb(skb);
}

static inline struct sk_buff* det_skb_clone(struct sk_buff *skb)
{
	return skb_clone(skb, GFP_ATOMIC);
}

static inline struct sk_buff* det_alloc_tx_skb(struct net_device *netdev,
					       int hdr_size,
					       int payload_size)
{
	struct sk_buff *skb;

	/* account for link header */
	hdr_size += ETH_HDR_SIZE;

	skb = dev_alloc_skb(hdr_size);
	if (unlikely(!skb))
		return NULL;
	skb->protocol = DET_PACKET_TYPE;
	skb->dev = netdev;
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	skb->priority = TC_PRIO_CONTROL;  /* highest defined priority */
	skb_reset_network_header(skb);
	skb_reset_mac_header(skb);
	skb->len = hdr_size + payload_size;
	skb->data_len = payload_size;
	skb->tail += hdr_size;

	return skb;
}

#ifdef DET_CKSUM
static u32 det_sum(struct det_hdr *hdr, int len)
{
	u8* data = (u8*)hdr;
	u32 sum = 0;

	if ((len < 0) ||(len > sizeof(union det_pdu)))
		return -1;
	
	data += (sizeof(hdr->sum) + sizeof(hdr->sum_len));
	len  -= (sizeof(hdr->sum) + sizeof(hdr->sum_len));
	while(len--)
		sum += *data++;
	return sum;
}


static int det_dev_queue_xmit(struct sk_buff *skb)
{
	u32 sum;
	int result;

	struct det_full_frame *frame = (struct det_full_frame*)skb->data;
	u32 len = (skb->len - skb->data_len) - sizeof(frame->eth_hdr);

	sum = det_sum(&frame->det.hdr, len);
	if (sum == -1) {
		printk("error summing for xmit: len %d data_len %d\n", skb->len, skb->data_len);
		return ~NET_XMIT_SUCCESS;
	}
	frame->det.hdr.sum = sum;
	frame->det.hdr.sum_len = len;
	det_check_loopback(skb);

	result = dev_queue_xmit(skb);
	if (result)
		DET_STAT(tx_errors++);
	else
		DET_STAT(packets_sent++);
	return result;
}

#else

static int det_dev_queue_xmit(struct sk_buff *skb)
{
	int result;

	det_check_loopback(skb);

	result = dev_queue_xmit(skb);
	if (result)
		DET_STAT(tx_errors++);
	else
		DET_STAT(packets_sent++);
	return result;
}

#endif /* DET_CKSUM */


static void det_check_loopback(struct sk_buff *skb)
{
	struct det_full_frame *pdu = (struct det_full_frame*)skb->data;
	struct sk_buff *new_skb;

	/*
	 *  If we are transmitting to ourselves, clone the skb and put
	 *  it on our receive queue
	 */
	if ((!(*pdu->eth_hdr.h_dest & 1) &&	/* multicast/broadcast */
	     !det_hw_addr_equal(skb->dev->dev_addr, pdu->eth_hdr.h_dest)) ||
	    !strncmp(skb->dev->name, "lo", 2))
		return;

	new_skb = det_skb_clone(skb);
	if (unlikely(!new_skb)) {
		printk(KERN_INFO "DET: no sk_buff resources for loopback\n");
		return;
	}

#ifdef CONFIG_DET_SEQUESTER
	eth_type_trans(new_skb, skb->dev);

	recv_queue_lock();
	skb_queue_tail(&det_recv_queue, new_skb);
	recv_queue_unlock();
#else
	{
		struct net_device *dev = det_dev_get_by_name("lo");
		if (unlikely(!dev)) {
			det_free_skb(new_skb);
			printk(KERN_INFO "DET: netdev \"lo\" not found\n");
			return;
		}
		new_skb->dev = dev;
		if (dev_queue_xmit(new_skb))
			DET_STAT(tx_errors++);
		else
			DET_STAT(packets_sent++);
		dev_put(dev);
	}
#endif
}


static void det_process_proto_error(struct det_qp * const qp,
				    const int reason)
{
	printk(KERN_NOTICE "DET Disconnect Protocol error %d\n", reason);
	det_qp_internal_disconnect(qp, reason);
}


/*
 *  Setup a for a fresh data descriptor
 */
#define DS_SETUP(ds, mr, page_offset, page_index, ds_len_left)	\
do {								\
	mr = ds->mr;						\
	ds_len_left = ds->length;				\
	page_offset = ds->offset + (mr->vaddr & ~PAGE_MASK);	\
	page_index = page_offset >> PAGE_SHIFT;			\
	page_offset &= ~PAGE_MASK;				\
} while(0)


/*
 *  Setup for page crossing within a data descriptor
 */
#define NEXT_PAGE(ds, mr, page_offset, page_index, ds_len_left)		\
do {									\
	if (!ds_len_left) {						\
		ds++;							\
		DS_SETUP(ds, mr, page_offset, page_index, ds_len_left);	\
	} else {							\
		page_index++;						\
		assert(mr->page_cnt > page_index);			\
		page_offset = 0;					\
	}								\
} while(0)


/*
 *  Setup the data descriptor, page, and offset for specified sequence number
 */
#define SETUP_BY_SEQ(wr, ds, mr, from_seq, wr_length, page_offset, page_index,		\
		    ds_len_left, max_payload)						\
do {											\
	u32 i, frag_len_max;								\
											\
	DS_SETUP(ds, mr, page_offset, page_index, ds_len_left);				\
	for (i = wr->sar.seg.starting_seq; seq_before(i, from_seq); i++) {		\
		num_frags = 0;								\
		payload_left = max_payload;						\
		while (payload_left && (num_frags < MAX_SKB_FRAGS)) {			\
			frag_len_max = min(ds_len_left, (u32)(PAGE_SIZE - page_offset));\
			if (wr_length > payload_left) {					\
				if (payload_left > frag_len_max) {			\
					ds_len_left -= frag_len_max;			\
					NEXT_PAGE(ds, mr, page_offset,			\
						  page_index, ds_len_left);		\
				} else {						\
					frag_len_max = payload_left; /* frag->size */	\
					ds_len_left -= payload_left;			\
					page_offset += payload_left;			\
				}							\
			} else {							\
				if (wr_length > frag_len_max) {				\
					ds_len_left -= frag_len_max;			\
					NEXT_PAGE(ds, mr, page_offset,			\
						  page_index, ds_len_left);		\
				} else {						\
					printk(KERN_ERR					\
				"from_seq botch botch(%d): wr %p type %d length %d\n",	\
					from_seq, wr, wr->type, wr_length);		\
					return 0;					\
				}							\
			}								\
			wr_length -= frag_len_max;					\
			payload_left -= frag_len_max;					\
			num_frags++;							\
		}									\
	}										\
} while(0)


static inline void det_make_ethhdr(struct ethhdr * const ethhdr,
				   u8 *local_mac,
				   u8 *remote_mac)
{
	det_memcpy(ethhdr->h_source, local_mac, DET_MAC_ADDR_LEN);
	det_memcpy(ethhdr->h_dest, remote_mac, DET_MAC_ADDR_LEN);
	ethhdr->h_proto = __constant_htons(DET_PACKET_TYPE);
}


void dump_pdu(char *str, const struct det_hdr * const hdr)
{
#ifdef DET_CKSUM
	printk("%s: sum %x sum_len %d opcode %x len %d dst %x src %x seq %d sq_ack %d iq_ack %d\n",
		str, hdr->sum, hdr->sum_len, hdr->opcode, hdr->length, hdr->dst_qp,
		hdr->src_qp, hdr->seq_num, hdr->sq_ack_num, hdr->iq_ack_num);
#else
	printk("%s: opcode %x len %d dst %x src %x seq %d sq_ack %d iq_ack %d\n",
		str, hdr->opcode, hdr->length, hdr->dst_qp,
		hdr->src_qp, hdr->seq_num, hdr->sq_ack_num, hdr->iq_ack_num);
#endif
}

void det_skb_destructor( struct sk_buff * const skb )
{
	struct det_scheduler *sched = GET_SKB_SCHED(skb);

	/*
	 *  A sk_buff is now available.
	 */
	atomic_inc(&sched->available);

	/* Release the module reference held for this sk_buff. */
	module_put(THIS_MODULE);
}


static int det_create_hdr(struct det_qp * const qp,
			  struct det_wr * const wr,
			  struct sk_buff * const skb,
			  u32 seq_num,
			  const u32 wr_len_remaining,
			  int force )
{
	struct det_full_frame *pdu = (struct det_full_frame*)skb->data;
	u16 opcode;
	u32 sq_seq, iq_seq;

	det_make_ethhdr(&pdu->eth_hdr, qp->attr.local_mac.addr,
				       qp->attr.remote_mac.addr);

	sq_seq = atomic_read(&qp->wirestate.sq_rx.last_in_seq);
	qp->wirestate.sq_rx.last_seq_acked = sq_seq;
	iq_seq = atomic_read(&qp->wirestate.iq_rx.last_in_seq);
	qp->wirestate.iq_rx.last_seq_acked = iq_seq;

	pdu->det.hdr.length = HTON16(skb->data_len);
	pdu->det.hdr.dst_qp = HTON32(qp->attr.remote_qp_num);
	pdu->det.hdr.src_qp = HTON32(qp->attr.local_qp_num);
	pdu->det.hdr.seq_num = HTON32(seq_num);
	pdu->det.hdr.sq_ack_num = HTON32(sq_seq);
	pdu->det.hdr.iq_ack_num = HTON32(iq_seq);

	switch( wr->type ) {
	case DET_WR_SEND:
		opcode = det_op_send;
		if (skb->data_len == wr_len_remaining) {
			opcode = det_pdu_set_last(opcode);
			if (!(wr->flags & DET_WR_SURPRESSED))
				force = 1;
			if (wr->flags & DET_WR_IMMEDIATE) {
				opcode = det_pdu_set_immed(opcode);
				pdu->det.send.immed_data =
					wr->send.immediate_data;
			} else pdu->det.send.immed_data = 0;
			if (wr->flags & DET_WR_SOLICITED)
				opcode = det_pdu_set_se(opcode);
		}
		pdu->det.send.msg_id = HTON32(wr->msg_id);
		pdu->det.send.msg_length = HTON32(wr->total_length);
		pdu->det.send.msg_offset = HTON32(wr->total_length -
						  wr_len_remaining);
		break;

	case DET_WR_RDMA_WRITE:
		opcode = det_op_write;
		if (wr->flags & DET_WR_IMMEDIATE) {
			opcode = det_pdu_set_immed(opcode);
			pdu->det.write.immed_data = wr->write.immediate_data;
			if (wr->flags & DET_WR_SOLICITED)
				opcode = det_pdu_set_se(opcode);
		} else pdu->det.write.immed_data = 0;
		if (skb->data_len == wr_len_remaining) {
			opcode = det_pdu_set_last(opcode);
			if (!(wr->flags & DET_WR_SURPRESSED))
				force = 1;
		}
		pdu->det.write.msg_id = HTON32(wr->msg_id);
		pdu->det.write.rdma_key = wr->write.remote_key;
		pdu->det.write.rdma_address =
			      HTON64(NTOH64(wr->write.remote_address) + 
			                   (wr->total_length -
			                    wr_len_remaining));
		break;

	case DET_WR_RDMA_READ:
		opcode = det_op_read;
		pdu->det.read_req.rdma_id = HTON32(wr->msg_id);
		pdu->det.read_req.rdma_key = wr->read.remote_key;
		pdu->det.read_req.rdma_address = wr->read.remote_address;
		pdu->det.read_req.rdma_length = wr->read.remote_length;
		break;

	case DET_WR_RDMA_READ_RESP:
		opcode = det_op_read_resp;
		if (skb->data_len == wr_len_remaining)
			opcode = det_pdu_set_last(opcode);
		pdu->det.read_rsp.rdma_id = HTON32(wr->msg_id);
		pdu->det.read_rsp.rdma_offset = HTON32(wr->total_length -
						       wr_len_remaining);
		break;

	case DET_WR_ATOMIC_RESP:
		opcode = det_pdu_set_last(wr->atomic_resp.opcode);
		pdu->det.atomic_rsp.atomic_id = HTON32(wr->msg_id);
		pdu->det.atomic_rsp.orig_data = wr->atomic_resp.orig_data;
		break;

	case DET_WR_ATOMIC_COMP_EXCH:
		opcode = det_pdu_set_last(det_op_comp_exch);
		pdu->det.comp_exch.atomic_address = wr->comp_exch.remote_address;
		pdu->det.comp_exch.comp_data = wr->comp_exch.comp_operand;
		pdu->det.comp_exch.exch_data = wr->comp_exch.exch_operand;
		pdu->det.comp_exch.atomic_key = wr->comp_exch.remote_key;
		pdu->det.comp_exch.atomic_id = HTON32(wr->msg_id);
		break;

	case DET_WR_ATOMIC_FETCH_ADD:
		opcode = det_pdu_set_last(det_op_fetch_add);
		pdu->det.fetch_add.add_data = wr->fetch_add.add_operand;
		pdu->det.fetch_add.atomic_address = wr->fetch_add.remote_address;
		pdu->det.fetch_add.atomic_key = wr->fetch_add.remote_key;
		pdu->det.fetch_add.atomic_id = HTON32(wr->msg_id);
		break;

	case DET_WR_JOIN:
		opcode = det_pdu_set_last(det_op_join);
		if (wr->flags & DET_WR_SOLICITED)
			opcode = det_pdu_set_se(opcode);
		pdu->det.join.tag = qp->co->group->tag;
		pdu->det.join.root = HTON32(qp->co->rank);
		pdu->det.join.size = HTON32(qp->co->group->size);
		pdu->det.join.msg_id = HTON32(wr->msg_id);
		break;

	default:
		printk(KERN_ERR
			"det_create_hdr: invalid type (%d)\n", wr->type);
		return 1;
	}

	if (force)
		opcode = det_pdu_set_force_ack(opcode);

	pdu->det.hdr.opcode = HTON16(opcode);
	wr->sar.seg.last_opcode = opcode;

	return 0;
}


static int get_hdr_size_from_wr( const struct det_wr * const wr )
{
	switch (wr->type) {
	case DET_WR_SEND:		return sizeof(struct det_send_hdr);
	case DET_WR_RDMA_WRITE:		return sizeof(struct det_write_hdr);
	case DET_WR_RDMA_READ:		return sizeof(struct det_read_req_hdr);
	case DET_WR_ATOMIC_COMP_EXCH:	return sizeof(struct det_comp_exch_hdr);
	case DET_WR_ATOMIC_FETCH_ADD:	return sizeof(struct det_fetch_add_hdr);
	case DET_WR_RDMA_READ_RESP:	return sizeof(struct det_read_rsp_hdr);
	case DET_WR_ATOMIC_RESP:	return sizeof(struct det_atomic_rsp_hdr);
	case DET_WR_JOIN:		return sizeof(struct det_join_hdr);
	default: return -1;
	}
}


u32 det_get_msg_id(const union det_pdu * const pdu)
{
	/*
	 * The id field moves around depending on the operation.
	 * It probably should have been placed in the base header.
	 */
	switch (det_pdu_base_type(pdu->hdr.opcode)) {
	case det_op_send:		return pdu->send.msg_id;
	case det_op_write:		return pdu->write.msg_id;
	case det_op_read:		return pdu->read_req.rdma_id;
	case det_op_read_resp:		return pdu->read_rsp.rdma_id;
	case det_op_comp_exch_resp:
	case det_op_fetch_add_resp:	return pdu->atomic_rsp.atomic_id;
	case det_op_comp_exch:		return pdu->comp_exch.atomic_id;
	case det_op_fetch_add:		return pdu->fetch_add.atomic_id;
	case det_op_join:		return pdu->join.msg_id;
	default:			return -1;
	}
}


static struct sk_buff* det_alloc_pdu(struct det_qp * const qp,
				     struct det_wr * const wr,
				     const int hdr_size,
				     const u32 seq_num,
				     const u32 payload_size,
				     const u32 len_remaining,
				     const int force )
{
	struct sk_buff *skb;

	if (atomic_dec_and_test(&qp->scheduler->available))
		goto bail;

	/*
	 *  Get skb for this DET protocol packet
	 */
	skb = det_alloc_tx_skb(qp->netdev, hdr_size, payload_size);
	if (unlikely(!skb))
		goto bail;

	/* Hold a reference on the module until skb->destructor is called. */
	__module_get(THIS_MODULE);
	skb->destructor = det_skb_destructor;

	SET_SKB_SCHED(skb, qp);
	SET_SKB_WR(skb, wr);

	/*
	 *  Construct the header and copy it to skb
	 */
	if (unlikely(det_create_hdr(qp, wr, skb, seq_num, len_remaining, force))) {
		det_free_skb(skb);
		goto bail;
	}

	return skb;
bail:
	atomic_inc(&qp->scheduler->available);
	return NULL;
}


static int det_send_null_pdu( struct det_qp * const qp,
			      struct det_wq * const wq,
			      struct det_wr * const wr,
			      struct det_scheduler * const sched,
			      const u32 hdr_size)
{
	struct sk_buff *skb;

	/*
	 *  Allocate an initialized skb with PDU header
	 */
	skb = det_alloc_pdu(qp, wr, hdr_size, wr->sar.seg.starting_seq, 0, 0, 0);
	if (unlikely(!skb))
		return 0;

	if (det_dev_queue_xmit(skb) != NET_XMIT_SUCCESS)
		return 0;
	return 1;
}

int det_send_echo(struct det_qp * const qp)
{
	struct sk_buff *skb;
	struct det_full_frame *pdu;

	skb = det_alloc_tx_skb(qp->netdev, sizeof(pdu->det.echo), 0);
	if (unlikely(!skb)) {
		printk(KERN_ERR "det_send_echo: can't allocate skb\n");
		return 0;
	}

	pdu = (struct det_full_frame*)skb->data;
	det_make_ethhdr(&pdu->eth_hdr,
			qp->attr.local_mac.addr, qp->attr.remote_mac.addr);

	/* length has no meaning */
	pdu->det.hdr.length = 0;
	pdu->det.hdr.sq_ack_num = HTON32(atomic_read(
					&qp->wirestate.sq_rx.last_in_seq));
	pdu->det.hdr.iq_ack_num = HTON32(atomic_read(
					&qp->wirestate.iq_rx.last_in_seq));

	pdu->det.hdr.dst_qp = HTON32(qp->attr.remote_qp_num);
	pdu->det.hdr.src_qp = HTON32(qp->attr.local_qp_num);

	/* seq_num has no meaning so we set to something easy to spot */
	pdu->det.hdr.seq_num = 0;
	pdu->det.hdr.opcode = HTON16(det_op_echo_req);
	PERF_GET_HRC(pdu->det.echo.timestamp);

	det_dev_queue_xmit(skb);

	return 1;
}


int det_xmit_wr( struct det_qp * const qp,
		 struct det_wq * const wq,
		 struct det_wr * const wr,
		 const int tx_limit,
		 const int retransmit,
		 u32 from_seq,
		 atomic_t *posted )
{
	struct sk_buff *skb;
	struct det_ds *ds;
	struct det_mr *mr;
	struct det_scheduler *sched;
	skb_frag_t *frag;
	int hdr_size, num_xmited, page_index, num_frags;
	u32 page_offset;
	u32 wr_length, max_payload, payload_left, ds_len_left;

	/*
	 *  No use trying to send zero frames or tx suppressed requests
	 */
	if (wr->flags & DET_WR_CO_RESERVED)
		return 0;

	if (tx_limit == 0) {
		DET_STAT(zero_tx_limit++);
		return 0;
	}

	sched = qp->scheduler;
	hdr_size = get_hdr_size_from_wr(wr);
	max_payload = qp->attr.mtu_size - hdr_size;

	if (retransmit) {
		/*
		 *  There is a race condition where an ack can be received
		 *  during the retry/timeout processing of the scheduler.
		 *  If the 'from_seq' is equal to or greater than the next
		 *  sequence for the stream, or this was for the last fragment
		 *  of this WR, from_seq could be outside the sequence space
		 *  of this WR.  Rather than take the sq/iq locks in ack
		 *  processing, we'll do a quick check here to catch this race
		 *  and skip the send.
		 */
		assert(!seq_before(from_seq, wr->sar.seg.starting_seq));
		if (!seq_before(from_seq, wr->sar.seg.next_seq) ||
		    (seq_after(from_seq, wr->sar.seg.ending_seq))) {
			return 0;
		}

		/*
		 *  We're retransmiting some or all of this wr. If it has
		 *  a payload, find out where we're retransmitting from.
		 *  Otherwise, send it on its way.
		 */
		wr_length = wr->total_length;
		if (wr_length) {
			ds = wr->ds_array;
			SETUP_BY_SEQ(wr, ds, mr, from_seq, wr_length, page_offset,
				     page_index, ds_len_left, max_payload);
		} else {
			if (posted)
				atomic_set(posted, from_seq);
			return det_send_null_pdu(qp, wq, wr, sched, hdr_size);
		}
	} else if (wr->sar.seg.current_ds == NULL) {
		/*
		 *  This is a fresh send so intialize the wr
		 *  by setting the static parts of the header
		 *  and sequence number range for this wr
		 */
		PERF_RECORD(SCHED_DELAY, wr->start);

		wr_length = wr->total_length;
		wr->sar.seg.starting_seq = from_seq;
		wr->sar.seg.ending_seq = from_seq;
		if (wr_length > max_payload) {
			wr->sar.seg.ending_seq += (wr_length / max_payload);
			if (!(wr_length % max_payload))
				wr->sar.seg.ending_seq--;
		}


		atomic_set(&wr->state, WR_STATE_STARTED);

		/*
		 *  If this request has a payload, setup for fragmentation.
		 *  Otherwise, send it on its way.
		 */
		if (wr_length) {
			ds = wr->ds_array;
			DS_SETUP(ds, mr, page_offset, page_index, ds_len_left);
		} else {
			num_xmited = det_send_null_pdu(qp, wq, wr, sched, hdr_size);
			/* from_seq must always advanced even in null PDU cases */
			from_seq++;
			goto finish;
		}
	} else {
		/*
		 *  We're picking up from a paritally sent request.
		 */
		mr = wr->sar.seg.current_mr;
		ds = wr->sar.seg.current_ds;
		wr_length = wr->sar.seg.wr_length_remaining;
		ds_len_left = wr->sar.seg.ds_length_remaining;
		page_index = wr->sar.seg.current_page_index;
		page_offset = wr->sar.seg.current_page_offset;
		from_seq = wr->sar.seg.next_seq;
	}

	/*
	 *  Ok, let's break this bad-boy up
	 */
	num_xmited = 0;
	while ( wr_length &&
	       (num_xmited < tx_limit) &&
	       (qp->attr.state == DET_QP_CONNECTED)) {

	       PERF_DECL(start)
	       PERF_GET_HRC(start);

		/*
		 *  Allocate an initialized skb with PDU header
		 */
		skb = det_alloc_pdu(qp, wr, hdr_size, from_seq,
				    min(wr_length, max_payload), wr_length,
				    retransmit && (num_xmited == (tx_limit-1)));
		if (unlikely(!skb)) {
			num_xmited = -1; /* indicate xmit resources exhausted */
			break;
		}

		/*
		 *  Update sequence number for next pass
		 */
		from_seq++;

		/*
		 *  Fill the skb fragment list
		 */
		frag = skb_shinfo(skb)->frags;
		num_frags = 0;
		payload_left = max_payload;

		while (payload_left && (num_frags < MAX_SKB_FRAGS)) {
			u32 frag_len_max;

			frag->page = mr->pages[page_index];
			frag->page_offset = page_offset;

			/* take a reference on the page - kfree_skb will release */
			get_page(frag->page);

			frag_len_max = min(ds_len_left, (u32)(PAGE_SIZE - page_offset));
			if (wr_length > payload_left) {
				if (payload_left > frag_len_max) {
					/* deal with page boundary crossing */
					frag->size = frag_len_max;
					ds_len_left -= frag_len_max;
					NEXT_PAGE(ds, mr, page_offset,
						  page_index, ds_len_left);
				} else {
					frag->size = payload_left;
					ds_len_left -= payload_left;
					page_offset += payload_left;
				}
			} else {
				if (wr_length > frag_len_max) {
					/* deal with page boundary crossing */
					frag->size = frag_len_max;
					ds_len_left -= frag_len_max;
					NEXT_PAGE(ds, mr, page_offset,
						  page_index, ds_len_left);
				} else {
					frag->size = wr_length;
					payload_left -= wr_length;
					wr_length = 0;
					num_frags++; /* change from index to number */
					break;
				}
			}

			wr_length -= frag->size;
			payload_left -= frag->size;
			num_frags++;
			frag++;
		}
		skb_shinfo(skb)->nr_frags = num_frags;

		/* check if we need to do a fixup because we ran out of frags */
		if ((num_frags == MAX_SKB_FRAGS) && wr_length) {
			struct det_full_frame *pdu = (struct det_full_frame*)skb->data;

			skb->len = ETH_HDR_SIZE + hdr_size + (max_payload - payload_left);
			skb->data_len = (max_payload - payload_left);
			pdu->det.hdr.length = skb->data_len;
			pdu->det.hdr.opcode &= ~det_last_flag;
		}

		/*
		 *  Send it.
		 */
		PERF_GET_HRC(((struct det_skb_cb*)(&skb->cb))->timestamp);
		if (det_dev_queue_xmit(skb) != NET_XMIT_SUCCESS) {
			num_xmited = -1; /* indicate xmit resources exhausted */
			break;
		}
		PERF_RECORD(TX_FRAG, start);

		if (retransmit)
			DET_STAT(retries++);
		num_xmited++;
	}

	/*
	 *  Update state. If this is a retransmit, don't update anything.
	 *  If not and there's more to do on the wr, save state.  Otherwise,
	 *  setup for next wr.
	 */
	if (!retransmit) {
		if (wr_length) {
			wr->sar.seg.current_mr = mr;
			wr->sar.seg.current_ds = ds;
			wr->sar.seg.wr_length_remaining = wr_length;
			wr->sar.seg.ds_length_remaining = ds_len_left;
			wr->sar.seg.current_page_index = page_index;
			wr->sar.seg.current_page_offset = page_offset;
		} else {
finish:			atomic_set(&wr->state, WR_STATE_WAITING_FOR_ACK);
			wq->next_active_wr = (wq->next_active_wr + 1) % wq->size;
			switch(det_pdu_base_type(wr->sar.seg.last_opcode)) {
			case det_op_read:
			case det_op_write:
			case det_op_send:
				PERF_RECORD(WR_SQ_XMIT, wr->start);
				break;
			default:
				if (det_pdu_is_iq(wr->sar.seg.last_opcode))
					PERF_RECORD(WR_IQ_XMIT, wr->start);
			}

#ifdef	DET_TRIGGERED_WR
			if (wr->signal &&
			    !atomic_add_negative(1, &wr->signal->sq.gate))
				det_schedule(DET_SCHEDULE_NEW, wr->signal);
#endif
		}

		wr->sar.seg.next_seq = from_seq;
		if (posted)
			atomic_set(posted, from_seq);
	} else if (posted) {
		atomic_set(posted, from_seq - 1);
	}

	return num_xmited;
}


static int det_schedule_dma(struct det_qp * const qp,
			    struct page **page,
			    u32 page_offset,
			    struct sk_buff *skb,
			    u32 data_len)
{
	u32 transfer_len;
	u8 *vaddr;
	u8 *data = skb->data;
	PERF_DECL(start)

	if (likely(data_len)) {
		PERF_GET_HRC(start);
next_page:
		transfer_len = min(data_len, (u32)PAGE_SIZE - page_offset);
		vaddr = det_kmap_dst(*page) + page_offset;

		if (unlikely(!vaddr)) {
			dprintk("det_schedule_dma: det_kmap_dst returned NULL\n");
			return DET_AE_WRAP_ERROR;
		}

		(void)det_atomic_copy(vaddr, data, transfer_len, 0);

		atomic_inc(&qp->dma_pending);
		det_kunmap_dst(*page, vaddr);
		if (data_len -= transfer_len) {
			page++;
			page_offset = 0;
			data += transfer_len;
			goto next_page;
		}
		PERF_RECORD(RECV_COPY, start);
	}

	return 0;
}

int det_wait_on_dma(struct det_qp * const qp)
{
	atomic_set(&qp->dma_pending, 0);
	return 0;
}

static void det_send_snack(struct det_qp * const qp,
			   const union det_pdu * const in_pdu,
			   struct sk_buff * const in_skb,
			   const int is_iq)
{
	struct sk_buff *skb;
	struct det_full_frame *out_pdu;
	u32 sq_seq, iq_seq;

	skb = det_alloc_tx_skb(qp->netdev, sizeof(out_pdu->det.snack), 0);
	if (unlikely(!skb)) {
		printk(KERN_ERR "det_send_snack: can't allocate skb\n");
		return;
	}

	out_pdu = (struct det_full_frame*)skb->data;

	det_make_ethhdr(&out_pdu->eth_hdr,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
			eth_hdr(in_skb)->h_dest,
			eth_hdr(in_skb)->h_source);
#else
			in_skb->mac.ethernet->h_dest,
			in_skb->mac.ethernet->h_source);
#endif
	out_pdu->det.hdr.dst_qp = HTON32(in_pdu->hdr.src_qp);
	out_pdu->det.hdr.src_qp = HTON32(qp->attr.local_qp_num);

	/* length has no meaning */
	out_pdu->det.hdr.length  = 0;
	/* seq_num has no meaning so we set to something easy to spot */
	out_pdu->det.hdr.seq_num = 0;

	sq_seq = atomic_read(&qp->wirestate.sq_rx.last_in_seq);
	qp->wirestate.sq_rx.last_seq_acked = sq_seq;
	iq_seq = atomic_read(&qp->wirestate.iq_rx.last_in_seq);
	qp->wirestate.iq_rx.last_seq_acked = iq_seq;

	out_pdu->det.hdr.sq_ack_num = HTON32(sq_seq);
	out_pdu->det.hdr.iq_ack_num = HTON32(iq_seq);

	if (is_iq) {
		out_pdu->det.hdr.opcode = det_op_snack_iq;
		out_pdu->det.snack.seq_edge =
			HTON32(qp->wirestate.iq_rx.first_snack_seq);
	} else {
		out_pdu->det.hdr.opcode = det_op_snack_sq;
		out_pdu->det.snack.seq_edge =
			HTON32(qp->wirestate.sq_rx.first_snack_seq);
	}
	/* no need to set a destructor for SNACKs */

	DET_STAT(snacks_sent++);
	det_dev_queue_xmit(skb);
}

void det_send_ack(struct det_qp * const qp)
{
	struct sk_buff *skb;
	struct det_full_frame *pdu;
	u32 sq_seq, iq_seq;

	/* suppress sending acks to "unconnected" CO QP's */
	if (qp->attr.remote_qp_num == -1)
		return;

	skb = det_alloc_tx_skb(qp->netdev, sizeof(pdu->det.ack), 0);
	if (unlikely(!skb)) {
		printk(KERN_ERR "det_send_ack: can't allocate skb\n");
		return;
	}

	pdu = (struct det_full_frame *)skb->data;

	det_make_ethhdr(&pdu->eth_hdr,
			qp->attr.local_mac.addr, qp->attr.remote_mac.addr);

	pdu->det.hdr.dst_qp = HTON32(qp->attr.remote_qp_num);
	pdu->det.hdr.src_qp = HTON32(qp->attr.local_qp_num);

	pdu->det.hdr.opcode = HTON16(det_op_ack);
	/* length has no meaning */
	pdu->det.hdr.length = 0;
	/* seq_num has no meaning so we set to something easy to spot */
	pdu->det.hdr.seq_num = 0;

	sq_seq = atomic_read(&qp->wirestate.sq_rx.last_in_seq);
	qp->wirestate.sq_rx.last_seq_acked = sq_seq;
	iq_seq = atomic_read(&qp->wirestate.iq_rx.last_in_seq);
	qp->wirestate.iq_rx.last_seq_acked = iq_seq;

	pdu->det.hdr.sq_ack_num = HTON32(sq_seq);
	pdu->det.hdr.iq_ack_num = HTON32(iq_seq);

	det_dev_queue_xmit(skb);
}

void det_send_disconnect(struct det_qp * const qp,
			 const enum det_event_code reason)
{
	struct sk_buff *skb;
	struct det_full_frame *pdu;

	if (qp_is_co(qp))
		return;

	if (qp->loopback)
		return det_loopback_disconnect(qp, reason);

	skb = det_alloc_tx_skb(qp->netdev, sizeof(pdu->det.disconnect), 0);
	if (unlikely(!skb)) {
		printk(KERN_ERR "det_send_disconnect: can't allocate disconnect skb\n");
		return;
	}

	pdu = (struct det_full_frame*)skb->data;
	det_make_ethhdr(&pdu->eth_hdr, qp->attr.local_mac.addr,
				       qp->attr.remote_mac.addr);

	pdu->det.hdr.opcode = HTON16(det_op_disconnect);
	/* length has no meaning */
	pdu->det.hdr.length = 0;
	pdu->det.hdr.sq_ack_num = HTON32(atomic_read(
					&qp->wirestate.sq_rx.last_in_seq));
	pdu->det.hdr.iq_ack_num = HTON32(atomic_read(
					&qp->wirestate.iq_rx.last_in_seq));

	pdu->det.hdr.dst_qp = HTON32(qp->attr.remote_qp_num);
	pdu->det.hdr.src_qp = HTON32(qp->attr.local_qp_num);

	/* seq_num has no meaning so we set to something easy to spot */
	pdu->det.hdr.seq_num = 0;
	pdu->det.disconnect.code = HTON32(reason);

	det_dev_queue_xmit(skb);
}

void det_reflect_disconnect(struct det_hdr * const hdr,
			    struct sk_buff * const in_skb,
			    const enum det_event_code reason)
{
	struct sk_buff *skb;
	struct det_full_frame *pdu;

	/* We don't send disconnects from disconnects */
	if (hdr->opcode == det_op_disconnect)
		return;

	skb = det_alloc_tx_skb(in_skb->dev, sizeof(pdu->det.disconnect), 0);
	if (unlikely(!skb)) {
		printk(KERN_ERR "det_reflect_disconnect: can't allocate disconnect skb\n");
		return;
	}

	pdu = (struct det_full_frame*)skb->data;

	det_make_ethhdr(&pdu->eth_hdr,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
			eth_hdr(in_skb)->h_dest,
			eth_hdr(in_skb)->h_source);
#else
			in_skb->mac.ethernet->h_dest,
			in_skb->mac.ethernet->h_source);
#endif
	pdu->det.hdr.opcode = HTON16(det_op_disconnect);
	pdu->det.hdr.length = 0;
	pdu->det.hdr.sq_ack_num = 0;
	pdu->det.hdr.iq_ack_num = 0;
	pdu->det.hdr.seq_num = 0;
	pdu->det.hdr.dst_qp = HTON32(hdr->src_qp);
	pdu->det.hdr.src_qp = HTON32(hdr->dst_qp);

	pdu->det.disconnect.code = HTON32(reason);

	det_dev_queue_xmit(skb);
}

void det_reflect_echo(struct det_hdr * const hdr,
		      struct sk_buff * const in_skb)
{
	struct sk_buff *out_skb;
	struct det_full_frame *pdu;

	out_skb = det_alloc_tx_skb(in_skb->dev, sizeof(pdu->det.echo), 0);
	if (unlikely(!out_skb)) {
		printk(KERN_ERR "det_reflect_echo: can't allocate skb\n");
		return;
	}

	pdu = (struct det_full_frame*)out_skb->data;

	det_make_ethhdr(&pdu->eth_hdr,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,9)
			eth_hdr(in_skb)->h_dest,
			eth_hdr(in_skb)->h_source);
#else
			in_skb->mac.ethernet->h_dest,
			in_skb->mac.ethernet->h_source);
#endif
	pdu->det.hdr.opcode = HTON16(det_op_echo_resp);
	pdu->det.hdr.length = 0;
	pdu->det.hdr.sq_ack_num = 0;
	pdu->det.hdr.iq_ack_num = 0;
	pdu->det.hdr.seq_num = 0;
	pdu->det.hdr.dst_qp = HTON32(hdr->src_qp);
	pdu->det.hdr.src_qp = HTON32(hdr->dst_qp);

	pdu->det.echo.timestamp = ((union det_pdu*)(hdr))->echo.timestamp;

	det_dev_queue_xmit(out_skb);
}

static int update_rx_seq_numbers(struct det_qp * const qp,
				 const union det_pdu *pdu,
				 struct det_rx_state * const rx)
{
	struct sk_buff *skb;
	u32 seq_num = pdu->hdr.seq_num;
	int err;

	if (pdu->hdr.opcode == det_op_ack      ||
	    pdu->hdr.opcode == det_op_snack_sq ||
	    pdu->hdr.opcode == det_op_snack_iq)
		return 0;

	if (seq_num != atomic_read(&rx->last_in_seq)+1)
		return 0;

	/*
	 *  See if this closes a snack window.
	 *  I.e. last_in_seq >= first_snack_seq
	 */
	atomic_set(&rx->last_in_seq, seq_num);
	if (rx->snacked &&
	    /* sequence number just before the start of the hole fills it */
	    !seq_before(seq_num, rx->first_snack_seq - 1)) {

		/*
 		 *  Cool - a snack hole has been filled.
		 *  Place any deferred packets.
		 */
		while ((skb = skb_dequeue(&rx->snack_deferred))) {
			det_process_pdu(qp, (union det_pdu*)skb->data, skb, 0);
			det_free_skb(skb);
		}

		/*
		 *  Wait on any scheduled dma from above
		 */
		err = atomic_read(&qp->dma_pending) ? det_wait_on_dma(qp) : 0;
		if (unlikely(err)) {
			det_process_proto_error(qp, err);
		} else {
			/*
			 *  Update last_in_seq to cover any of the frames
			 *  we placed after the hole was discovered
			 */
			rx->snacked = 0;
			atomic_set(&rx->last_in_seq, rx->last_snack_seq);
		}
	}

	return 1;
}


/*
 *  Caller must hold the send queue lock
 */
int det_process_sq_completions(struct det_qp * const qp,
			       struct det_wq * const wq)
{
	struct det_wc *uninitialized_var(wc);
	struct det_wr *wr;
	u32 target;
	int err = 0;

	/*
	 *  Iterate the send queue looking for defered completions.
	 */
	for (target = (wq->head + wq->completion_cnt) % wq->size;
	     target != wq->tail;
	     target = (target + 1) % wq->size) {

		wr = det_get_wr(wq, target);
		if (atomic_read(&wr->state) != WR_STATE_COMPLETED)
			break;

		wq->completion_cnt++;
		wq->reap_cnt++;

		/*
		 *  If an IQ request has been completed.
		 *  Update throttling variables.
		 */
		if ((wr->type == DET_WR_RDMA_READ) ||
		    (wr->type == DET_WR_ATOMIC_COMP_EXCH) ||
		    (wr->type == DET_WR_ATOMIC_FETCH_ADD)) {

			assert(atomic_read(&qp->or_depth));
			atomic_dec(&qp->or_depth);
			atomic_dec(&qp->or_posted);
		}
		PERF_RECORD(WR_SQ_CMPLT, wr->start);

		/*
		 *  See if we need to generate a completion
		 */
		if (wr->flags & DET_WR_SURPRESSED)
			continue;

		/*
		 *  There are always send queue work requests
		 *  being completed here.
		 *
		 *  Note: They can also be completed in SQ ack
		 *        processing.
		 */
		err = det_reserve_cqe(qp->attr.sq_cq, &wc);
		if (unlikely(err))
			return (err == -ENOSPC) ? DET_AE_CQ_OVERRUN :
						  DET_AE_CQ_FATAL;

		wc->id = wr->id;
		wc->status = DET_WS_SUCCESS;
		wc->type = wr->type;
		if (wr->flags & DET_WR_IMMEDIATE) {
			wc->immediate_data = (wr->type == DET_WR_SEND) ?
				NTOH32(wr->send.immediate_data) :
				NTOH32(wr->write.immediate_data);
			wc->flags = DET_WC_IMMEDIATE;
		} else {
			wc->flags = 0;
		}
		wc->length = ((wr->type == DET_WR_RDMA_READ) ||
			      (wr->type == DET_WR_ATOMIC_COMP_EXCH) ||
			      (wr->type == DET_WR_ATOMIC_FETCH_ADD)) ?
			       wr->sar.rea.final_length : 0;
		wc->reserved = (unsigned long)wq;

		/*
		 *  Do completion accounting
		 */
		wc->reap_cnt = wq->reap_cnt;
		wq->reap_cnt = 0;

		det_append_cqe(qp->attr.sq_cq, wc);
	}

	return err;
}


static inline int __det_process_sq_completions(struct det_qp * const qp)
{
	struct det_wq *wq = &qp->sq;
	int err;

	sq_lock_bh(&wq->lock);
	err = det_process_sq_completions(qp, wq);
	sq_unlock_bh(&wq->lock);

	det_notify_cq(qp->attr.sq_cq);

	return err;
}


int det_schedule_rx_completions(struct det_qp * const qp,
				const int is_iq)
{
	struct det_wc *uninitialized_var(wc);
	struct det_wr *wr;
	struct det_wq *wq;
	u32 target;
	u32 last_in_seq;
	int err = 0;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (is_iq) {
		wq = &qp->sq;	/* yep, the SQ */
		last_in_seq = atomic_read(&qp->wirestate.iq_rx.last_in_seq);
	} else {
		wq = &qp->rq;
		last_in_seq = atomic_read(&qp->wirestate.sq_rx.last_in_seq);
	}

	/*
	 *  Make sure there are entries to process
	 */
	if (wq->size == 0)
		return 0;

	wq_lock_bh(&wq->lock);
	for (target = (wq->head + wq->completion_cnt) % wq->size;
	     target != wq->tail;
	     target = (target + 1) % wq->size) {

		wr = det_get_wr(wq, target);

		/*
		 *  Skip over non-IQ entries
		 */
		if ((wr->type == DET_WR_SEND)  ||
		    (wr->type == DET_WR_RDMA_WRITE) ||
		    (wr->type == DET_WR_BIND))
			continue;

		/*
		 *  If this WR hasn't seen the final segment in sequence,
		 *  nothing more to process in this queue.  We use the LAST
		 *  state as a qualifier because last_packet_seq will be
		 *  uninitialized until last packet is seen.
		 */
		if ((atomic_read(&wr->state) != WR_STATE_LAST_SEEN) ||
		    seq_before(last_in_seq, wr->sar.rea.last_packet_seq))
			break;

		/*
		 *  Clear references on memory regions
		 */
		det_clear_ds_refs(wr->ds_array, wr->num_ds);

		if (is_iq) {
			/*
			 *  Completed IQ replies are defered until earlier
			 *  non-IQ WR have completed.  This is determined 
			 *  with a second iteration of the WQ below.
			 */
			atomic_set(&wr->state, WR_STATE_COMPLETED);
			continue; /* look for more IQ completions */
		}

#ifdef	DET_TRIGGERED_WR
		if (wr->signal) {
			/* No work completions from signaling receives. */
			wq->head = (wq->head + 1) % wq->size;
			wq->depth--;
			if (!atomic_add_negative(1, &wr->signal->sq.gate))
				det_schedule(DET_SCHEDULE_NEW, wr->signal);
			continue;
		}
#endif
		/*
		 *  All receive queue completions are done here.
		 */
		err = det_reserve_cqe(qp->attr.rq_cq, &wc);
		if (unlikely(err)) {
			wq_unlock_bh(&wq->lock);
			return (err == -ENOSPC) ? DET_AE_CQ_OVERRUN :
						  DET_AE_CQ_FATAL;
		}

		wq->completion_cnt++;
		wc->reap_cnt = 1;

		wc->id = wr->id;
		wc->status = DET_WS_SUCCESS;
		wc->type = wr->type;
		wc->flags = 0;

		if (det_pdu_is_se(wr->sar.rea.opcode))
			wc->flags = DET_WC_SOLICITED;
		if (det_pdu_is_immed(wr->sar.rea.opcode)) {
			wc->flags |= DET_WC_IMMEDIATE;
			wc->immediate_data = NTOH32(wr->sar.rea.immediate_data);
		}

		wc->length = wr->sar.rea.final_length;
		wc->reserved = (unsigned long)wq;

		det_append_cqe(qp->attr.rq_cq, wc);
	}
	wq_unlock_bh(&wq->lock);

	/*
	 *  If this was the recieve queue, there is no more
	 *  processing to be done.
	 */
	if (!is_iq) {
		det_notify_cq(qp->attr.rq_cq);
		PERF_RECORD(RX_COMP_RQ, start);
		return 0;
	}

	err = __det_process_sq_completions(qp);
	if (unlikely(err))
		return err;

	/*
	 *  If we just created room for a backlogged IQ stream request
	 *  and there is a tx window, reschedule to get it sent
	 */
	if ((atomic_read(&qp->or_posted) > atomic_read(&qp->or_depth)) &&
	    (atomic_read(&qp->or_depth) < qp->attr.max_or) &&
	    det_tx_window(&qp->wirestate.sq_tx)) {

		qp->reschedule_flags |= DET_SCHEDULE_RESUME;
	}

	PERF_RECORD(RX_COMP_IQ, start);
	return 0;
}

static inline int det_recv_data(struct det_qp * const qp,
				struct det_wr *wr,
				struct sk_buff *skb,
				u32 length,
				u32 offset,
				u32 seq_num)
{
	struct det_ds *ds;
	struct det_mr *mr;
	u32 ds_offset;
	u32 seg_num;
	int page_index;
	u32 page_offset;
	u32 dma_len;
	int err;

	if (unlikely((length + offset) > wr->total_length)) {
		dprintk("Length botch\n");
		return DET_AE_INVALID_LENGTH;
	}

	if (!length) {
		ds = NULL;
		dma_len = 0;
		ds_offset = 0;
		goto no_data;
	}

	/*
	 *  See if we can use our ds cache
	 */
	if (likely((wr->sar.rea.current_ds != NULL) &&
		   (wr->sar.rea.last_seen_seq == seq_num-1))) {
		/*
		 *  Take cached entires
		 */
		ds = wr->sar.rea.current_ds;
		mr = ds->mr;
		ds_offset = wr->sar.rea.current_ds_offset;
		seg_num = (ds - wr->ds_array) / sizeof(struct det_ds);
	} else {
		ds_offset = offset;
		ds = wr->ds_array;
		seg_num = 0;
		while ((ds_offset >= ds->length) && (seg_num < wr->num_ds)) {
			ds_offset -= ds->length;
			ds++;
			seg_num++;
		}
next_ds:
		if (unlikely(seg_num >= wr->num_ds)) {
			dprintk("DS botch: seq=%d offset=%d len=%d\n",
					seq_num, offset, length);
			return DET_AE_INVALID_LENGTH;
		}

		/*
		 *  Because DAPL allows freeing a memory region which
		 *  may have posted receives against it, we need to
		 *  burn the cycles here to look it up to make sure
		 *  it's still valid. We'll take a reference now that
		 *  the data is coming in.
		 */
		if (!ds->in_use) {
			wiremap_read_lock();
			mr = idr_find(&det_wire_map, ds->l_key);
			if (unlikely(!mr || (mr->base.type != DET_TYPE_MR) ||
				     (mr->attr.l_key != ds->l_key))) {
				wiremap_read_unlock();
				return DET_AE_INVALID_L_KEY;
			}
			atomic_inc(&mr->base.refcnt);
			wiremap_read_unlock();

			ds->in_use = 1;

			if (unlikely(!(mr->attr.base.access & DET_AC_LOCAL_WRITE))) {
				err = DET_AE_ACCESS_VIOLATION;
				dprintk("Access violation\n");
				goto out;
			}
		} else {
			mr = ds->mr;
			assert(mr->base.type == DET_TYPE_MR);
		}
	}

	/*
	 *  Place data for this descriptor.
	 *  Routine will handle page boundary crossings.
	 */
	page_offset = ds->offset + ds_offset + (mr->vaddr & ~PAGE_MASK);
	page_index = page_offset >> PAGE_SHIFT;
	page_offset &= ~PAGE_MASK;
	dma_len = min(ds->length - ds_offset, length);

	err = det_schedule_dma(qp, &mr->pages[page_index], page_offset,
				skb, dma_len);
	if (unlikely(err)) {
out:
		if (atomic_dec_and_test(&mr->base.refcnt))
			complete(&mr->base.done);
		ds->in_use = 0;
		return err;
	}

	length -= dma_len;
	if (length) {
		ds++;
		seg_num++;
		ds_offset = 0;
		skb_pull(skb, dma_len);
		goto next_ds;
	}

no_data:
	wr->sar.rea.last_seen_seq = seq_num;

	if (ds && ((ds_offset + dma_len) < ds->length)) {
		wr->sar.rea.current_ds = ds;
		wr->sar.rea.current_ds_offset = ds_offset + dma_len;
	} else {
		/* force a validation of the next ds */
		wr->sar.rea.current_ds = NULL;
	}

	return 0;
}

static int det_process_send(struct det_qp * const qp,
			    const union det_pdu * const pdu,
			    struct sk_buff *skb,
			    int user_cntx)
{
	struct det_wr *wr;
	struct det_rx_state *rx;
	u32 msg_id;
	u32 msg_length;
	u32 msg_offset;
	u32 seq_num;
	int err;

	msg_id = NTOH32(pdu->send.msg_id);

	rq_lock_bh(&qp->rq.lock);
	if (qp_is_co_member(qp)) {
		rx = &qp->wirestate.sq_rx;

		if ((msg_id >= qp->rq.next_msg_id) ||
		    (rx->defer_in_process && !user_cntx)) {
			skb = det_skb_clone(skb);
			if (!skb) {
				rq_unlock_bh(&qp->rq.lock);
				return DET_AE_QP_RQ_ERROR;
			}
			skb_queue_tail(&rx->co_deferred, skb);
			rq_unlock_bh(&qp->rq.lock);

			DET_STAT(co_deferred++);
			return 0;
		}
	} else if (unlikely(msg_id >= qp->rq.next_msg_id)) {
		dprintk("RQ overflow\n");
		rq_unlock_bh(&qp->rq.lock);
		return DET_AE_QP_RQ_ERROR;
	}
	rq_unlock_bh(&qp->rq.lock);

	wr = det_wr_by_msg_id(&qp->rq, msg_id);
	if (unlikely(!wr)) {
		dprintk("Invalid MSG ID\n");
		return DET_AE_INVALID_MSG_ID;
	}

	msg_length = NTOH32(pdu->send.msg_length);
	if (unlikely(msg_length > wr->total_length)) {
		dprintk("MSG len error: msg_length=%d wr->total_length=%d\n",
					msg_length, wr->total_length);
		return DET_AE_BOUNDS_VIOLATION;
	}

	msg_offset = NTOH32(pdu->send.msg_offset);
	if (unlikely(msg_offset > msg_length)) {
		dprintk("MSG offset error\n");
		return DET_AE_INVALID_LENGTH;
	}

	/*
	 *  Remove PDU header
	 */
	skb_pull(skb, sizeof(pdu->send));
	seq_num = pdu->hdr.seq_num;

	err = det_recv_data(qp, wr, skb, pdu->hdr.length, msg_offset, seq_num);
	if (unlikely(err)) {
		dprintk("det_recv_data error %d\n", err);
		return err;
	}

	if (det_pdu_is_last(pdu->hdr.opcode)) {
		/*
		 *  We've got the last of the message
		 *  Note: We always assume immediate data.
		 *        If we were wrong, no harm, on foul.
		 */
		atomic_set(&wr->state, WR_STATE_LAST_SEEN);
		wr->sar.rea.immediate_data = pdu->send.immed_data;
		wr->sar.rea.last_packet_seq = seq_num;
		wr->sar.rea.opcode = pdu->hdr.opcode;
		wr->sar.rea.final_length = msg_length;
		wr->sar.rea.current_ds = NULL;	/* No data after this ds */
	}

	return 0;
}


static int det_process_write(struct det_qp * const qp,
			     const union det_pdu * const pdu,
			     struct sk_buff *skb)
{
	struct det_wr *wr;
	struct det_mr *mr;
	struct page **pages;
	u64 base_addr, rdma_addr;
	u32 base_len, rdma_len;
	u32 msg_id;
	u32 page_offset;
	int page_index;
	int err;

	/*
	 *  Writes with immediate data consume a rq wqe
	 */
	if (det_pdu_is_immed(pdu->hdr.opcode)) {
		/*
		 *  If the message ID is larger than the next ID we'd
		 *  assign, they've overrun the receive queue.
		 */
		msg_id = NTOH32(pdu->write.msg_id);
		if (unlikely(msg_id >= qp->rq.next_msg_id)) {
			dprintk("RQ overflow\n");
			return DET_AE_QP_RQ_ERROR;
		}

		wr = det_wr_by_msg_id(&qp->rq, msg_id);
		if (unlikely(!wr)) {
			dprintk("Invalid MSG ID\n");
			return DET_AE_INVALID_MSG_ID;
		}
	} else {
		wr = NULL;
	}

	/*
	 *  Remove PDU header
	 */
	skb_pull(skb, sizeof(pdu->write));

	/*
	 *  Look up the mr/mw
	 */
	wiremap_read_lock();
	mr = idr_find(&det_wire_map, NTOH32(pdu->write.rdma_key));
	if (unlikely(!mr || ((mr->base.type != DET_TYPE_MR)  &&
			     (mr->base.type != DET_TYPE_MW)) ||
		     (mr->attr.base.r_key != NTOH32(pdu->write.rdma_key)))) {
		wiremap_read_unlock();
		dprintk("Invalid key\n");
		return DET_AE_INVALID_RDMA_KEY;
	}
	atomic_inc(&mr->base.refcnt);
	wiremap_read_unlock();

	if (unlikely(mr->attr.base.pd != qp->attr.pd)) {
		err = DET_AE_PROTECTION_VIOLATION;
		dprintk("Protection violation\n");
		goto out;
	}
	if (unlikely(!(mr->attr.base.access & DET_AC_REMOTE_WRITE))) {
		err = DET_AE_ACCESS_VIOLATION;
		dprintk("Access violation\n");
		goto out;
	}

	base_len = mr->attr.base.length;
	if (mr->base.type == DET_TYPE_MW) {
		base_addr = ((struct det_mw*)mr)->mr->vaddr +
			    ((struct det_mw*)mr)->mr_offset;
		page_index = ((((struct det_mw*)mr)->mr->vaddr & ~PAGE_MASK) +
			       ((struct det_mw*)mr)->mr_offset) >> PAGE_SHIFT;
		pages = &((struct det_mw*)mr)->mr->pages[page_index];
	} else {
		base_addr = mr->vaddr;
		pages = mr->pages;
	}
	rdma_len = pdu->hdr.length;
	rdma_addr = NTOH64(pdu->write.rdma_address);

	/*
	 *  Make sure the request is within bounds
	 */
	if (unlikely((rdma_addr + (rdma_len - 1)) < rdma_addr)) {
		err = DET_AE_WRAP_ERROR;
		dprintk("Wrap error\n");
		goto out;
	}
	if (unlikely((rdma_addr < base_addr) ||
		     ((rdma_addr + rdma_len) > (base_addr + base_len)))) {
		err = DET_AE_BOUNDS_VIOLATION;
		dprintk("Bounds violation\n");
		goto out;
	}

	page_offset = rdma_addr & ~PAGE_MASK;
	page_index = ((rdma_addr - base_addr) +
		      (base_addr & ~PAGE_MASK)) >> PAGE_SHIFT;

	/*
	 *  Place data for operation. Routine will handle
	 *  page boundary crossings
	 */
	err = det_schedule_dma(qp, &pages[page_index],
				  page_offset, skb, rdma_len);
	if (unlikely(err))
		goto out;

	if (wr) {
		wr->sar.rea.final_length += rdma_len;
		if (det_pdu_is_last(pdu->hdr.opcode)) {
			/*
			 *  We've got the last of the write data
			 */
			atomic_set(&wr->state, WR_STATE_LAST_SEEN);
			wr->sar.rea.immediate_data = pdu->write.immed_data;
			wr->sar.rea.last_packet_seq = pdu->hdr.seq_num;
			wr->sar.rea.opcode = pdu->hdr.opcode;
		}
	}
out:
	if (atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);
	return err;
}


static int det_process_read(struct det_qp * const qp,
			    const union det_pdu * const pdu,
			    struct sk_buff * const skb)
{
	struct det_wr *uninitialized_var(wr);
	struct det_mr *mr;
	u64 base_addr, rdma_addr;
	u32 base_len, rdma_len;
	int err;

#ifdef	CONFIG_DET_DEBUG
	qp->wirestate.iq_tx.next_msg_id++;
#endif

	/*
	 *  Look up the mr/mw
	 */
	wiremap_read_lock();
	mr = idr_find(&det_wire_map, NTOH32(pdu->read_req.rdma_key));
	if (unlikely(!mr || ((mr->base.type != DET_TYPE_MR)  &&
			     (mr->base.type != DET_TYPE_MW)) ||
		     (mr->attr.base.r_key != NTOH32(pdu->read_req.rdma_key)))) {
		wiremap_read_unlock();
		dprintk("Invalid key\n");
		return DET_AE_INVALID_RDMA_KEY;
	}
	atomic_inc(&mr->base.refcnt);
	wiremap_read_unlock();

	if (unlikely(mr->attr.base.pd != qp->attr.pd)) {
		err = DET_AE_PROTECTION_VIOLATION;
		dprintk("Protection violation\n");
		goto out;
	}
	if (unlikely(!(mr->attr.base.access & DET_AC_REMOTE_READ))) {
		err = DET_AE_ACCESS_VIOLATION;
		dprintk("Access violation\n");
		goto out;
	}

	base_len = mr->attr.base.length;
	if (mr->base.type == DET_TYPE_MW) {
		base_addr = ((struct det_mw*)mr)->mr->vaddr +
			    ((struct det_mw*)mr)->mr_offset;
		mr = ((struct det_mw*)mr)->mr;
	} else {
		base_addr = mr->vaddr;
	}

	/*
	 *  Make sure the request is within bounds
	 */
	rdma_addr = NTOH64(pdu->read_req.rdma_address);
	rdma_len = NTOH32(pdu->read_req.rdma_length);
	if (unlikely((rdma_addr + (rdma_len - 1)) < rdma_addr)) {
		err = DET_AE_WRAP_ERROR;
		dprintk("Wrap error\n");
		goto out;
	}
	if (unlikely((rdma_addr < base_addr) ||
		     ((rdma_addr + rdma_len) > (base_addr + base_len)))) {
		err = DET_AE_BOUNDS_VIOLATION;
		dprintk("Bounds violation\n");
		goto out;
	}

	/*
	 *  Make out a wr for the return data
	 */
	err = det_reserve_iq_wqe(qp, &wr);
	if (unlikely(err)) {
		err = (err == -ENOSPC) ? DET_AE_MAX_IR_EXCEEDED :
					 DET_AE_QP_FATAL;
		dprintk("Queue overrun\n");
		goto out;
	}

	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_RDMA_READ_RESP;
	wr->total_length = rdma_len;
	wr->msg_id = NTOH32(pdu->read_req.rdma_id);
	wr->id = 0;
	wr->flags = 0;

	wr->num_ds = 1;
	wr->ds_array[0].mr = mr;
	wr->ds_array[0].offset = rdma_addr - mr->vaddr;
	wr->ds_array[0].length = rdma_len;
	wr->ds_array[0].in_use = 1;

	atomic_set(&wr->state, WR_STATE_WAITING);

	/*
	 *  Post wr to the iq and schedule
	 */
	det_append_iq_wqe(qp);
	qp->reschedule_flags |= DET_SCHEDULE_NEW;
	return 0;
out:
	if (atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);

	return err;
}


static int det_process_read_resp(struct det_qp * const qp,
				 const union det_pdu * const pdu,
				 struct sk_buff * const skb)
{
	struct det_wr *wr;
	struct det_ds *ds;
	struct det_mr *mr;
	int err;
	int page_index;
	u32 page_offset;
	u32 len_remaining;
	u32 dma_len;
	u32 seq_num;
	u32 rdma_offset;
	u32 ds_offset;
	u32 seg_num;

	/*
	 *  Find the requesting wr by message ID
	 */
	wr = det_wr_by_msg_id(&qp->sq, NTOH32(pdu->read_rsp.rdma_id));
	if (unlikely(!wr || (wr->type != DET_WR_RDMA_READ))) {
		dprintk("Invalid RDMA ID\n");
		return DET_AE_INVALID_RDMA_ID;
	}

	/*
	 *  Remove PDU header
	 */
	skb_pull(skb, sizeof(pdu->read_rsp));
	seq_num = pdu->hdr.seq_num;
	rdma_offset = NTOH32(pdu->read_rsp.rdma_offset);
	len_remaining = pdu->hdr.length;
	if (!len_remaining) {
		/* these just keep the compiler from complaining */
		ds = NULL;
		dma_len = 0;
		ds_offset = 0;
		goto no_data;
	}

	/*
	 *  See if we can use our ds cache
	 */
	if (likely((wr->sar.rea.current_ds != NULL) &&
		   (wr->sar.rea.last_seen_seq == seq_num-1))) {
		/*
		 *  Take cached entires
		 */
		ds = wr->sar.rea.current_ds;
		mr = ds->mr;
		ds_offset = wr->sar.rea.current_ds_offset;
		seg_num = (ds - wr->ds_array) / sizeof(struct det_ds);
	} else {
		ds_offset = rdma_offset;
		ds = wr->ds_array;
		seg_num = 0;
		while (ds_offset > ds->length) {
			ds_offset -= ds->length;
			ds++;
			seg_num++;
		}
		mr = ds->mr;
		assert(mr->base.type == DET_TYPE_MR);
	}

	/*
	 *  Place data for this descriptor. Routine will handle
	 *  page boundary crossings
	 */
next_ds:
	if (unlikely(seg_num >= wr->num_ds)) {
		dprintk(
	"DS botch: seq=%d last_seen_seq=%d rdma_offset=%d pdu_len=%d "
	"len_remaining=%d seg_num=%d num_ds=%d last_in_seq=%d\n",
			seq_num, wr->sar.rea.last_seen_seq, rdma_offset,
			pdu->hdr.length, len_remaining, seg_num, wr->num_ds,
			atomic_read(&qp->wirestate.iq_rx.last_in_seq));
		return DET_AE_INVALID_LENGTH;
	}
	assert(mr->base.type == DET_TYPE_MR);
	page_offset = ds->offset + ds_offset + (mr->vaddr & ~PAGE_MASK);

	page_index = page_offset >> PAGE_SHIFT;
	page_offset &= ~PAGE_MASK;
	dma_len = min(ds->length - ds_offset, len_remaining);

	err = det_schedule_dma(qp, &mr->pages[page_index], page_offset,
			       skb, dma_len);
	if (unlikely(err)) {
		return err;
	}

	len_remaining -= dma_len;
	if (len_remaining) {
		ds++;
		seg_num++;
		mr = ds->mr;
		ds_offset = 0;
		skb_pull(skb, dma_len);
		goto next_ds;
	}

no_data:
	wr->sar.rea.last_seen_seq = seq_num;

	if (det_pdu_is_last(pdu->hdr.opcode)) {
		/*
		 *  We've got the last of the RDMA transfer
		 */
		atomic_set(&wr->state, WR_STATE_LAST_SEEN);
		wr->sar.rea.last_packet_seq = seq_num;
		wr->sar.rea.opcode = pdu->hdr.opcode;
		wr->sar.rea.final_length = rdma_offset + pdu->hdr.length;
		wr->sar.rea.current_ds = NULL;
	} else if ((ds_offset + dma_len) < ds->length) {
		wr->sar.rea.current_ds = ds;
		wr->sar.rea.current_ds_offset = ds_offset + dma_len;
	} else {
		/* force a validation of the next ds */
		wr->sar.rea.current_ds = NULL;
	}

	return 0;
}


static int det_process_atomic_req(struct det_qp * const qp,
				  const union det_pdu * const pdu,
				  struct sk_buff * const skb)
{
	struct det_wr *uninitialized_var(wr);
	struct det_mr *mr;
	struct page *page;
	u64 atomic_address;
	u64 atomic_val1;
	u64 atomic_val2;
	u64 base_addr;
	u64 *val_addr;
	u32 base_len;
	u32 offset;
	u32 atomic_id;
	u32 atomic_key;
	u16 opcode;
	int err;

	/*
	 *  Tease out the header values
	 */
	if (det_pdu_base_type(pdu->hdr.opcode) == det_op_comp_exch) {
		atomic_address = NTOH64(pdu->comp_exch.atomic_address);
		atomic_val1 = NTOH64(pdu->comp_exch.comp_data);
		atomic_val2 = NTOH64(pdu->comp_exch.exch_data);
		atomic_key = pdu->comp_exch.atomic_key;
		atomic_id = NTOH32(pdu->comp_exch.atomic_id);
		opcode = det_op_comp_exch_resp;
	} else {
		atomic_address = pdu->fetch_add.atomic_address;
		atomic_val1 = NTOH64(pdu->fetch_add.add_data);
		atomic_val2 = 0; /* compiler happyness */
		atomic_key = pdu->fetch_add.atomic_key;
		atomic_id = NTOH32(pdu->fetch_add.atomic_id);
		opcode = det_op_fetch_add_resp;
	}

#ifdef	CONFIG_DET_DEBUG
	qp->wirestate.iq_tx.next_msg_id++;
#endif

	/*
	 *  Look up the mr/mw
	 */
	wiremap_read_lock();
	mr = idr_find(&det_wire_map, atomic_key);
	if (unlikely(!mr || ((mr->base.type != DET_TYPE_MR)  &&
			     (mr->base.type != DET_TYPE_MW)) ||
		     (mr->attr.base.r_key != atomic_key))) {
		wiremap_read_unlock();
		dprintk("Invalid key\n");
		return DET_AE_INVALID_ATOMIC_KEY;
	}
	atomic_inc(&mr->base.refcnt);
	wiremap_read_unlock();

	if (unlikely(mr->attr.base.pd != qp->attr.pd)) {
		dprintk("Protection violation\n");
		err = DET_AE_PROTECTION_VIOLATION;
		goto error;
	}
	if (unlikely((mr->attr.base.access &
			(DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE)) !=
			(DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE))) {
		dprintk("Access violation\n");
		err =  DET_AE_ACCESS_VIOLATION;
		goto error;
	}

	base_len = mr->attr.base.length;
	if (mr->base.type == DET_TYPE_MW) {
		base_addr = ((struct det_mw*)mr)->mr->vaddr +
			    ((struct det_mw*)mr)->mr_offset;
		mr = ((struct det_mw*)mr)->mr;
	} else {
		base_addr = mr->vaddr;
	}

	/*
	 *  Make sure the request is within bounds
	 */
	if (unlikely((atomic_address + (sizeof(atomic_val1) - 1)) <
		      atomic_address)) {
		dprintk("Wrap error\n");
		err =  DET_AE_WRAP_ERROR;
		goto error;
	}
	if (unlikely((atomic_address < base_addr) ||
		     ((atomic_address + sizeof(atomic_val1)) >
		      (base_addr + base_len)))) {
		dprintk("Bounds violation\n");
		err = DET_AE_BOUNDS_VIOLATION;
		goto error;
	}

	/*
	 *  Allocate wr for the return data
	 */
	err = det_reserve_iq_wqe(qp, &wr);
	if (unlikely(err)) {
		dprintk("Queue overrun\n");
		err  = (err == -ENOSPC) ? DET_AE_MAX_IR_EXCEEDED :
					  DET_AE_QP_FATAL;
		goto error;
	}

	/*
	 *  Map an address to the atomic target
	 */
	offset = (atomic_address - mr->vaddr) + (mr->vaddr & ~PAGE_MASK);
	page = mr->pages[offset >> PAGE_SHIFT];
	offset &= ~PAGE_MASK;
	val_addr = det_kmap_src(page) + offset;

	/* Lock to perform the atomic operation. */
	det_spin_lock_bh(&qp->scheduler->atomic_lock);

	/* Save the original data */
	wr->atomic_resp.orig_data = HTON64(*val_addr);

	if (det_pdu_base_type(pdu->hdr.opcode) == det_op_comp_exch) {
		/* Compare and exchange if equal */
		if (*val_addr == atomic_val1) {
			*val_addr  = atomic_val2;
			flush_dcache_page(page);
			if (!PageReserved(page))
				set_page_dirty(page);
		}
	} else {
		/* Add value */
		*val_addr += atomic_val1;
		flush_dcache_page(page);
		if (!PageReserved(page))
			set_page_dirty(page);
	}

	/* Unlock - atomic operation is complete. */
	det_spin_unlock_bh(&qp->scheduler->atomic_lock);

	det_kunmap_src(page, val_addr);

	/*
	 *  Construct the wr to get the result returned
	 */
	memset(&wr->sar, 0, sizeof(wr->sar));
	det_reset_timeout(wr);

	wr->type = DET_WR_ATOMIC_RESP;
	wr->total_length = 0;
	wr->msg_id = atomic_id;
	wr->atomic_resp.opcode = opcode;
	wr->id = 0;
	wr->flags = 0;
	wr->num_ds = 0;
	atomic_set(&wr->state, WR_STATE_WAITING);

	/*
	 *  Post wr to the iq and schedule
	 */
	det_append_iq_wqe(qp);
	qp->reschedule_flags |= DET_SCHEDULE_NEW;

error:
	if (atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);
	return err;
}


static int det_process_atomic_resp(struct det_qp * const qp,
				   const union det_pdu * const pdu,
				   struct sk_buff * const skb)
{
	struct det_wr *wr;
	struct det_ds *ds;
	struct det_mr *mr;
	int err;
	int page_index;
	u32 page_offset;
	u32 len_remaining;
	u32 dma_len;
	u32 ds_offset;
	u32 seg_num;

	/*
	 *  Find the requesting wr by message ID
	 */
	wr = det_wr_by_msg_id(&qp->sq, NTOH32(pdu->atomic_rsp.atomic_id));
	if (unlikely(!wr || (wr->type !=
		(det_pdu_base_type(pdu->hdr.opcode) == det_op_comp_exch_resp ?
						       DET_WR_ATOMIC_COMP_EXCH :
						       DET_WR_ATOMIC_FETCH_ADD)))) {
		dprintk("Invalid ATOMIC ID\n");
		return DET_AE_INVALID_ATOMIC_ID;
	}

	ds = wr->ds_array;
	mr = ds->mr;
	assert(mr->base.type == DET_TYPE_MR);
	len_remaining = sizeof(pdu->atomic_rsp.orig_data);
	skb_pull(skb, (unsigned long)&pdu->atomic_rsp.orig_data -
		      (unsigned long)pdu);
	ds_offset = 0;
	seg_num = 0;

	/*
	 *  Place data for this descriptor. Routine will handle
	 *  page boundary crossings
	 */
next_ds:
	if (seg_num >= wr->num_ds)
		return DET_AE_INVALID_LENGTH;

	page_offset = ds->offset + ds_offset + (mr->vaddr & ~PAGE_MASK);
	page_index = page_offset >> PAGE_SHIFT;
	page_offset &= ~PAGE_MASK;
	dma_len = min(ds->length - ds_offset, len_remaining);

	err = det_schedule_dma(qp, &mr->pages[page_index], page_offset,
			       skb, dma_len);
	if (unlikely(err))
		return err;

	len_remaining -= dma_len;
	if (len_remaining) {
		ds++;
		seg_num++;
		mr = ds->mr;
		assert(mr->base.type == DET_TYPE_MR);
		ds_offset = 0;
		skb_pull(skb, dma_len);
		goto next_ds;
	}

	atomic_set(&wr->state, WR_STATE_LAST_SEEN);
	wr->sar.rea.last_packet_seq = pdu->hdr.seq_num;
	wr->sar.rea.opcode = 0;
	wr->sar.rea.final_length = sizeof(pdu->atomic_rsp.orig_data);
	wr->sar.rea.current_ds = NULL;

	return 0;
}


static int det_process_disconnect(struct det_qp * const qp,
				  const union det_pdu * const pdu,
				  struct sk_buff * const skb)
{
	if (unlikely(NTOH32(pdu->disconnect.code) != DET_AE_DISCONNECT))
		printk(KERN_NOTICE "Received abnormal disconnect: %d\n",
			NTOH32(pdu->disconnect.code));
	if (!qp_is_co_member(qp))
		det_qp_remote_disconnect(qp, NTOH32(pdu->disconnect.code));

	return 0;
}


static int det_process_snack(struct det_qp * const qp,
			     const union det_pdu * const pdu,
			     struct sk_buff * const skb)
{
	/*
	 *  Setup for the proper stream
	 */
	if (det_pdu_is_iq(pdu->hdr.opcode)) {
		atomic_set(&qp->wirestate.iq_tx.snack_edge, 
			   NTOH32(pdu->snack.seq_edge));
	} else {
		atomic_set(&qp->wirestate.sq_tx.snack_edge, 
			   NTOH32(pdu->snack.seq_edge));
	}

	qp->reschedule_flags |= DET_SCHEDULE_RETRY;

	DET_STAT(snacks_recvd++);

	return 0;
}


static int det_process_sq_ack(struct det_qp *const qp,
			      const u32 seq_num)
{
	struct det_wr *wr = NULL;
	struct det_tx_state *tx = &qp->wirestate.sq_tx;
	struct det_wq *wq = &qp->sq;
	int status = 0;
	int err = 0;
	int throttled;
	u32 target;

	/* optimization */
	if (!wq->depth)
		return 0;

	/* if this is old news, get out */
	if (!seq_after(seq_num, atomic_read(&tx->last_ack_seq_recvd)))
		return 0;

	/* Capture if window was closed before updating */
	throttled = (det_tx_window(tx) == 0);
	atomic_set(&tx->last_ack_seq_recvd, seq_num);

	/*
	 *  If were were throttled and now have an open window or
	 *  simply up to date, resume streaming transfers.  This
	 *  can be overwritten with other reschedule state below....
	 */
	if (throttled && det_tx_window(tx))
		status = DET_SCHEDULE_RESUME;

	assert(wq->size);
	sq_lock_bh(&wq->lock);
	for (target = (wq->head + wq->completion_cnt) % wq->size;
	     target != wq->tail;
	     target = (target + 1) % wq->size) {

		wr = det_get_wr(wq, target);

		/*
		 *  Get out if the WR hasn't been scheduled yet.
		 *  or is within or before this WR
		 */
		if (atomic_read(&wr->state) == WR_STATE_WAITING)
			break;

		if (seq_after(wr->sar.seg.ending_seq, seq_num)) {
			/*
			 *  Deal with uncompleted timed out requests
			 */
			if (wr->sar.seg.timeout_cnt) {
				if (!det_tx_unacked_window(tx)) {
					status = DET_SCHEDULE_RESUME;
				} else if (seq_num ==
					   atomic_read(&wr->sar.seg.last_timeout_seq_sent)) {
					/* we know where we are so retry unacked */
					atomic_set(&tx->snack_edge,
						   atomic_read(&tx->next_seq));
					status = DET_SCHEDULE_RETRY;
				} else {
					/*
					 *  Negate possible eager RESUME
					 *  set before loop - we're still
					 *  retrying this WR.
					 */
					status = 0;
				}
				/*
				 *  If progress of some sort is being made
				 *  then reset the timeout retry counters
				 */
				if (status)
					det_reset_timeout(wr);
			}
			/*
			 *  Deal with up to date WR
			 */
			else if ((atomic_read(&wr->state) == WR_STATE_STARTED) &&
				   !det_tx_unacked_window(tx)) {
				status = DET_SCHEDULE_RESUME;
			}

			break;
		}

		/*
		 *  We seem to have a completed request. Deal with
		 *  request/reaponse types....
		 */
		if ((wr->type == DET_WR_RDMA_READ) ||
		    (wr->type == DET_WR_ATOMIC_COMP_EXCH) ||
		    (wr->type == DET_WR_ATOMIC_FETCH_ADD)) {
			/*
			 *  We have an IQ request acknowledgment.  Note the
			 *  state change so it isn't retried.
			 *
			 *  BTW, IQ requests are completed in the
			 *  det_schedule_rx_completions() routine when
			 *  the requested data has arrived.
			 */
			if (atomic_read(&wr->state) == WR_STATE_WAITING_FOR_ACK)
				atomic_set(&wr->state, WR_STATE_WAITING_FOR_RESP);

		} else if (atomic_read(&wr->state) != WR_STATE_COMPLETED) {
			/*
			 *  Request is complete so no need to keep the ds references
			 */
			det_clear_ds_refs(wr->ds_array, wr->num_ds);
			atomic_set(&wr->state, WR_STATE_COMPLETED);
		}
	}
	sq_unlock_bh(&wq->lock);

	err = __det_process_sq_completions(qp);
	if (unlikely(err)) {
		det_process_proto_error(qp, err);
		status = 0;
	}

	return status;
}


static int det_process_iq_ack(struct det_qp * const qp,
			      const u32 seq_num)
{
	struct det_wr *wr = NULL;
	struct det_tx_state *tx = &qp->wirestate.iq_tx;
	struct det_wq *wq = &qp->iq;
	int throttled;
	int status = 0;
	u32 target;

	/* optimization */
	if (!wq->size || !wq->depth)
		return 0;

	/* if this is old news, get out */
	if (!seq_after(seq_num, atomic_read(&tx->last_ack_seq_recvd)))
		return 0;

	/* Capture if window was closed before updating */
	throttled = (det_tx_window(tx) == 0);
	atomic_set(&tx->last_ack_seq_recvd, seq_num);

	/*
	 *  If were were throttled and now have an open window or
	 *  simply up to date, resume streaming transfers.  This
	 *  can be overwritten with other reschedule state below....
	 */
	if (throttled && det_tx_window(tx))
		status = DET_SCHEDULE_RESUME;

	iq_lock_bh(&wq->lock);
	for (target = wq->head;
	     wq->depth && (target != wq->tail); /* tail check is a safety */
	     target = (target + 1) % wq->size) {

		wr = det_get_wr(wq, target);
		if (atomic_read(&wr->state) == WR_STATE_WAITING)
			break;

		/*
		 *  Get out if the sequence number is within or before this WR
		 *  or the WR hasn't been scheduled yet.
		 */
		if (seq_after(wr->sar.seg.ending_seq, seq_num)) {
			/*
			 *  Deal with uncompleted retying requests
			 */
			if (wr->sar.seg.timeout_cnt) {
				if (!det_tx_unacked_window(tx)) {
					status = DET_SCHEDULE_RESUME;
				} else if (seq_num ==
					   atomic_read(&wr->sar.seg.last_timeout_seq_sent)) {
					/* we know where we are so retry unacked */
					atomic_set(&tx->snack_edge,
						   atomic_read(&tx->next_seq));
					status = DET_SCHEDULE_RETRY;
				} else {
					/*
					 *  Negate possible eager RESUME
					 *  set before loop - we're still
					 *  retrying this WR.
					 */
					status = 0;
				}
				/*
				 *  If progress of some sort is being made
				 *  then reset the timeout retry counters
				 */
				if (status)
					det_reset_timeout(wr);
			}
			/*
			 *  Deal with up to date WR
			 */
			else if ((atomic_read(&wr->state) == WR_STATE_STARTED) &&
				   !det_tx_unacked_window(tx)) {
				status = DET_SCHEDULE_RESUME;
			}

			break;
		}

		PERF_RECORD(WR_IQ_CMPLT, wr->start);

		/*
		 *  We have a completed reply. Clear references to
		 *  the memory region and remove entry
		 */
		det_clear_ds_refs(wr->ds_array, wr->num_ds);

		/*
		 *  It's much more effiecent to retire an iq wqe manually
		 *  here instead of calling det_retire_wqes()
		 */
		wq->head = (wq->head + 1) % wq->size;
		wq->depth -= 1;
	}
	iq_unlock_bh(&wq->lock);

	return status;
}


static void det_process_ack(struct det_qp * const qp,
			    const struct det_hdr * const hdr)
{
	qp->reschedule_flags |= det_process_sq_ack(qp, hdr->sq_ack_num);
	qp->reschedule_flags |= det_process_iq_ack(qp, hdr->iq_ack_num);
}


static int valid_data_seq_number(struct det_qp * const qp,
				 const union det_pdu * const pdu,
				 struct sk_buff * const skb,
				 const u32 seq_num,
				 const u16 opcode,
				 struct det_rx_state * const rx)
{
	u32 last_in_seq;

	/*
	 *  Filter out non-data packets
	 */
	if (opcode == det_op_ack      ||
	    opcode == det_op_snack_sq ||
	    opcode == det_op_snack_iq ||
	    opcode == det_op_disconnect)
		return PROCESS_FRAME;

	last_in_seq = atomic_read(&rx->last_in_seq);

	/*
	 *  Is it exactly in sequence
	 */
	if (seq_num == last_in_seq + 1)
		return PROCESS_FRAME;

	/*
	 *  Have we seen this data before?
	 */
	if (!seq_after(seq_num, last_in_seq)) {
		DET_STAT(duplicates++);
		return SEND_ACK;
	}

	/*
	 *  Sequence number is not in order and hasn't been seen before.
	 *  Process for possible SNACK.
	 */
	if (!rx->snacked) {
		/*
		 *  Beginning of a snack window
		 */
		rx->snacked = 1;
		rx->first_snack_seq = seq_num;
		rx->last_snack_seq  = seq_num;
		det_send_snack(qp, pdu, skb, det_pdu_is_iq(opcode));

		/*
		 *  OOO 'Last' PDUs are never placeable and so we
		 *  can't start a snack window with one.
		 */
		return (det_pdu_is_last(opcode)) ?
			DEFER_PLACEMENT : PROCESS_FRAME;
	}

	/*
	 *  A snack window has been started. Check if this is in the
	 *  snack window and placeable (i.e. not last)
	 */
	if (rx->last_snack_seq + 1 == seq_num) {
		rx->last_snack_seq  = seq_num;

		return (det_pdu_is_last(opcode)) ?
			DEFER_PLACEMENT : PROCESS_FRAME;
	}

	/*
	 *  The fall-through case is a second snack hole so we can't place
	 */
	DET_STAT(busted_snacks++);
	return DONT_PLACE;
}


int det_process_pdu(struct det_qp * const qp,
		    const union det_pdu * const pdu,
		    struct sk_buff * const skb,
		    int user_cntx)
{
	int err;

	switch (det_pdu_base_type(pdu->hdr.opcode)) {
		case det_op_send:
			err = det_process_send(qp, pdu, skb, user_cntx);
			break;
		case det_op_write:
			err = det_process_write(qp, pdu, skb);
			break;
		case det_op_read:
			err = det_process_read(qp, pdu, skb);
			break;
		case det_op_read_resp:
			err = det_process_read_resp(qp, pdu, skb);
			break;
		case det_op_comp_exch_resp:
		case det_op_fetch_add_resp:
			err = det_process_atomic_resp(qp, pdu, skb);
			break;
		case det_op_comp_exch:
		case det_op_fetch_add:
			err = det_process_atomic_req(qp, pdu, skb);
			break;
		case det_op_ack:
			/* handled in piggyback ack processing */
			err = 0;
			break;
		case det_op_snack_sq:
		case det_op_snack_iq:
			err = det_process_snack(qp, pdu, skb);
			break;
		case det_op_disconnect:
			/*
			 *  Post any send completions before the
			 *  this disconnect flushes the queues
			 */
			det_process_ack(qp, &pdu->hdr);

			/* now disconnect the QP */
			err = det_process_disconnect(qp, pdu, skb);
			break;
		default:
			printk("DET received invalid opcode (%x)\n",
					det_pdu_base_type(pdu->hdr.opcode));
			err = DET_AE_INVALID_OPCODE;
			break;
	}

	if (err)
		det_process_proto_error(qp, err);

	return err;
}


static int det_process_qp_skb(struct det_qp *qp,
			      struct sk_buff *skb,
			      struct det_rx_state * const rx)
{
	union det_pdu *pdu = (union det_pdu*)skb->data;
	int status, err = 0;

	/*
	 *  Start with no reschedules
	 */
	qp->reschedule_flags = 0;

	/*
	 *  If this QP is not accepting data, disconnect the other side.
	 */
	if (unlikely(qp->attr.state != DET_QP_CONNECTED)) {
		det_reflect_disconnect(&pdu->hdr, skb, DET_AE_INVALID_QP);
		status = 0;
		goto done;
	}

	status = valid_data_seq_number(qp, pdu, skb, pdu->hdr.seq_num,
				       pdu->hdr.opcode, rx);
	switch (status) {
		case PROCESS_FRAME:
			if (det_process_pdu(qp, pdu, skb, 0) == DET_AE_INVALID_OPCODE)
				return DONT_PLACE;
			break;

		case SEND_ACK:
			if (!det_pdu_is_force_ack(pdu->hdr.opcode))
				det_send_ack(qp);
			break;

		case DEFER_PLACEMENT:
			skb_queue_tail(&rx->snack_deferred, skb);
			break;

		case DONT_PLACE:
		default:
			break;
	}

	/*
	 *  Process piggybacked ack
	 */
	det_process_ack(qp, &pdu->hdr);

	if (atomic_read(&qp->dma_pending)) {
		/*
		 *  Wait on any scheduled dma from pdu processing
		 */
		err = det_wait_on_dma(qp);
		if (unlikely(err)) {
			det_process_proto_error(qp, err);
			goto done;
		}
	}

	/*
	 *  Update rx seq numbers
	 */
	if (update_rx_seq_numbers(qp, pdu, rx)) {
		/*
		 *  PDU is in sequence so schedule / remove
		 *  completed work requests
		 */
		err = det_schedule_rx_completions(qp,
				det_pdu_is_iq(pdu->hdr.opcode));
		if (unlikely(err)) {
			det_process_proto_error(qp, err);
			goto done;
		}
	}

	/*
	 *  Generate an ack if forced to or the current window dictates it.
	 */
	if (!det_pdu_is_force_ack(pdu->hdr.opcode)) {
		if ((pdu->hdr.opcode != det_op_ack)	 &&
		    (pdu->hdr.opcode != det_op_snack_sq) &&
		    (pdu->hdr.opcode != det_op_snack_iq)) {
			u32 window = det_rx_window(rx);
			if (window &&
			    (window % (det_window_size / DET_MIN_WINDOW_SIZE)) == 0)
				det_send_ack(qp);
		}
	} else {
		det_send_ack(qp);
	}

	/*
	 *  If someone requested to run the scheduler, do it.
	 */
done:
	if (qp->reschedule_flags & DET_SCHEDULE_RETRY)
		det_schedule(DET_SCHEDULE_RETRY, qp);
	if (qp->reschedule_flags & DET_SCHEDULE_RESUME) /* RESUME & NEW are the same */
		det_schedule(DET_SCHEDULE_RESUME, qp);

	return status;
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
int det_recv_pkt(struct sk_buff *skb,
		 struct net_device *netdev,
		 struct packet_type *pt,
		 struct net_device *orig_dev)
#else
int det_recv_pkt(struct sk_buff *skb,
		 struct net_device *netdev,
		 struct packet_type *pt)
#endif
#ifdef CONFIG_DET_SEQUESTER
{
	recv_queue_lock();
	skb_queue_tail(&det_recv_queue, skb);
	recv_queue_unlock();
	return 0;
}


int det_process_pkt(struct sk_buff *skb,
		    struct net_device *netdev)
#endif	/* CONFIG_DET_SEQUESTER */
{
	struct det_qp *qp = NULL;	/* silence the compiler */
	union det_pdu *pdu = (union det_pdu*)skb->data;
	int status = 0;
	PERF_DECL(start)

#ifdef DET_REENTRENCY_CHK
	static atomic_t reentry = ATOMIC_INIT(1);
	if(!atomic_dec_and_test(&reentry)) {
		printk("det_recv_pkt: Reentrancy botch!!!!\n");
		goto free_skb;
	}
#endif

	DET_STAT(packets_recvd++);
/////	PERF_RECORD(SKB_RECV, ((DET_CNTR*)skb->cb)[0]);
	PERF_GET_HRC(start);

	/*
	 *  Do echo processing without validating QP
	 */
	if (pdu->hdr.opcode == det_op_echo_req) {
		det_reflect_echo(&pdu->hdr, skb);
		goto free_skb;
	} else if (pdu->hdr.opcode == det_op_echo_resp) {
		PERF_RECORD(PERF_ECHO, pdu->echo.timestamp);
		goto free_skb;
	}

#ifdef DET_CKSUM
	if (pdu->hdr.sum != det_sum(&pdu->hdr, pdu->hdr.sum_len)) {
		dump_pdu("bad sum", &pdu->hdr);
		goto free_skb;
	}
	pdu->hdr.sum = 0xcafebabe;
	pdu->hdr.sum_len = 0xdeadbeef;
#endif

	if (det_dbg_drop_packet(pdu))
		goto free_skb;

	/*
	 *  Convert header - should be a no-op
	 */
	pdu->hdr.opcode = NTOH16(pdu->hdr.opcode);
	pdu->hdr.length = NTOH16(pdu->hdr.length);
	pdu->hdr.dst_qp = NTOH32(pdu->hdr.dst_qp);
	pdu->hdr.src_qp = NTOH32(pdu->hdr.src_qp);
	pdu->hdr.seq_num = NTOH32(pdu->hdr.seq_num);
	pdu->hdr.sq_ack_num = NTOH32(pdu->hdr.sq_ack_num);
	pdu->hdr.iq_ack_num = NTOH32(pdu->hdr.iq_ack_num);

	/*
	 *  Verify this is really addressed to us (promiscuous filter)
	 */
	if (det_pdu_is_co(pdu->hdr.opcode)) {
		if (skb->pkt_type == PACKET_MULTICAST) {
			struct dev_mc_list *mc = netdev->mc_list;
			int i = netdev->mc_count;
			while (i--) {
				if (!memcmp(mc->dmi_addr, skb_mac_header(skb),
							netdev->addr_len))
					goto ours;
				mc = mc->next;
			}
		} else if ((skb->pkt_type == PACKET_BROADCAST) ||
			   (det_hw_addr_equal(netdev->dev_addr, skb_mac_header(skb)))) {

			goto ours;
		}
		if (!memcmp(netdev->name, "lo", 2)) {
			goto ours;
		}

		DET_STAT(bad_addr++);
		goto free_skb;
	} else if (likely(det_hw_addr_equal(netdev->dev_addr, skb_mac_header(skb)) ||
			  !memcmp(netdev->name, "lo", 2))) {
		/*
		 *  Find qp for this packet.  A qp reference is taken on success.
		 */
		wiremap_read_lock();
		qp = idr_find(&det_wire_map, pdu->hdr.dst_qp);
		if (unlikely(!qp || (qp->type != DET_TYPE_QP) || !qp->valid ||
			     ((!qp_is_co_member(qp) ||
			      ( qp_is_co_member(qp) && (qp->attr.remote_qp_num != -1) )) &&
				((qp->attr.local_qp_num  != pdu->hdr.dst_qp) ||
				 (qp->attr.remote_qp_num != pdu->hdr.src_qp) ||
				 !det_hw_addr_equal(qp->attr.remote_mac.addr,
						&(skb_mac_header(skb))[DET_MAC_ADDR_LEN]))))) {

			wiremap_read_unlock();
			DET_STAT(invalid_qp++);

			/* Disconnect the rouge */
			det_reflect_disconnect(&pdu->hdr, skb, DET_AE_INVALID_QP);
			goto free_skb;
		}
		atomic_inc(&qp->refcnt);
		wiremap_read_unlock();
	} else {
		DET_STAT(bad_addr++);
		goto free_skb;
	}
ours:
	/*
	 *  If skb is a frag list (ie loopback), linerize it
	 */
#if (defined(SLE_VERSION) && (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16))) || (LINUX_VERSION_CODE >=KERNEL_VERSION(2,6,18))
	if (skb_linearize(skb))
#else
	if (skb_is_nonlinear(skb) && skb_linearize(skb, GFP_ATOMIC))
#endif
		goto free_skb;

	if (qp) {
		struct det_rx_state *rx = (det_pdu_is_iq(pdu->hdr.opcode)) ?
			&qp->wirestate.iq_rx : &qp->wirestate.sq_rx;

		status = det_process_qp_skb(qp, skb, rx);

		/*  Done with qp */
		if (atomic_dec_and_test(&qp->refcnt))
			complete(&qp->done);
	} else
		status = det_process_broadcast_pkt(skb);

free_skb:
	if (likely(status != DEFER_PLACEMENT))
		det_free_skb(skb);

	PERF_RECORD(RECV_PATH, start);
#ifdef DET_REENTRENCY_CHK
	atomic_inc(&reentry);
#endif
	return 0;
}

#endif	/* CONFIG_DET_LOOPBACK */
