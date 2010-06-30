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

#ifndef __DET_PROTOCOL_H__
#define __DET_PROTOCOL_H__

/*
 * DET ethernet packet service type
 */
#define	DET_PACKET_TYPE		0x8086


/*
 * Base DET protocol header version
 */
#define	DET_PROTOCOL_VER_1	1
#define	DET_PROTOCOL_VER	DET_PROTOCOL_VER_1


/*
 * DET opcode values - All other values are reserved.
 */
#define det_collective_flag	0x8000
#define det_last_flag		0x4000
#define det_immed_flag		0x2000
#define det_se_flag		0x1000
#define det_force_ack_flag	0x0800
#define det_iq_flag		0x0400

#define	det_op_send		0
#define	det_op_send_last	(det_op_send | det_last_flag)
#define	det_op_send_last_se	(det_op_send | det_last_flag  | det_se_flag)
#define	det_op_send_immed	(det_op_send | det_immed_flag)
#define	det_op_send_immed_se	(det_op_send | det_immed_flag | det_se_flag)

#define	det_op_write		1
#define	det_op_write_last	(det_op_write | det_last_flag)
#define	det_op_write_immed	(det_op_write | det_immed_flag)
#define	det_op_write_immed_se	(det_op_write | det_immed_flag | det_se_flag)

#define	det_op_read		2
#define	det_op_read_resp	(det_op_read      | det_iq_flag)
#define	det_op_read_resp_last	(det_op_read_resp | det_last_flag)

#define	det_op_comp_exch	3
#define det_op_comp_exch_resp	(det_op_comp_exch | det_iq_flag)

#define	det_op_fetch_add	4
#define det_op_fetch_add_resp	(det_op_fetch_add | det_iq_flag)

#define	det_op_snack		5
#define	det_op_snack_sq		(det_op_snack)
#define	det_op_snack_iq		(det_op_snack | det_iq_flag)

#define	det_op_ack		6
#define	det_op_disconnect	7
#define	det_op_echo_req		8
#define	det_op_echo_resp	9
#define det_op_join		(10 | det_collective_flag)

#define det_pdu_is_last( opcode )	(opcode & det_last_flag)
#define det_pdu_is_immed( opcode )	(opcode & det_immed_flag)
#define det_pdu_is_se( opcode )		(opcode & det_se_flag)
#define det_pdu_is_force_ack( opcode )	(opcode & det_force_ack_flag)
#define det_pdu_is_iq( opcode )		(opcode & det_iq_flag)
#define det_pdu_is_co( opcode )		(opcode & det_collective_flag)

#define det_pdu_set_last( opcode )	(opcode | det_last_flag)
#define det_pdu_set_immed( opcode )	(opcode | det_immed_flag)
#define det_pdu_set_se( opcode )	(opcode | det_se_flag)
#define det_pdu_set_force_ack( opcode )	(opcode | det_force_ack_flag)
#define det_pdu_set_iq( opcode )	(opcode | det_iq_flag)

#define det_pdu_base_type( opcode )       \
	(opcode & ~(det_last_flag       | \
		    det_se_flag         | \
		    det_immed_flag      | \
		    det_force_ack_flag ))


#define DEFAULT_DET_TIMER_PERIOD	20	/* in msec */
#define DEFAULT_DET_ACK_TIMEOUT		60	/* in sec */
#define DET_MIN_ACK_TIMEOUT		1	/* in sec */
#define DEFAULT_DET_WINDOW_SIZE		40
#define DET_MIN_WINDOW_SIZE		4
#define MAX_DET_TIMER_PERIOD		(1000/DEFAULT_DET_TIMER_PERIOD)

extern int det_timer_ack;
extern int det_max_retries;
extern int det_window_size;

#define det_seq_window( earlier, later ) \
	((earlier) > (later) ? (((u32)~0 - (earlier)) + (later)) : \
			       ((later) - (earlier)))

#define det_rx_window(rx) \
	det_seq_window((rx)->last_seq_acked, \
		       atomic_read(&((rx)->last_in_seq)))

#define det_tx_window(tx) \
	(u32)(det_window_size - det_tx_unacked_window(tx))

#define det_tx_unacked_window(tx) \
	(u32)(det_seq_window(atomic_read(&((tx)->last_ack_seq_recvd)), \
			     atomic_read(&((tx)->next_seq))-1))

#define det_hw_addr_equal(h1, h2) \
	(!memcmp(h1, h2, DET_MAC_ADDR_LEN))

#define DET_MIN_PKT_PAD(n32s, n64s) \
	u8 min_pad[46 - ((sizeof(net32_t)*(n32s)) + \
			 (sizeof(net64_t)*(n64s)) + \
			 (sizeof(struct det_hdr)))];
/*
 * Base DET header
 */
struct det_hdr {
#ifdef DET_CKSUM
	u32			sum;
	u32			sum_len;
	u32			pad[2]; /* keep header multiple of 64 bits */
#endif
	net16_t			opcode;
	net16_t			length;
	net32_t			dst_qp;
	net32_t			src_qp;
	net32_t			seq_num;
	net32_t			sq_ack_num;
	net32_t			iq_ack_num;
} __attribute__ ((packed));


/*
 * DET Send Header
 */
struct det_send_hdr {
	struct det_hdr		hdr;
	net32_t			msg_id;
	net32_t			msg_length;
	net32_t			msg_offset;
	net32_t			immed_data;

	DET_MIN_PKT_PAD(4, 0)	// net32_t's, net64_t's,

} __attribute__ ((packed));


/*
 * DET RDMA Write Header
 */
struct det_write_hdr {
	struct det_hdr		hdr;
	net64_t			rdma_address;
	net32_t			rdma_key;
	net32_t			immed_data;
	net32_t			msg_id;

	DET_MIN_PKT_PAD(3, 1)	// net32_t's, net64_t's,

} __attribute__ ((packed));


/*
 * DET RDMA Read Request Header
 */
struct det_read_req_hdr {
	struct det_hdr		hdr;
	net64_t			rdma_address;
	net32_t			rdma_key;
	net32_t			rdma_length;
	net32_t			rdma_id;

	DET_MIN_PKT_PAD(3, 1)	// net32_t's, net64_t's,

} __attribute__ ((packed));


/*
 * DET RDMA Read Response Header
 */
struct det_read_rsp_hdr {
	struct det_hdr		hdr;
	net32_t			rdma_offset;
	net32_t			rdma_id;

	DET_MIN_PKT_PAD(2, 0)	// net32_t's, net64_t's,

} __attribute__ ((packed));


/*
 * DET Atomic Compare/Exchange Header
 */
struct det_comp_exch_hdr {
	struct det_hdr		hdr;
	net64_t			atomic_address;
	net64_t			comp_data;
	net64_t			exch_data;
	net32_t			atomic_key;
	net32_t			atomic_id;

	/* no pad needed */
	/* DET_MIN_PKT_PAD(2, 3)	// net32_t's, net64_t's */

} __attribute__ ((packed));


/*
 * DET Atomic Fetch/Add Header
 */
struct det_fetch_add_hdr {
	struct det_hdr		hdr;
	net64_t			atomic_address;
	net64_t			add_data;
	net32_t			atomic_key;
	net32_t			atomic_id;

	/* no pad needed */
	/* DET_MIN_PKT_PAD(2, 2)	// net32_t's, net64_t's, */

} __attribute__ ((packed));

/*
 * DET Atomic Response Header
 */
struct det_atomic_rsp_hdr {
	struct det_hdr		hdr;
	net64_t			orig_data;
	net32_t			atomic_id;

	DET_MIN_PKT_PAD(1, 1)	// net32_t's, net64_t's,

} __attribute__ ((packed));


/*
 * DET ACK Header
 */
struct det_ack_hdr {
	struct det_hdr		hdr;

	DET_MIN_PKT_PAD(0, 0)	// net32_t's, net64_t's,

} __attribute__ ((packed));


/*
 * DET Selective NACK Header
 */
struct det_snack_hdr {
	struct det_hdr		hdr;
	net32_t			seq_edge;

	DET_MIN_PKT_PAD(1, 0)	// net32_t's, net64_t's,

} __attribute__ ((packed));


/*
 * DET Disconnect Header
 */
struct det_disconnect_hdr {
	struct det_hdr		hdr;
	net32_t			code;

	DET_MIN_PKT_PAD(1, 0)	// net32_t's, net64_t's,

} __attribute__ ((packed));


/*
 * DET Echo Header
 */
struct det_echo_hdr {
	struct det_hdr		hdr;
	net64_t			timestamp;

	DET_MIN_PKT_PAD(0, 1)	// net32_t's, net64_t's,

} __attribute__ ((packed));


/*
 * DET Join Header
 */
struct det_join_hdr {
	struct det_hdr		hdr;
	net64_t			tag;
	net32_t			root;
	net32_t			size;
	net32_t			msg_id;

	DET_MIN_PKT_PAD(3, 1)	// net32_t's, net64_t's,

} __attribute__ ((packed));


union det_pdu {
	struct det_hdr				hdr;
	struct det_send_hdr 			send;
	struct det_write_hdr			write;
	struct det_read_req_hdr			read_req;
	struct det_read_rsp_hdr			read_rsp;
	struct det_comp_exch_hdr		comp_exch;
	struct det_fetch_add_hdr		fetch_add;
	struct det_atomic_rsp_hdr		atomic_rsp;
	struct det_ack_hdr			ack;
	struct det_snack_hdr			snack;
	struct det_disconnect_hdr		disconnect;
	struct det_echo_hdr			echo;
	struct det_join_hdr			join;
};

struct det_full_frame {
	struct ethhdr	eth_hdr;
	union det_pdu	det;
};

#define ETH_HDR_SIZE sizeof(struct ethhdr)

/*
 * QP/WR backpointers overlayed in skb cb[]
 */
struct det_skb_cb {
	struct det_scheduler	*sched;
	struct det_wr		*wr;
	net64_t			timestamp;
};

#define SET_SKB_SCHED(skb, qp)	(((struct det_skb_cb*)(&skb->cb))->sched = qp->scheduler)
#define SET_SKB_WR(skb, wr)	(((struct det_skb_cb*)(&skb->cb))->wr = wr)

#define GET_SKB_SCHED(skb)	(((struct det_skb_cb*)(&skb->cb))->sched)
#define GET_SKB_WR(skb)		(((struct det_skb_cb*)(&skb->cb))->wr)


static inline int seq_before(const u32 seq1, const u32 seq2)
{
	return (s32)(seq1 - seq2) < 0;
}

static inline int seq_after(const u32 seq1, const u32 seq2)
{
	return (s32)(seq2 - seq1) < 0;
}

static inline int seq_between(const u32 seq_target, const u32 seq_low, const u32 seq_high)
{
	return seq_high - seq_low >= seq_target - seq_low;
}

#endif /* __DET_PROTOCOL_H__ */
