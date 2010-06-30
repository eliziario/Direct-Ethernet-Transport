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

struct det_seg {
	enum det_access_ctrl	access;
	struct det_ds const	*ds;
	struct det_mr		*mr;
	struct page		**page;
	void			*addr;
	u32			offset;
	u32			ds_len;
	u32			pg_len;
	void			*(*map)(struct page *page);
	void			(*unmap)(struct page *page, void *addr);
};

static inline int lb_is_sane(struct det_qp *r_qp, struct det_qp *l_qp)
{
	if (  !r_qp->loopback
	   || (r_qp->netdev != l_qp->netdev)
	   || (r_qp->attr.local_qp_num != l_qp->attr.remote_qp_num)
	   || (l_qp->attr.local_qp_num != r_qp->attr.remote_qp_num)) {
		printk(KERN_ERR
		"DET loopback botch: r_qp: loopback %d netdev %p loc qpn %d rem qpn %d\n"
		"                    l_qp: loopback %d netdev %p loc qpn %d rem qpn %d\n", 
		r_qp->loopback, r_qp->netdev, r_qp->attr.local_qp_num, r_qp->attr.remote_qp_num,
		l_qp->loopback, l_qp->netdev, l_qp->attr.local_qp_num, l_qp->attr.remote_qp_num);
		
		return 0;
	}

	return 1;
}

/*
 * Get the QP from the given QP number; otherwise return NULL.
 * If successful, a reference is held on the QP.  The caller
 * must use det_put_qp() to release the reference.  Note that
 * since no lock is held on the QP its state could change.
 */
struct det_qp *det_get_qp(const u32 qp_num)
{
	struct det_qp *qp;

	wiremap_read_lock();
	qp = idr_find(&det_wire_map, qp_num);
	if (unlikely(!qp || (qp->type != DET_TYPE_QP) || !qp->valid ||
		     (qp->attr.local_qp_num != qp_num))) {
		wiremap_read_unlock();
		return NULL;
	}
	atomic_inc(&qp->refcnt);
	wiremap_read_unlock();

	return qp;
}


/*
 * Release the reference held on a QP.
 */
static inline void det_put_qp(struct det_qp * const qp)
{
	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);
}


/*
 * Get the memory region from the given l_key; otherwise return NULL.
 * If successful, a reference is held on the memory region.  The caller
 * must use det_put_mr() to release the reference.
 */
struct det_mr *det_get_lmr(const u32 l_key)
{
	struct det_mr *mr;

	wiremap_read_lock();
	mr = idr_find(&det_wire_map, l_key);
	if (unlikely(!mr || ((mr->base.type != DET_TYPE_MR)  &&
			     (mr->base.type != DET_TYPE_MW)) ||
		     (mr->attr.l_key != l_key))) {
		wiremap_read_unlock();
		return NULL;
	}
	atomic_inc(&mr->base.refcnt);
	wiremap_read_unlock();

	return mr;
}


/*
 * Get the memory region from the given r_key; otherwise return NULL.
 * If successful, a reference is held on the memory region.  The caller
 * must use det_put_mr() to release the reference.
 */
struct det_mr *det_get_rmr(const u32 r_key)
{
	struct det_mr *mr;

	wiremap_read_lock();
	mr = idr_find(&det_wire_map, r_key);
	if (unlikely(!mr || ((mr->base.type != DET_TYPE_MR)  &&
			     (mr->base.type != DET_TYPE_MW)) ||
		     (mr->attr.base.r_key != r_key))) {
		wiremap_read_unlock();
		return NULL;
	}
	atomic_inc(&mr->base.refcnt);
	wiremap_read_unlock();

	return mr;
}


/*
 * Release the reference held on a memory region.
 */
static inline void det_put_mr(struct det_mr * const mr)
{
	if (atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);
}

static void det_seg_init(struct det_seg *seg, struct det_ds const *ds,
			 void *(*map)(struct page * page),
			 void (*unmap)(struct page *page, void *addr),
			 enum det_access_ctrl access)
{
	memset(seg, 0, sizeof *seg);
	seg->ds	    = ds;
	seg->map    = map;
	seg->unmap  = unmap;
	seg->access = access;
}

static void det_seg_fini(struct det_seg *seg)
{
	seg->unmap(*seg->page, seg->addr);
	if (likely(seg->mr))
		det_put_mr(seg->mr);
}

static int det_seg_set(struct det_seg *seg, u32 length, u32 copy_len)
{
	struct page **prev_page;

	if (!seg->ds_len) {

		if (seg->mr)
			det_put_mr(seg->mr);

		seg->mr = det_get_lmr(seg->ds->l_key);
		if (unlikely(!seg->mr))
			return DET_AE_INVALID_L_KEY;

		if (unlikely(!(seg->mr->attr.base.access & seg->access)))
			return DET_AE_ACCESS_VIOLATION;

		prev_page    = seg->page;
		seg->offset  = seg->ds->offset + (seg->mr->vaddr & ~PAGE_MASK);
		seg->page    = &seg->mr->pages[seg->offset >> PAGE_SHIFT];
		seg->offset &= ~PAGE_MASK;
		seg->ds_len  = seg->ds->length;
		seg->pg_len  = min(seg->ds_len, (u32)PAGE_SIZE - seg->offset);
		seg->pg_len  = min(seg->pg_len, length);

		if (seg->page != prev_page)
			seg->addr = seg->map(*seg->page) + seg->offset;

		seg->ds++;

	} else if (!seg->pg_len) {

		seg->unmap(*seg->page, seg->addr);

		seg->page++;
		seg->addr   = seg->map(*seg->page);
		seg->pg_len = min(seg->ds_len, (u32)PAGE_SIZE);
		seg->pg_len = min(seg->pg_len, length);
	} else
		seg->addr += copy_len;

	return 0;
}

static inline int det_seg_copy(struct det_seg *dst, struct det_seg *src, u32 length, int head_copied)
{
	src->ds_len -= length;
	src->pg_len -= length;

	dst->ds_len -= length;
	dst->pg_len -= length;

	return det_atomic_copy(dst->addr, src->addr, length, head_copied);
}

/*
 * Copy data from the source to the destination data segment list.
 * This is a bit complicated since we must map and copy each page
 * individually and because each data segment can be split across
 * multiple pages within the memory region as illustrated below:
 *
 *	+---page---+   +---page---+   +---page---+
 *	|  .~~mr~~~|~~~|~~~~~~~~~~|~~~|~~~~~~.   |
 *	|  |       |   |  [==ds===|===|====] |   |
 *	|  '~~~~~~~|~~~|~~~~~~~~~~|~~~|~~~~~~'   |
 *	+----------+   +----------+   +----------+
 *
 * For example, due to different buffer page offsets, copying data
 * between the following buffers will result in five separate copy
 * operations as shown by the numeric labels below:
 *
 *	       +----------+     +----------+
 *	       |          |     |          |
 *	       |1111111111|     |          |
 *	       |2222222222|     |1111111111|
 *	       +----------+     +----------+
 *
 *	       +----------+     +----------+
 *	       |3333333333|     |2222222222|
 *	       |3333333333|     |3333333333|
 *	       |4444444444|     |3333333333|
 *	       +----------+     +----------+
 *
 *	       +----------+     +----------+
 *	       |5555555555|     |4444444444|
 *	       |          |     |5555555555|
 *	       |          |     |          |
 *	       +----------+     +----------+
 *
 * The source and destination data segment list lengths are
 * assumed to have been validated outside of this function.
 */
int det_copy_data(struct det_ds const *dst_ds, struct det_ds const *src_ds, u32 length)
{
	struct det_seg src, dst;
	int head_copied;
	u32 copy_len;
	int err = 0;

	det_seg_init(&src, src_ds, det_kmap_src, det_kunmap_src, DET_AC_LOCAL_READ);
	det_seg_init(&dst, dst_ds, det_kmap_dst, det_kunmap_dst, DET_AC_LOCAL_WRITE);

	head_copied = 0;
	for (copy_len = 0; length; length -= copy_len) {

		err = det_seg_set(&src, length, copy_len);
		if (unlikely(err))
			break;
		err = det_seg_set(&dst, length, copy_len);
		if (unlikely(err))
			break;

		copy_len = min(src.pg_len, dst.pg_len);
		head_copied = det_seg_copy(&dst, &src, copy_len, head_copied);
	}

	det_seg_fini(&src);
	det_seg_fini(&dst);

	return err;
}


/* Hold qp->sq.lock during this call for synchronization. */
int det_complete_sq_wr(struct det_qp * const qp,
		       struct det_wr * const wr,
		       const enum det_wc_status status)
{
	struct det_wc *uninitialized_var(wc);
	int err;

	/* Complete the work request. */
	det_clear_ds_refs(wr->ds_array, wr->num_ds);
	qp->sq.completion_cnt++;
	qp->sq.reap_cnt++;

	/* Build the work completion. */
	if (!(wr->flags & DET_WR_SURPRESSED)) {
		err = det_reserve_cqe(qp->attr.sq_cq, &wc);
		if (unlikely(err))
			return (err == -ENOSPC) ? DET_AE_CQ_OVERRUN :
						  DET_AE_CQ_FATAL;
		wc->id = wr->id;
		wc->status = status;
		wc->type = wr->type;
		wc->flags = 0;
		wc->immediate_data = 0;
		if (wr->type == DET_WR_RDMA_READ)
			wc->length = wr->read.remote_length;
		else if ((wr->type == DET_WR_ATOMIC_COMP_EXCH) ||
			 (wr->type == DET_WR_ATOMIC_FETCH_ADD))
			wc->length = sizeof(wr->atomic_resp.orig_data);
		else
			wc->length = 0;
		wc->reserved = (unsigned long)&qp->sq;
		wc->reap_cnt = qp->sq.reap_cnt;
		qp->sq.reap_cnt = 0;
		det_append_cqe(qp->attr.sq_cq, wc);
	}

	return 0;
}


/* Hold qp->rq.lock during this call for synchronization. */
int det_complete_rq_wr(struct det_qp * const qp,
		       struct det_wr * const wr,
		       const enum det_wc_status status,
		       const enum det_wc_flags flags,
		       const net32_t immediate_data,
		       const u32 length)
{
	struct det_wc *uninitialized_var(wc);
	int err;

	det_clear_ds_refs(wr->ds_array, wr->num_ds);

#ifdef	DET_TRIGGERED_WR
	if (wr->signal) {
		/* No work completions from signaling receives. */
		qp->rq.head = (qp->rq.head + 1) % qp->rq.size;
		qp->rq.depth--;
		if (!atomic_add_negative(1, &wr->signal->sq.gate))
			det_schedule(DET_SCHEDULE_NEW, wr->signal);
		return 0;
	}
#endif

	/* Complete the receive work request. */
	qp->rq.completion_cnt++;
	qp->rq.reap_cnt++;

	/* Build the receive work completion. */
	err = det_reserve_cqe(qp->attr.rq_cq, &wc);
	if (unlikely(err))
		return (err == -ENOSPC) ? DET_AE_CQ_OVERRUN :
					  DET_AE_CQ_FATAL;
	wc->id = wr->id;
	wc->status = status;
	wc->type = wr->type;
	wc->flags = 0;
	if (flags & DET_WR_SOLICITED)
		wc->flags = DET_WC_SOLICITED;
	if (flags & DET_WR_IMMEDIATE) {
		wc->flags |= DET_WC_IMMEDIATE;
		wc->immediate_data = NTOH32(immediate_data);
	}
	wc->length = length;
	wc->reserved = (unsigned long)&qp->rq;
	wc->reap_cnt = qp->rq.reap_cnt;
	qp->rq.reap_cnt = 0;
	det_append_cqe(qp->attr.rq_cq, wc);

	return 0;
}


int det_loopback_send(struct det_qp * const l_qp,
		      struct det_qp * const r_qp,
		      struct det_wr * const send_wr)
{
	struct det_wq *r_wq;
	struct det_wr *recv_wr;
	u32 next;
	int err;

	r_wq = &r_qp->rq;
	rq_lock_bh(&r_wq->lock);

	if (r_qp->attr.state != DET_QP_CONNECTED) {
		err = DET_AE_INVALID_QP;
		goto out;
	}

	/* Collective QPs violate these sanity checks during join. */
	if (!qp_is_co_member(l_qp) && !qp_is_co_member(r_qp)) {
		/* Sanity checks. */
		if (!lb_is_sane(r_qp, l_qp)) {
			err = DET_AE_QP_ERROR;
			goto out;
		}
	}

	if (unlikely(!r_wq->size)) {
		err = DET_AE_QP_RQ_ERROR;
		goto out;
	}

	next = (r_wq->head + r_wq->completion_cnt) % r_wq->size;
	if (unlikely(next == r_wq->tail)) {
		err = DET_AE_QP_RQ_ERROR;
		goto out;
	}

	recv_wr = det_get_wr(r_wq, next);

	if (likely(send_wr->total_length)) {
		if (unlikely(send_wr->total_length > recv_wr->total_length)) {
			err = DET_AE_BOUNDS_VIOLATION;
			goto out;
		}

		err = det_copy_data(recv_wr->ds_array,
				    send_wr->ds_array,
				    send_wr->total_length);
		if (unlikely(err))
			goto out;
	}

	err = det_complete_rq_wr(r_qp, recv_wr, DET_WS_SUCCESS,
		send_wr->flags, send_wr->send.immediate_data,
		send_wr->total_length);

out:
	rq_unlock_bh(&r_wq->lock);

	return err;
}


int det_loopback_read(struct det_qp * const l_qp,
		      struct det_qp * const r_qp,
		      struct det_wr * const read_wr)
{
	struct det_mr *src_mr;
	struct det_mr *mr;
	struct det_ds src_ds;
	u64 base_address;
	u64 rdma_address;
	u32 base_length;
	u32 rdma_length;
	int err = 0;

	src_mr = NULL;

	iq_lock_bh(&r_qp->iq.lock);

	if (r_qp->attr.state != DET_QP_CONNECTED) {
		err = DET_AE_INVALID_QP;
		goto out;
	}

	/* Sanity checks. */
	if (!lb_is_sane(r_qp, l_qp)) {
		err = DET_AE_QP_ERROR;
		goto out;
	}

	if (!r_qp->attr.max_ir) {
		err = DET_AE_MAX_IR_EXCEEDED;
		goto out;
	}

	if (likely(read_wr->read.remote_length)) {

		src_mr = det_get_rmr(NTOH32(read_wr->read.remote_key));
		if (unlikely(!src_mr)) {
			err =  DET_AE_INVALID_RDMA_KEY;
			goto out;
		}

		if (unlikely(src_mr->attr.base.pd != r_qp->attr.pd)) {
			err =  DET_AE_PROTECTION_VIOLATION;
			goto out;
		}

		if (unlikely(!(src_mr->attr.base.access &
				DET_AC_REMOTE_READ))) {
			err =  DET_AE_ACCESS_VIOLATION;
			goto out;
		}

		base_length = src_mr->attr.base.length;
		if (src_mr->base.type == DET_TYPE_MW) {
			base_address = ((struct det_mw*)src_mr)->mr->vaddr +
				       ((struct det_mw*)src_mr)->mr_offset;
			mr = ((struct det_mw*)src_mr)->mr;
			atomic_inc(&mr->base.refcnt);
			det_put_mr(src_mr);
			src_mr = mr;
		} else
			base_address = src_mr->vaddr;

		rdma_address = NTOH64(read_wr->read.remote_address);
		rdma_length  = NTOH32(read_wr->read.remote_length);

		/* Make sure the request is within bounds. */
		if (unlikely((rdma_address + (rdma_length-1)) < rdma_address)) {
			err =  DET_AE_WRAP_ERROR;
			goto out;
		}
		if (unlikely((rdma_address < base_address) ||
			     ((rdma_address + rdma_length) >
			      (base_address + base_length)))) {
			err =  DET_AE_BOUNDS_VIOLATION;
			goto out;
		}

		/* Build a source data segment entry for the data copy. */
		src_ds.mr     = src_mr;
		src_ds.offset = rdma_address - src_mr->vaddr;
		src_ds.length = rdma_length;
		src_ds.l_key  = src_mr->attr.l_key;

		err = det_copy_data(read_wr->ds_array, &src_ds, rdma_length);
	}

out:
	if (src_mr)
		det_put_mr(src_mr);

	iq_unlock_bh(&r_qp->iq.lock);

	atomic_dec(&l_qp->or_posted);

	return err;
}


int det_loopback_write(struct det_qp * const l_qp,
		       struct det_qp * const r_qp,
		       struct det_wr * const write_wr)
{
	struct det_mr *dst_mr;
	struct det_mr *mr;
	struct det_ds dst_ds;
	struct det_wq *r_wq;
	struct det_wr *recv_wr;
	u64 base_address;
	u64 rdma_address;
	u32 base_length;
	u32 rdma_length;
	u32 next;
	int err = 0;

	dst_mr = NULL;

	r_wq = &r_qp->rq;
	rq_lock_bh(&r_wq->lock);

	if (r_qp->attr.state != DET_QP_CONNECTED) {
		err = DET_AE_INVALID_QP;
		goto out;
	}

	/* Sanity checks. */
	if (!lb_is_sane(r_qp, l_qp)) {
		err = DET_AE_QP_ERROR;
		goto out;
	}

	if (write_wr->flags & DET_WR_IMMEDIATE) {
		next = (r_wq->head + r_wq->completion_cnt) % r_wq->size;
		if (unlikely(next == r_wq->tail)) {
			err = DET_AE_QP_RQ_ERROR;
			goto out;
		}
		recv_wr = det_get_wr(r_wq, next);
	} else
		recv_wr = NULL;

	if (likely(write_wr->total_length)) {

		dst_mr = det_get_rmr(NTOH32(write_wr->write.remote_key));
		if (unlikely(!dst_mr)) {
			err =  DET_AE_INVALID_RDMA_KEY;
			goto out;
		}

		if (unlikely(dst_mr->attr.base.pd != r_qp->attr.pd)) {
			err =  DET_AE_PROTECTION_VIOLATION;
			goto out;
		}

		if (unlikely(!(dst_mr->attr.base.access &
				DET_AC_REMOTE_WRITE))) {
			err =  DET_AE_ACCESS_VIOLATION;
			goto out;
		}

		base_length = dst_mr->attr.base.length;
		if (dst_mr->base.type == DET_TYPE_MW) {
			base_address = ((struct det_mw*)dst_mr)->mr->vaddr +
				       ((struct det_mw*)dst_mr)->mr_offset;
			mr = ((struct det_mw*)dst_mr)->mr;
			atomic_inc(&mr->base.refcnt);
			det_put_mr(dst_mr);
			dst_mr = mr;
		} else {
			base_address = dst_mr->vaddr;
		}

		rdma_address = NTOH64(write_wr->write.remote_address);
		rdma_length  = write_wr->total_length;

		/* Make sure the request is within bounds. */
		if (unlikely((rdma_address + (rdma_length-1)) < rdma_address)) {
			err =  DET_AE_WRAP_ERROR;
			goto out;
		}
		if (unlikely((rdma_address < base_address) ||
			     ((rdma_address + rdma_length) >
			      (base_address + base_length)))) {
			err =  DET_AE_BOUNDS_VIOLATION;
			goto out;
		}

		/* Build a destination data segment entry for the data copy. */
		dst_ds.mr     = dst_mr;
		dst_ds.offset = rdma_address - dst_mr->vaddr;
		dst_ds.length = rdma_length;
		dst_ds.l_key  = dst_mr->attr.l_key;

		err = det_copy_data(&dst_ds, write_wr->ds_array, rdma_length);
		if (unlikely(err))
			goto out;
	}

	if (recv_wr) {
		err = det_complete_rq_wr(r_qp, recv_wr, DET_WS_SUCCESS,
			write_wr->flags, write_wr->write.immediate_data,
			write_wr->total_length);
	}

out:
	if (dst_mr)
		det_put_mr(dst_mr);

	rq_unlock_bh(&r_wq->lock);

	return err;
}


int det_loopback_comp_exch(struct det_qp * const l_qp,
			   struct det_qp * const r_qp,
			   struct det_wr * const comp_exch_wr)
{
	struct det_ds src_ds;
	struct det_mr *src_mr;
	struct det_mr *mr;
	struct page *src_page;
	u64 *src_addr;
	u64 base_address;
	u64 atom_address;
	u32 src_offset;
	u32 base_length;
	u32 atom_length;
	int err = 0;

	src_mr = NULL;

	iq_lock_bh(&r_qp->iq.lock);

	if (r_qp->attr.state != DET_QP_CONNECTED) {
		err = DET_AE_INVALID_QP;
		goto out;
	}

	/* Sanity checks. */
	if (!lb_is_sane(r_qp, l_qp)) {
		err = DET_AE_QP_ERROR;
		goto out;
	}

	if (!r_qp->attr.max_ir) {
		err = DET_AE_MAX_IR_EXCEEDED;
		goto out;
	}

	src_mr = det_get_rmr(NTOH32(comp_exch_wr->comp_exch.remote_key));
	if (unlikely(!src_mr)) {
		err =  DET_AE_INVALID_ATOMIC_KEY;
		goto out;
	}

	if (unlikely(src_mr->attr.base.pd != r_qp->attr.pd)) {
		err =  DET_AE_PROTECTION_VIOLATION;
		goto out;
	}

	if (unlikely((src_mr->attr.base.access &
			(DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE)) !=
			(DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE))) {
		err =  DET_AE_ACCESS_VIOLATION;
		goto out;
	}

	base_length = src_mr->attr.base.length;
	if (src_mr->base.type == DET_TYPE_MW) {
		base_address = ((struct det_mw*)src_mr)->mr->vaddr +
			       ((struct det_mw*)src_mr)->mr_offset;
		mr = ((struct det_mw*)src_mr)->mr;
		atomic_inc(&mr->base.refcnt);
		det_put_mr(src_mr);
		src_mr = mr;
	} else
		base_address = src_mr->vaddr;

	atom_address = NTOH64(comp_exch_wr->comp_exch.remote_address);
	atom_length  = 8;

	/* Check for 64-bit alignment. */
	if (atom_address & (atom_length - 1)) {
		err = DET_AE_QP_ERROR;
		goto out;
	}

	/* Make sure the request is within bounds. */
	if (unlikely((atom_address + (atom_length - 1)) < atom_address)) {
		err =  DET_AE_WRAP_ERROR;
		goto out;
	}
	if (unlikely((atom_address < base_address) ||
		     ((atom_address + atom_length) >
		      (base_address + base_length)))) {
		err =  DET_AE_BOUNDS_VIOLATION;
		goto out;
	}

	/* Build a source data segment entry for the data copy. */
	src_ds.mr     = src_mr;
	src_ds.offset = atom_address - src_mr->vaddr;
	src_ds.length = atom_length;
	src_ds.l_key  = src_mr->attr.l_key;

	/* Determine which page to map. */
	src_offset = src_ds.offset + (src_mr->vaddr & ~PAGE_MASK);
	src_page = src_mr->pages[src_offset >> PAGE_SHIFT];
	src_offset &= ~PAGE_MASK;

	/* Lock to perform the atomic operation. */
	det_spin_lock_bh(&r_qp->scheduler->atomic_lock);

	/* Fetch the original data - this handles any page crossing. */
	err = det_copy_data(comp_exch_wr->ds_array, &src_ds, atom_length);
	if (likely(!err)) {
		/* Map source the page so we can read the memory directly. */
		src_addr = det_kmap_src(src_page) + src_offset;

		/* Compare and exchange. */
		if (*src_addr == NTOH64(comp_exch_wr->comp_exch.comp_operand))
		    *src_addr  = NTOH64(comp_exch_wr->comp_exch.exch_operand);

		/* Unmap the page. */
		det_kunmap_src(src_page, src_addr);
	}

	/* Unlock - atomic operation is complete. */
	det_spin_unlock_bh(&r_qp->scheduler->atomic_lock);

out:
	if (src_mr)
		det_put_mr(src_mr);

	iq_unlock_bh(&r_qp->iq.lock);

	atomic_dec(&l_qp->or_posted);

	return err;
}


int det_loopback_fetch_add(struct det_qp * const l_qp,
			   struct det_qp * const r_qp,
			   struct det_wr * const fetch_add_wr)
{
	struct det_ds src_ds;
	struct det_mr *src_mr;
	struct det_mr *mr;
	struct page *src_page;
	u64 *src_addr;
	u64 base_address;
	u64 atom_address;
	u32 src_offset;
	u32 base_length;
	u32 atom_length;
	int err = 0;

	src_mr = NULL;

	iq_lock_bh(&r_qp->iq.lock);

	if (r_qp->attr.state != DET_QP_CONNECTED) {
		err = DET_AE_INVALID_QP;
		goto out;
	}

	/* Sanity checks. */
	if (!lb_is_sane(r_qp, l_qp)) {
		err = DET_AE_QP_ERROR;
		goto out;
	}

	if (!r_qp->attr.max_ir) {
		err = DET_AE_MAX_IR_EXCEEDED;
		goto out;
	}

	src_mr = det_get_rmr(NTOH32(fetch_add_wr->fetch_add.remote_key));
	if (unlikely(!src_mr)) {
		err =  DET_AE_INVALID_ATOMIC_KEY;
		goto out;
	}

	if (unlikely(src_mr->attr.base.pd != r_qp->attr.pd)) {
		err =  DET_AE_PROTECTION_VIOLATION;
		goto out;
	}

	if (unlikely((src_mr->attr.base.access &
			(DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE)) !=
			(DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE))) {
		err =  DET_AE_ACCESS_VIOLATION;
		goto out;
	}

	base_length = src_mr->attr.base.length;
	if (src_mr->base.type == DET_TYPE_MW) {
		base_address = ((struct det_mw*)src_mr)->mr->vaddr +
			       ((struct det_mw*)src_mr)->mr_offset;
		mr = ((struct det_mw*)src_mr)->mr;
		atomic_inc(&mr->base.refcnt);
		det_put_mr(src_mr);
		src_mr = mr;
	} else
		base_address = src_mr->vaddr;

	atom_address = NTOH64(fetch_add_wr->fetch_add.remote_address);
	atom_length  = 8;

	/* Check for 64-bit alignment. */
	if (atom_address & (atom_length - 1)) {
		err = DET_AE_QP_ERROR;
		goto out;
	}

	/* Make sure the request is within bounds. */
	if (unlikely((atom_address + (atom_length - 1)) < atom_address)) {
		err =  DET_AE_WRAP_ERROR;
		goto out;
	}
	if (unlikely((atom_address < base_address) ||
		     ((atom_address + atom_length) >
		      (base_address + base_length)))) {
		err =  DET_AE_BOUNDS_VIOLATION;
		goto out;
	}

	/* Build a source data segment entry for the data copy. */
	src_ds.mr     = src_mr;
	src_ds.offset = atom_address - src_mr->vaddr;
	src_ds.length = atom_length;
	src_ds.l_key  = src_mr->attr.l_key;

	/* Determine which page to map. */
	src_offset = src_ds.offset + (src_mr->vaddr & ~PAGE_MASK);
	src_page = src_mr->pages[src_offset >> PAGE_SHIFT];
	src_offset &= ~PAGE_MASK;

	/* Lock to perform the atomic operation. */
	det_spin_lock_bh(&r_qp->scheduler->atomic_lock);

	/* Fetch the original data - this handles any page crossing. */
	err = det_copy_data(fetch_add_wr->ds_array, &src_ds, atom_length);
	if (likely(!err)) {
		/* Map source the page so we can read the memory directly. */
		src_addr = det_kmap_src(src_page) + src_offset;

		/* Perform addition. */
		*src_addr += NTOH64(fetch_add_wr->fetch_add.add_operand);

		/* Unmap the page. */
		det_kunmap_src(src_page, src_addr);
	}

	/* Unlock - atomic operation is complete. */
	det_spin_unlock_bh(&r_qp->scheduler->atomic_lock);

out:
	if (src_mr)
		det_put_mr(src_mr);

	iq_unlock_bh(&r_qp->iq.lock);

	atomic_dec(&l_qp->or_posted);

	return err;
}


int det_loopback_bind(struct det_qp * const l_qp,
		      struct det_wr * const bind_wr)
{
	/* Bind is already complete, just return success. */ 
	return 0;
}


void det_loopback_rq(struct det_qp * const l_qp)
{
	struct det_qp *r_qp;
	int sq_has_wr;

	if (unlikely(l_qp->attr.state != DET_QP_CONNECTED))
		return;

	r_qp = det_get_qp(l_qp->attr.remote_qp_num);
	if (unlikely(!r_qp)) {
		/* Disconnect the local QP. */
		det_qp_remote_disconnect(l_qp, DET_AE_INVALID_QP);
		return;
	}

	sq_lock_bh(&r_qp->sq.lock);
	sq_has_wr = (likely(r_qp->attr.state == DET_QP_CONNECTED) &&
		     (r_qp->sq.next_active_wr != r_qp->sq.tail)) ? 1 : 0;
	sq_unlock_bh(&r_qp->sq.lock);

	if (sq_has_wr)
		det_loopback_sq(r_qp);

	det_put_qp(r_qp);
}


/*
 * Loopback QPs connected through the same MAC address.
 * This includes the case where the SQ is connected to the RQ on the same QP.
 */
void det_loopback_sq(struct det_qp * const l_qp)
{
	struct det_qp *r_qp;
	struct det_wr *wr;
	enum det_wc_status status = DET_WS_SUCCESS;
	int err = 0;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (qp_is_co(l_qp))
		return;

	r_qp = det_get_qp(l_qp->attr.remote_qp_num);
	if (unlikely(!r_qp)) {
		/* Disconnect the local QP. */
		det_qp_remote_disconnect(l_qp, DET_AE_INVALID_QP);
		return;
	}

	sq_lock_bh(&l_qp->sq.lock);

	/* Make sure there is work to do. */
	if (l_qp->sq.next_active_wr == l_qp->sq.tail)
		goto done;

	wr = det_get_wr(&l_qp->sq, l_qp->sq.next_active_wr);

#ifdef	DET_TRIGGERED_WR
	if (wr->trigger) {
		if (wr->trigger > 0) {
			wr->trigger = -wr->trigger;
			atomic_add(wr->trigger, &l_qp->sq.gate);
		}
		if (atomic_read(&l_qp->sq.gate) < 0)
			goto done;	/* Suspended */
	}
#endif

	DET_STAT(loopback++);

	switch (wr->type) {
		case DET_WR_SEND:
			err = det_loopback_send(l_qp, r_qp, wr);
			if ((err == DET_AE_QP_RQ_ERROR) &&
			    qp_is_co_member(l_qp)) {
				DET_STAT(co_lb_deferred++);
				err = 0;
				goto done;
			}
			break;

		case DET_WR_RDMA_READ:
			err = det_loopback_read(l_qp, r_qp, wr);
			break;

		case DET_WR_RDMA_WRITE:
			err = det_loopback_write(l_qp, r_qp, wr);
			break;

		case DET_WR_ATOMIC_COMP_EXCH:
			err = det_loopback_comp_exch(l_qp, r_qp, wr);
			break;

		case DET_WR_ATOMIC_FETCH_ADD:
			err = det_loopback_fetch_add(l_qp, r_qp, wr);
			break;

		case DET_WR_BIND:
			err = det_loopback_bind(l_qp, wr);
			break;

		case DET_WR_RECV:
		case DET_WR_RDMA_READ_RESP:
		default:
			printk(KERN_ERR
		"DET loopback botch: found wr type %d on scheduler queue\n",
				wr->type);
			err = DET_AE_INVALID_OPCODE;
			goto invalid_type;
	}

#ifdef	DET_TRIGGERED_WR
	if (wr->signal && !atomic_add_negative(1, &wr->signal->sq.gate))
		det_schedule(DET_SCHEDULE_NEW, wr->signal);
#endif

	/* Map return codes to SQ work completion status. */
	switch (err) {
		case DET_AE_PROTECTION_VIOLATION:
			status = DET_WS_PROTECTION_ERR;
			break;

		case DET_AE_BOUNDS_VIOLATION:
			status = DET_WS_BOUNDS_ERR;
			break;

		case DET_AE_ACCESS_VIOLATION:
			status = DET_WS_ACCESS_ERR;
			break;

		case DET_AE_WRAP_ERROR:
			status = DET_WS_WRAP_ERR;
			break;

		default:
			status = DET_WS_SUCCESS;
			break;
	}
	status = det_complete_sq_wr(l_qp, wr, status);

invalid_type:
	/* Set up for the next work request. */
	l_qp->sq.next_active_wr = (l_qp->sq.next_active_wr + 1) % l_qp->sq.size;

done:
	sq_unlock_bh(&l_qp->sq.lock);

	det_notify_cq(l_qp->attr.sq_cq);
	det_notify_cq(r_qp->attr.rq_cq);

	if (unlikely(err || status))
		det_qp_internal_disconnect(r_qp, (err) ? err : status);

	det_put_qp(r_qp);

	PERF_RECORD(LOOPBACK_PATH, start);
}


/*
 * Called when disconnecting a local QP to send a disconnect to
 * the remote QP which is connected through the same MAC address.
 */
void det_loopback_disconnect(struct det_qp * const l_qp,
			     const enum det_event_code reason)
{
	struct det_qp *r_qp;

	r_qp = det_get_qp(l_qp->attr.remote_qp_num);
	if (unlikely(!r_qp))
		return;

	/* Don't bother if the SQ is connected to the RQ on the same QP. */
	if ((r_qp != l_qp) &&
	    (!qp_is_co_member(l_qp) || (reason != DET_AE_DISCONNECT)))
		det_qp_remote_disconnect(r_qp, reason);

	det_put_qp(r_qp);
}
