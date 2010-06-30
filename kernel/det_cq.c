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


/* Hold cq->lock during this call for synchronization. */
static void __det_query_cq(struct det_cq * const cq,
			   struct det_cq_attr * const cq_attr)
{
	if (cq_attr) {
		cq->attr.depth = atomic_read(&cq->depth);
		*cq_attr = cq->attr;
	}
}


static int det_alloc_wc_array(struct det_cq * const cq,
			      struct det_wc ** const wc_array,
			      __u32 * const size)
{
	u32 bytes, pages;

	bytes = PAGE_ALIGN(*size * sizeof(struct det_wc));
	pages = bytes >> PAGE_SHIFT;

	/* Restrict memory usage to a percentage of kernel pages. */
	if (pages >
	    (det_max_pages - atomic_read(&det_page_count) + cq->page_cnt))
		return -EDQUOT;

	if (bytes) {
		det_user_unlock();
		*wc_array = vmalloc(bytes);
		det_user_lock();
		if (unlikely(!*wc_array))
			return -ENOMEM;
	} else
		*wc_array = NULL;

	*size = bytes / sizeof(struct det_wc);

	return 0;
}


static void det_free_wc_array(struct det_wc * const wc_array)
{
	if (wc_array) {
		det_user_unlock();
		vfree(wc_array);
		det_user_lock();
	}
}


/* Hold cq->lock during this call for synchronization. */
static inline void det_kcopy_cqes(const struct det_cq * const cq,
				  struct det_wc * const wc_array,
				  const u32 num_wc)
{
	det_kcopy_ring(wc_array, cq->wc_array,
		       cq->head, cq->tail,
		       cq->attr.size, num_wc, sizeof(*wc_array));
}


/* Hold cq->lock during this call for synchronization. */
static struct det_wc *det_move_cq(struct det_cq * const cq,
				  struct det_wc * const wc_array,
				  const u32 size)
{
	struct det_wc *old_array;

	/* Adjust the memory usage quota. */
	atomic_sub(cq->page_cnt, &det_page_count);
	cq->page_cnt = PAGE_ALIGN(size * sizeof(*wc_array)) >> PAGE_SHIFT;
	atomic_add(cq->page_cnt, &det_page_count);

	/* Copy any existing CQEs. */
	if (atomic_read(&cq->depth))
		det_kcopy_cqes(cq, wc_array, atomic_read(&cq->depth));

	/* Save the old array pointer. */
	old_array = cq->wc_array;

	/* Setup the CQ to use the new array. */
	cq->wc_array = wc_array;
	cq->head = 0;
	cq->tail = atomic_read(&cq->depth);
	cq->attr.size = size;

	/* Return the old_array so it can be freed without holding a lock. */
	return old_array;
}


int det_create_cq(struct det_nic * const nic,
		  const __u32 size,
		  const det_completion_cb completion_cb,
		  struct det_cq_attr * const cq_attr,
		  struct det_cq * const cq)
{
	struct det_device *detdev = nic->detdev;
	struct det_wc *wc_array;
	u32 actual_size;
	int err;

	if (unlikely(size > MAX_CQ_SIZE))
		return -EINVAL;

	if (unlikely(detdev->cq_cnt >= MAX_CQS))
		return -EAGAIN;

	cq->type = DET_TYPE_CQ;
	cq->detdev = detdev;
	cq->nic = nic;
	cq->completion_cb = completion_cb;
	det_spin_lock_init(&cq->lock);
	atomic_set(&cq->refcnt, 1);
	init_MUTEX(&cq->mutex);
	cq->co = NULL;
	cq->nr_events = 0;
	cq->page_cnt = 0;
	cq->wc_array = NULL;
	cq->head = 0;
	cq->tail = 0;
	atomic_set(&cq->depth, 0);
	cq->attr.state = DET_CQ_READY;
	cq->attr.arm = 0;
	cq->attr.size = 0;
	cq->attr.threshold = 0;

	actual_size = size;
	err = det_alloc_wc_array(cq, &wc_array, &actual_size);
	if (unlikely(err))
		return err;

	det_move_cq(cq, wc_array, actual_size);

	__det_query_cq(cq, cq_attr);

	atomic_inc(&nic->refcnt);

	write_lock(&detdev->lock);
	list_add_tail(&cq->entry, &detdev->cq_list);
	detdev->cq_cnt++;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_create_cq);


int det_query_cq(struct det_cq * const cq,
		 struct det_cq_attr * const cq_attr)
{
	cq_lock_bh(&cq->lock);
	__det_query_cq(cq, cq_attr);
	cq_unlock_bh(&cq->lock);

	return 0;
}
EXPORT_SYMBOL(det_query_cq);


int det_resize_cq(struct det_cq * const cq,
		  const __u32 size,
		  struct det_cq_attr * const cq_attr)
{
	struct det_wc *wc_array;
	u32 actual_size;
	int err;

	actual_size = size;
	err = det_alloc_wc_array(cq, &wc_array, &actual_size);
	if (unlikely(err))
		return err;

	cq_lock_bh(&cq->lock);

	if (unlikely((actual_size > MAX_CQ_SIZE) ||
		     (actual_size < cq->attr.threshold))) {
		err = -EINVAL;
		goto out;
	}
	if (unlikely(actual_size < atomic_read(&cq->depth))) {
		err = -EBUSY;
		goto out;
	}

	wc_array = det_move_cq(cq, wc_array, actual_size);

	__det_query_cq(cq, cq_attr);

	cq_unlock_bh(&cq->lock);

	/* Must free the old array without holding a lock. */
	det_free_wc_array(wc_array);

	return 0;

out:
	cq_unlock_bh(&cq->lock);
	det_free_wc_array(wc_array);
	return err;
}
EXPORT_SYMBOL(det_resize_cq);


int det_arm_cq(struct det_cq * const cq,
	       const enum det_cq_arm arm,
	       const __u32 threshold)
{
	if (unlikely(!(arm & (DET_CQ_NEXT_SIGNALED  |
			      DET_CQ_NEXT_SOLICITED |
			      DET_CQ_THRESHOLD))   ||
		     ((arm & DET_CQ_THRESHOLD) &&
		      (!threshold || (cq->attr.size < threshold)))))
		return -EINVAL;

	cq_lock_bh(&cq->lock);
	if (arm & DET_CQ_THRESHOLD) {
		cq->attr.threshold = threshold;
		if (atomic_read(&cq->depth) >= threshold) {
			cq->attr.arm = 0;	/* Disarm the CQ. */
			cq_unlock_bh(&cq->lock);
			cq->completion_cb(cq);
			return 0;
		}
	}
	if (arm & DET_CQ_NEXT_SOLICITED)
		cq->solicited = 0;
	cq->attr.arm |= arm;
	cq_unlock_bh(&cq->lock);

	return 0;
}
EXPORT_SYMBOL(det_arm_cq);


int det_poll_cq(struct det_cq * const cq,
		__u32 * const num_wc,
		struct det_wc * const wc_array)
{
	u32 i, n, count;
	struct det_wq *wq;

	cq_lock_bh(&cq->lock);
	n = min(*num_wc, (__u32)atomic_read(&cq->depth));
	if (n) {
		det_kcopy_cqes(cq, wc_array, n);
		cq->head = (cq->head + n) % cq->attr.size;
		atomic_sub(n, &cq->depth);
	}
	cq_unlock_bh(&cq->lock);

	/*
	 * Retire WQEs for polled CQEs.  Coalesce reap counts
	 * from back-to-back completions on the same work queue.
	 * This reduces the number of calls to det_retire_wqes.
	 */
	if (n) {
		wq = (struct det_wq *)(unsigned long)wc_array[0].reserved;
		count = wc_array[0].reap_cnt;
		for (i = 1; i < n; i++) {
			if (wq == (struct det_wq *)(unsigned long)
						wc_array[i].reserved) {
				count += wc_array[i].reap_cnt;
			} else {
				det_retire_wqes(wq, count);
				wq = (struct det_wq *)(unsigned long)
					wc_array[i].reserved;
				count = wc_array[i].reap_cnt;
			}
		}
		det_retire_wqes(wq, count);
	}

	*num_wc = n;
	return (n) ? 0 : -EAGAIN;
}
EXPORT_SYMBOL(det_poll_cq);


int det_destroy_cq(struct det_cq * const cq)
{
	struct det_device *detdev = cq->detdev;

	assert(atomic_read(&cq->refcnt) == 1);

	atomic_dec(&cq->nic->refcnt);

	det_free_wc_array(cq->wc_array);

	atomic_sub(cq->page_cnt, &det_page_count);

	det_remove_events(cq->event, cq);

	write_lock(&detdev->lock);
	list_del(&cq->entry);
	detdev->cq_cnt--;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_destroy_cq);


void det_clear_cqes(struct det_cq * const cq,
		    const struct det_wq * const wq)
{
	struct det_wc *wc;
	u32 i, n;

	if (!cq)
		return;

	/*
	 * Walk the CQ and clear any pointers to this WQ
	 * to prevent retiring WQEs when CQEs are polled.
	 */
	cq_lock_bh(&cq->lock);
	n = cq->head;
	for (i = 0; i < atomic_read(&cq->depth); i++) {
		wc = &cq->wc_array[n];
		if (wc->reserved == (unsigned long)wq)
			wc->reserved = (unsigned long)NULL;
		n = (n + 1) % cq->attr.size;
	}
	cq_unlock_bh(&cq->lock);
}


void det_completion_callback(struct det_cq * const cq)
{
	struct det_eqe *eqe;

	eqe = kmem_cache_alloc(det_eqe_cache, GFP_ATOMIC);
	if (unlikely(!eqe)) {
		printk(KERN_ERR
			"det_completion_callback: kmem_cache_alloc failed.\n");
		printk(KERN_ERR "Dropping CQ completion event: CQ %p.\n", cq);
		return;
	}

	eqe->event.record.code = DET_AE_CQ_COMPLETION;
	eqe->event.record.type = DET_TYPE_CQ;
	eqe->event.record.handle = cq;
	eqe->event.context = cq->context;

	det_append_eqe(cq->event, eqe);
}
