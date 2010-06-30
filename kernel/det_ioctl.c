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


static int det_query_ioctl(struct det_device * const detdev,
			   const unsigned long arg)
{
	struct det_attr attr;
	int err;

	err = det_query(detdev, &attr);
	if (unlikely(err))
		return err;

	if (unlikely(copy_to_user((void __user *)arg, &attr, sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_create_event_ioctl(struct det_device * const detdev,
				  const unsigned long arg)
{
	struct det_event *event;
	int err;

	event = kmalloc(sizeof(*event), GFP_KERNEL);
	if (unlikely(!event))
		return -ENOMEM;

	det_user_lock();
	err = det_create_event(detdev, event);
	if (unlikely(err))
		goto out;

	do {
		if (unlikely(!det_idr_pre_get(&detdev->map, GFP_KERNEL))) {
			err = -ENOMEM;
			goto out1;
		}
		write_lock(&detdev->map_lock);
		err = det_get_id(&detdev->map, event, &event->id);
		write_unlock(&detdev->map_lock);
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		goto out1;

	det_user_unlock();
	err = put_user(event->id, (int __user *)arg);
	if (unlikely(err))
		goto out2;

	return 0;

out2:
	det_user_lock();
	write_lock(&detdev->map_lock);
	idr_remove(&detdev->map, event->id);
	write_unlock(&detdev->map_lock);
out1:
	det_destroy_event(event);
out:
	det_user_unlock();
	kfree(event);
	return err;
}


static int det_wait_on_event_ioctl(struct det_device * const detdev,
				   const unsigned long arg)
{
	struct det_ioc_wait_on_event __user *ioc;
	struct det_ioc_wait_on_event wait;
	struct det_event *event;
	struct det_eqe *eqe;
	int err;

	ioc = (void __user *)arg;

	if (unlikely(copy_from_user(&wait, ioc, sizeof(wait))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	event = idr_find(&detdev->map, wait.event_id);
	if (unlikely(!event || event->id != wait.event_id ||
		     event->type != DET_TYPE_EVENT)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&event->refcnt);
	read_unlock(&detdev->map_lock);

	err = det_wait_on_event(event, wait.timeout, &eqe);

	det_user_unlock();

	if (atomic_dec_and_test(&event->refcnt))
		complete(&event->done);

	if (unlikely(err))
		return err;

	if (unlikely(copy_to_user(ioc->event, &eqe->event, sizeof(eqe->event))))
		err = -EFAULT;

	kmem_cache_free(det_eqe_cache, eqe);

	return err;
}


static int det_generate_event_ioctl(struct det_device * const detdev,
				    const unsigned long arg)
{
	struct det_event *event;
	struct det_ioc_generate_event generate;
	int err;

	if (unlikely(copy_from_user(&generate, (void __user *)arg,
				    sizeof(generate))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	event = idr_find(&detdev->map, generate.event_id);
	if (unlikely(!event || event->id != generate.event_id ||
		     event->type != DET_TYPE_EVENT)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&event->refcnt);
	read_unlock(&detdev->map_lock);

	err = det_generate_event(event, generate.handle);

	if (atomic_dec_and_test(&event->refcnt))
		complete(&event->done);

	return err;
}


static int det_destroy_event_ioctl(struct det_device * const detdev,
				   const unsigned long arg)
{
	struct det_event *event;
	int event_id;
	int err;

	err = get_user(event_id, (int __user *)arg);
	if (unlikely(err))
		return err;

	det_user_lock();

	write_lock(&detdev->map_lock);
	event = idr_find(&detdev->map, event_id);
	if (unlikely(!event || event->id != event_id ||
		     event->type != DET_TYPE_EVENT)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	if (atomic_read(&event->refcnt) != 1) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EBUSY;
	}
	idr_remove(&detdev->map, event->id);
	write_unlock(&detdev->map_lock);

	det_destroy_event(event);

	det_user_unlock();

	kfree(event);
	return 0;
}


static int det_open_nic_ioctl(struct det_device * const detdev,
			      const unsigned long arg)
{
	struct det_event *event;
	struct det_nic *nic;
	struct det_ioc_open_nic open;
	int err;

	if (unlikely(copy_from_user(&open, (void __user *)arg, sizeof(open))))
		return -EFAULT;

	nic = kmalloc(sizeof(*nic), GFP_KERNEL);
	if (unlikely(!nic))
		return -ENOMEM;

	det_user_lock();

	read_lock(&detdev->map_lock);
	event = idr_find(&detdev->map, open.event_id);
	if (unlikely(!event || event->id != open.event_id ||
		     event->type != DET_TYPE_EVENT)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock()
		kfree(nic);
		return -EINVAL;
	}
	atomic_inc(&event->refcnt);
	read_unlock(&detdev->map_lock);

	nic->valid = 0;		/* Prevent event reporting. */
	nic->event = event;
	nic->context = open.context;

	err = det_open_nic(detdev, open.ifname, det_event_callback, nic);
	if (unlikely(err))
		goto out1;

	do {
		if (unlikely(!det_idr_pre_get(&detdev->map, GFP_KERNEL))) {
			err = -ENOMEM;
			goto out2;
		}
		write_lock(&detdev->map_lock);
		err = det_get_id(&detdev->map, nic, &nic->id);
		write_unlock(&detdev->map_lock);
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		goto out2;

	det_user_unlock();

	err = put_user(nic->id, open.nic_id);
	if (unlikely(err))
		goto out3;

	nic->valid = 1;		/* Allow event reporting. */
	return 0;

out3:
	det_user_lock();
	write_lock(&detdev->map_lock);
	idr_remove(&detdev->map, nic->id);
	write_unlock(&detdev->map_lock);
out2:
	det_close_nic(nic);
out1:
	det_user_unlock();
	kfree(nic);
	if (atomic_dec_and_test(&event->refcnt))
		complete(&event->done);
	return err;
}


static int det_query_nic_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_nic *nic;
	struct det_ioc_query_nic query;
	struct det_nic_attr attr;
	int err;

	if (unlikely(copy_from_user(&query, (void __user *)arg, sizeof(query))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	nic = idr_find(&detdev->map, query.nic_id);
	if (unlikely(!nic || nic->id != query.nic_id ||
		     nic->type != DET_TYPE_NIC)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&nic->refcnt);
	read_unlock(&detdev->map_lock);

	err = det_query_nic(nic, &attr);

	det_user_unlock();

	atomic_dec(&nic->refcnt);
	if (unlikely(err))
		return err;

	if (unlikely(copy_to_user(query.attr, &attr, sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_close_nic_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_nic *nic;
	struct det_ioc_close_nic close;
	int err;

	if (unlikely(copy_from_user(&close, (void __user *)arg, sizeof(close))))
		return -EFAULT;

	det_user_lock();

	write_lock(&detdev->map_lock);
	nic = idr_find(&detdev->map, close.nic_id);
	if (unlikely(!nic || nic->id != close.nic_id ||
		     nic->type != DET_TYPE_NIC)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	if (unlikely(atomic_read(&nic->refcnt) != 1)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EBUSY;
	}
	idr_remove(&detdev->map, nic->id);
	write_unlock(&detdev->map_lock);

	det_close_nic(nic);

	det_user_unlock();

	if (atomic_dec_and_test(&nic->event->refcnt))
		complete(&nic->event->done);

	err = put_user(nic->nr_events, close.nr_events);

	kfree(nic);
	return err;
}


static int det_alloc_pd_ioctl(struct det_device * const detdev,
			      const unsigned long arg)
{
	struct det_nic *nic;
	struct det_pd *pd;
	struct det_ioc_alloc_pd alloc;
	int err;

	if (unlikely(copy_from_user(&alloc, (void __user *)arg,
				    sizeof(alloc))))
		return -EFAULT;

	pd = kmalloc(sizeof(*pd), GFP_KERNEL);
	if (unlikely(!pd))
		return -ENOMEM;

	det_user_lock();

	read_lock(&detdev->map_lock);
	nic = idr_find(&detdev->map, alloc.nic_id);
	if (unlikely(!nic || nic->id != alloc.nic_id ||
		     nic->type != DET_TYPE_NIC)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		kfree(pd);
		return -EINVAL;
	}
	atomic_inc(&nic->refcnt);
	read_unlock(&detdev->map_lock);

	err = det_alloc_pd(nic, pd);
	if (unlikely(err))
		goto out1;

	do {
		if (unlikely(!det_idr_pre_get(&detdev->map, GFP_KERNEL))) {
			err = -ENOMEM;
			goto out2;
		}
		write_lock(&detdev->map_lock);
		err = det_get_id(&detdev->map, pd, &pd->id);
		write_unlock(&detdev->map_lock);
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		goto out2;

	det_user_unlock();

	err = put_user(pd->id, alloc.pd_id);
	if (unlikely(err))
		goto out3;

	atomic_dec(&nic->refcnt);

	return 0;

out3:
	det_user_lock();
	write_lock(&detdev->map_lock);
	idr_remove(&detdev->map, pd->id);
	write_unlock(&detdev->map_lock);
out2:
	det_dealloc_pd(pd);
out1:
	det_user_unlock();
	kfree(pd);

	atomic_dec(&nic->refcnt);
	return err;
}


static int det_dealloc_pd_ioctl(struct det_device * const detdev,
			        const unsigned long arg)
{
	struct det_pd *pd;
	int pd_id;
	int err;

	err = get_user(pd_id, (int __user *)arg);
	if (unlikely(err))
		return err;

	det_user_lock();

	write_lock(&detdev->map_lock);
	pd = idr_find(&detdev->map, pd_id);
	if (unlikely(!pd || pd->id != pd_id ||
		     pd->type != DET_TYPE_PD)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	if (unlikely(atomic_read(&pd->refcnt) != 1)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EBUSY;
	}
	idr_remove(&detdev->map, pd->id);
	write_unlock(&detdev->map_lock);

	det_dealloc_pd(pd);

	det_user_unlock();

	kfree(pd);
	return 0;
}


static int det_create_cq_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_nic *nic;
	struct det_event *event;
	struct det_cq *cq;
	struct det_ioc_create_cq create;
	struct det_cq_attr attr;
	int err;

	if (unlikely(copy_from_user(&create, (void __user *)arg,
				    sizeof(create))))
		return -EFAULT;

	cq = kmalloc(sizeof(*cq), GFP_KERNEL);
	if (unlikely(!cq))
		return -ENOMEM;

	det_user_lock();

	read_lock(&detdev->map_lock);
	nic = idr_find(&detdev->map, create.nic_id);
	if (unlikely(!nic || nic->id != create.nic_id ||
		     nic->type != DET_TYPE_NIC)) {
		read_unlock(&detdev->map_lock);
		err = -EINVAL;
		goto out;
	}
	event = idr_find(&detdev->map, create.event_id);
	if (unlikely(!event || event->id != create.event_id ||
		     event->type != DET_TYPE_EVENT)) {
		read_unlock(&detdev->map_lock);
		err = -EINVAL;
		goto out;
	}
	atomic_inc(&nic->refcnt);
	atomic_inc(&event->refcnt);
	read_unlock(&detdev->map_lock);

	cq->valid = 0;		/* Prevent event reporting. */
	cq->event = event;
	cq->context = create.context;

	err = det_create_cq(nic, create.size, det_completion_callback,
			&attr, cq);
	if (unlikely(err))
		goto out1;

	do {
		if (unlikely(!det_idr_pre_get(&detdev->map, GFP_KERNEL))) {
			err = -ENOMEM;
			goto out2;
		}
		write_lock(&detdev->map_lock);
		err = det_get_id(&detdev->map, cq, &cq->id);
		write_unlock(&detdev->map_lock);
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		goto out2;

	det_user_unlock();

	if (create.attr &&
	    unlikely(copy_to_user(create.attr, &attr, sizeof(attr)))) {
		err = -EFAULT;
		goto out3;
	}

	err = put_user(cq->id, create.cq_id);
	if (unlikely(err))
		goto out3;

	/* User-mode CQs hold a reference on the event until destroyed. */
	atomic_dec(&nic->refcnt);

	cq->valid = 1;		/* Allow event reporting. */
	return 0;

out3:
	det_user_lock();
	write_lock(&detdev->map_lock);
	idr_remove(&detdev->map, cq->id);
	write_unlock(&detdev->map_lock);
out2:
	det_destroy_cq(cq);
out1:
	det_user_unlock();
	kfree(cq);

	if (atomic_dec_and_test(&event->refcnt))
		complete(&event->done);
	atomic_dec(&nic->refcnt);
	return err;

out:
	det_user_unlock()
	kfree(cq);
	return err;
}


static int det_query_cq_ioctl(struct det_device * const detdev,
			      const unsigned long arg)
{
	struct det_cq *cq;
	struct det_ioc_query_cq query;
	struct det_cq_attr attr;
	int err;

	if (unlikely(copy_from_user(&query, (void __user *)arg,
				    sizeof(query))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	cq = idr_find(&detdev->map, query.cq_id);
	if (unlikely(!cq || cq->id != query.cq_id ||
		     cq->type != DET_TYPE_CQ)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&cq->refcnt);
	read_unlock(&detdev->map_lock);

	/* Prevent concurrent CQ query, resize, and poll. */
	det_serialize_start(&cq->mutex, &cq->mutex, NULL);
	err = det_query_cq(cq, &attr);
	det_serialize_end(&cq->mutex);

	det_user_unlock();

	atomic_dec(&cq->refcnt);

	if (unlikely(err))
		return err;

	if (unlikely(copy_to_user(query.attr, &attr, sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_resize_cq_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_cq *cq;
	struct det_ioc_resize_cq resize;
	struct det_cq_attr attr;
	int err;

	if (unlikely(copy_from_user(&resize, (void __user *)arg,
				    sizeof(resize))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	cq = idr_find(&detdev->map, resize.cq_id);
	if (unlikely(!cq || cq->id != resize.cq_id ||
		     cq->type != DET_TYPE_CQ)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&cq->refcnt);
	read_unlock(&detdev->map_lock);

	/* Prevent concurrent CQ query, resize, and poll. */
	det_serialize_start(&cq->mutex, &cq->refcnt, NULL);
	err = det_resize_cq(cq, resize.size, &attr);
	det_serialize_end(&cq->mutex);

	det_user_unlock();

	atomic_dec(&cq->refcnt);

	if (unlikely(err))
		return err;

	if (resize.attr &&
	    unlikely(copy_to_user(resize.attr, &attr, sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_arm_cq_ioctl(struct det_device * const detdev,
			    const unsigned long arg)
{
	struct det_cq *cq;
	struct det_ioc_arm_cq arm;
	int err;

	if (unlikely(copy_from_user(&arm, (void __user *)arg, sizeof(arm))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	cq = idr_find(&detdev->map, arm.cq_id);
	if (unlikely(!cq || cq->id != arm.cq_id ||
		     cq->type != DET_TYPE_CQ)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&cq->refcnt);
	read_unlock(&detdev->map_lock);

	err = det_arm_cq(cq, arm.arm, arm.threshold);

	det_user_unlock();

	atomic_dec(&cq->refcnt);
	if (unlikely(err))
		return err;

	return 0;
}


static inline int det_ucopy_cqes(const struct det_cq * const cq,
				 struct det_wc * const wc_array,
				 const u32 num_wc)
{
	register u32 n;

	det_user_unlock();
	if (cq->head < cq->tail) {
		if (unlikely(copy_to_user(&wc_array[0],
			&cq->wc_array[cq->head],
			num_wc * sizeof(*wc_array))))
		goto out;
	} else {
		n = min(num_wc, cq->attr.size - cq->head);
		if (unlikely(copy_to_user(&wc_array[0],
				&cq->wc_array[cq->head],
				n * sizeof(*wc_array))))
			goto out;
		if (n < num_wc) {
			if (unlikely(copy_to_user(&wc_array[n],
					&cq->wc_array[0],
					(num_wc - n) * sizeof(*wc_array))))
				goto out;
		}
	}
	det_user_lock();

	return 0;
out:
	det_user_lock();
	return -EFAULT;
}


static int det_poll_cq_ioctl(struct det_device * const detdev,
			     const unsigned long arg)
{
	struct det_cq *cq;
	struct det_wq *wq;
	struct det_ioc_poll_cq poll;
	u32 i, count;
	int err;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (unlikely(copy_from_user(&poll, (void __user *)arg, sizeof(poll))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	cq = idr_find(&detdev->map, poll.cq_id);
	if (unlikely(!cq || cq->id != poll.cq_id ||
		     cq->type != DET_TYPE_CQ)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&cq->refcnt);
	read_unlock(&detdev->map_lock);

	/* Prevent concurrent CQ query, resize, and poll. */
	det_serialize_start(&cq->mutex, &cq->refcnt, NULL);

	poll.num_wc = min(poll.num_wc, (__u32)atomic_read(&cq->depth));
	if (poll.num_wc) {
		err = det_ucopy_cqes(cq, poll.wc_array, poll.num_wc);
		if (unlikely(err))
			goto out;

		/*
		 * Retire WQEs for polled CQEs.  Coalesce reap counts
		 * from back-to-back completions on the same work queue.
		 * This reduces the number of calls to det_retire_wqes.
		 */
		wq = (struct det_wq *)(unsigned long)
			cq->wc_array[cq->head].reserved;
		count = cq->wc_array[cq->head].reap_cnt;
		cq->head = (cq->head + 1) % cq->attr.size;
		for (i = 1; i < poll.num_wc; i++) {
			if (wq == (struct det_wq *)(unsigned long)
					cq->wc_array[cq->head].reserved) {
				count += cq->wc_array[cq->head].reap_cnt;
			} else {
				det_retire_wqes(wq, count);
				wq = (struct det_wq *)(unsigned long)
					cq->wc_array[cq->head].reserved;
				count = cq->wc_array[cq->head].reap_cnt;
			}
			cq->head = (cq->head + 1) % cq->attr.size;
		}
		det_retire_wqes(wq, count);

		atomic_sub(poll.num_wc, &cq->depth);
	}
	det_serialize_end(&cq->mutex);

	det_user_unlock();

	atomic_dec(&cq->refcnt);

	err = put_user(poll.num_wc, poll.p_num_wc);
	if (unlikely(err))
		return err;

	PERF_RECORD(poll.num_wc ? PERF_POLL_HIT : PERF_POLL_MISS, start);
	return (poll.num_wc) ? 0 : -EAGAIN;

out:
	det_serialize_end(&cq->mutex);
	det_user_unlock();
	atomic_dec(&cq->refcnt);
	return err;
}


static int det_destroy_cq_ioctl(struct det_device * const detdev,
			        const unsigned long arg)
{
	struct det_cq *cq;
	struct det_ioc_destroy_cq destroy;
	int err;

	if (unlikely(copy_from_user(&destroy,
				    (void __user *)arg, sizeof(destroy))))
		return -EFAULT;

	det_user_lock();

	write_lock(&detdev->map_lock);
	cq = idr_find(&detdev->map, destroy.cq_id);
	if (unlikely(!cq || cq->id != destroy.cq_id ||
		     cq->type != DET_TYPE_CQ)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	if (unlikely(atomic_read(&cq->refcnt) != 1)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EBUSY;
	}
	idr_remove(&detdev->map, cq->id);
	write_unlock(&detdev->map_lock);

	det_destroy_cq(cq);

	det_user_unlock();

	/* Release the event reference held for user-mode CQs. */
	if (atomic_dec_and_test(&cq->event->refcnt))
		complete(&cq->event->done);

	err = put_user(cq->nr_events, destroy.nr_events);

	kfree(cq);
	return err;
}


static int det_create_qp_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_pd *pd;
	struct det_qp *qp;
	struct det_cq *rq_cq;
	struct det_cq *sq_cq;
	struct det_ioc_create_qp create;
	struct det_qp_create qp_create;
	struct det_qp_attr attr;
	int err;
#ifdef	CONFIG_DET_DOORBELL
	int page_cnt, mapped;
#endif

	if (unlikely(copy_from_user(&create, (void __user *)arg,
				    sizeof(create))))
		return -EFAULT;

	if (unlikely(copy_from_user(&qp_create, create.create,
				sizeof(qp_create))))
		return -EFAULT;

	qp = kmalloc(sizeof(*qp), GFP_KERNEL);
	if (unlikely(!qp))
		return -ENOMEM;

	det_user_lock();

	read_lock(&detdev->map_lock);
	pd = idr_find(&detdev->map, create.pd_id);
	if (unlikely(!pd || pd->id != create.pd_id ||
		     pd->type != DET_TYPE_PD)) {
		err = -EINVAL;
		goto out;
	}
	if (create.sq_cq_id) {
		sq_cq = idr_find(&detdev->map, create.sq_cq_id);
		if (unlikely(!sq_cq || sq_cq->id != create.sq_cq_id ||
			     sq_cq->type != DET_TYPE_CQ)) {
			err = -EINVAL;
			goto out;
		}
	} else
		sq_cq = NULL;
	if (create.rq_cq_id) {
		rq_cq = idr_find(&detdev->map, create.rq_cq_id);
		if (unlikely(!rq_cq || rq_cq->id != create.rq_cq_id ||
			     rq_cq->type != DET_TYPE_CQ)) {
			err = -EINVAL;
			goto out;
		}
	} else
		rq_cq = NULL;
	atomic_inc(&pd->refcnt);
	if (sq_cq)
		atomic_inc(&sq_cq->refcnt);
	if (rq_cq)
		atomic_inc(&rq_cq->refcnt);
	read_unlock(&detdev->map_lock);

	qp->valid = 0;		/* Prevent event reporting. */
	qp->context = create.context;

	qp_create.sq_cq = sq_cq;
	qp_create.rq_cq = rq_cq;

#ifdef	CONFIG_DET_DOORBELL

	qp->doorbell = NULL;
	qp->doorbell_page = NULL;

#ifdef	CONFIG_COMPAT
	/* Determine if this is a 32-bit process. */
	if (unlikely(get_personality & PER_LINUX32)) {
		err = -ENOEXEC;
		goto out1;
	}
#endif

	/* Calculate pages for doorbell.  We only allow one. */
	page_cnt = (((unsigned long)create.doorbell & ~PAGE_MASK) +
			sizeof(*create.doorbell) + ~PAGE_MASK) >> PAGE_SHIFT;

	if (page_cnt != 1) {
		err = -EINVAL;
		goto out1;
	}

	det_user_unlock();
	down_read(&current->mm->mmap_sem);
	mapped = get_user_pages(current, current->mm,
				(unsigned long)create.doorbell,
				page_cnt, 1, 1, &qp->doorbell_page, NULL);
	up_read(&current->mm->mmap_sem);

	if (unlikely((mapped < 0) || (mapped != page_cnt))) {
		err = -ENOMEM;
		det_user_lock();
		goto out1;
	}

	qp->doorbell = kmap(qp->doorbell_page);
	det_user_lock();
	if (unlikely(!qp->doorbell)) {
		err = -ENOMEM;
		goto out1;
	}

	qp->doorbell = (void *)qp->doorbell +
		       ((unsigned long)create.doorbell & ~PAGE_MASK);

	/* Must initialize doorbell before calling det_create_qp. */
	memset(qp->doorbell, 0, sizeof(*qp->doorbell));
#endif

	err = det_create_qp(pd, &qp_create, &attr, qp);
	if (unlikely(err))
		goto out1;

	do {
		if (unlikely(!det_idr_pre_get(&detdev->map, GFP_KERNEL))) {
			err = -ENOMEM;
			goto out2;
		}
		write_lock(&detdev->map_lock);
		err = det_get_id(&detdev->map, qp, &qp->id);
		write_unlock(&detdev->map_lock);
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		goto out2;

	det_user_unlock();

	if (create.attr &&
	    unlikely(copy_to_user(create.attr, &attr, sizeof(attr)))) {
		err = -EFAULT;
		goto out3;
	}

	err = put_user(qp->id, create.qp_id);
	if (unlikely(err))
		goto out3;

	if (rq_cq)
		atomic_dec(&rq_cq->refcnt);
	if (sq_cq)
		atomic_dec(&sq_cq->refcnt);
	atomic_dec(&pd->refcnt);

	qp->valid = 1;		/* Allow event reporting. */
	return 0;

out3:
	det_user_lock();
	write_lock(&detdev->map_lock);
	idr_remove(&detdev->map, qp->id);
	write_unlock(&detdev->map_lock);
out2:
	det_destroy_qp(qp);
out1:
#ifdef	CONFIG_DET_DOORBELL
	if (qp->doorbell)
		kunmap(qp->doorbell_page);
	if (qp->doorbell_page)
		page_cache_release(qp->doorbell_page);
#endif
	det_user_unlock();
	kfree(qp);
	atomic_dec(&rq_cq->refcnt);
	atomic_dec(&sq_cq->refcnt);
	atomic_dec(&pd->refcnt);
	return err;

out:
	read_unlock(&detdev->map_lock);
	det_user_unlock();
	kfree(qp);
	return err;
}


static int det_query_qp_ioctl(struct det_device * const detdev,
			      const unsigned long arg)
{
	struct det_qp *qp;
	struct det_ioc_query_qp query;
	struct det_qp_attr attr;
	int err;

	if (unlikely(copy_from_user(&query, (void __user *)arg, sizeof(query))))
		return -EFAULT;

	det_user_lock();
	
	read_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, query.qp_id);
	if (unlikely(!qp || qp->id != query.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&qp->refcnt);
	read_unlock(&detdev->map_lock);

	/* Prevent concurrent QP modifies and queries. */
	det_serialize_start(&qp->mutex, &qp->refcnt, &qp->done);
	err = det_query_qp(qp, &attr);
	det_serialize_end(&qp->mutex);

	det_user_unlock();

	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	if (unlikely(err))
		return err;

	if (unlikely(copy_to_user(query.attr, &attr, sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_modify_qp_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_qp *qp;
	struct det_ioc_modify_qp modify;
	struct det_qp_mod mod;
	struct det_qp_attr attr;
	int err;

	if (unlikely(copy_from_user(&modify, (void __user *)arg,
				    sizeof(modify))))
		return -EFAULT;

	if (unlikely(copy_from_user(&mod, modify.mod, sizeof(mod))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, modify.qp_id);
	if (unlikely(!qp || qp->id != modify.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&qp->refcnt);
	read_unlock(&detdev->map_lock);

	/* Prevent concurrent QP modifies and queries. */
	det_serialize_start(&qp->mutex, &qp->refcnt, &qp->done);
	err = det_modify_qp(qp, &mod, &attr);
	det_serialize_end(&qp->mutex);

	det_user_unlock();

	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	if (unlikely(err))
		return err;

	if (modify.attr &&
	    unlikely(copy_to_user(modify.attr, &attr, sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_destroy_qp_ioctl(struct det_device * const detdev,
			        const unsigned long arg)
{
	struct det_qp *qp;
	struct det_ioc_destroy_qp destroy;
	int err;

	if (unlikely(copy_from_user(&destroy, (void __user *)arg,
				    sizeof(destroy))))
		return -EFAULT;

	det_user_lock();

	write_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, destroy.qp_id);
	if (unlikely(!qp || qp->id != destroy.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		write_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	idr_remove(&detdev->map, qp->id);
	write_unlock(&detdev->map_lock);

	det_destroy_qp(qp);

	det_user_unlock();

	err = put_user(qp->nr_events, destroy.nr_events);

#ifdef	CONFIG_DET_DOORBELL
	kunmap(qp->doorbell_page);
	page_cache_release(qp->doorbell_page);
#endif

	kfree(qp);
	return err;
}


static int det_reg_mr_ioctl(struct det_device * const detdev,
			    const unsigned long arg)
{
	struct det_pd *pd;
	struct det_mr *mr;
	struct det_ioc_reg_mr reg;
	__u32 l_key;
	net32_t r_key;
	int err, page_cnt, mapped, i;

	if (unlikely(copy_from_user(&reg, (void __user *)arg, sizeof(reg))))
		return -EFAULT;

	/* User attempted overflow! */
	if ((reg.mr_reg.vaddr + reg.mr_reg.length) < reg.mr_reg.vaddr)
		return -EINVAL;

	/* Calculate pages for region and allocate MR. */
	page_cnt = ((reg.mr_reg.vaddr & ~PAGE_MASK) + reg.mr_reg.length +
			~PAGE_MASK) >> PAGE_SHIFT;

	if (!page_cnt)
		return -EINVAL;

	det_user_lock();

	read_lock(&detdev->map_lock);
	pd = idr_find(&detdev->map, reg.pd_id);
	if (unlikely(!pd || pd->id != reg.pd_id ||
		     pd->type != DET_TYPE_PD)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&pd->refcnt);
	read_unlock(&detdev->map_lock);

	det_user_unlock();

	mr = vmalloc(sizeof(*mr) + (sizeof(struct page*) * page_cnt));
	if (unlikely(!mr)) {
		err = -ENOMEM;
		goto out;
	}
	mr->page_cnt = page_cnt;

	/*
	 * Map and lock pages.  Per Andrew Morton, get_user_pages()
	 * must be called with write=1 to fault in the real page.
	 */
	down_read(&current->mm->mmap_sem);
	mapped = get_user_pages(current, current->mm, reg.mr_reg.vaddr,
				page_cnt, 1, 1, mr->pages, NULL);
	up_read(&current->mm->mmap_sem);

	if (unlikely(mapped < 0)) {
		err = -ENOMEM;
		goto out1;
	}

	if (unlikely(mapped < page_cnt)) {
		err = -ENOMEM;
		goto out2;
	}

	det_user_lock();

	err = det_reg_mr(pd, &reg.mr_reg, &l_key, &r_key, mr);
	if (unlikely(err))
		goto out5;

	do {
		if (unlikely(!det_idr_pre_get(&detdev->map, GFP_KERNEL))) {
			err = -ENOMEM;
			goto out3;
		}
		write_lock(&detdev->map_lock);
		err = det_get_id(&detdev->map, mr, &mr->base.id);
		write_unlock(&detdev->map_lock);
	} while (unlikely(err == -EAGAIN));

	if (unlikely(err))
		goto out3;

	det_user_unlock();

	err = put_user(mr->base.id, reg.mr_id);
	if (unlikely(err))
		goto out4;

	err = put_user(l_key, reg.l_key);
	if (unlikely(err))
		goto out4;

	if (reg.r_key) {
		err = put_user(r_key, reg.r_key);
		if (unlikely(err))
			goto out4;
	}

	atomic_dec(&pd->refcnt);

	return 0;

out4:
	det_user_lock();
	write_lock(&detdev->map_lock);
	idr_remove(&detdev->map, mr->base.id);
	write_unlock(&detdev->map_lock);
out3:
	det_dereg_mr(mr);
out5:
	det_user_unlock();
out2:
	/* Release mapped pages. */
	for (i = 0; i < mapped; i++)
		page_cache_release(mr->pages[i]);
out1:
	vfree(mr);
out:
	atomic_dec(&pd->refcnt);
	return err;
}


static int det_query_mr_ioctl(struct det_device * const detdev,
			      const unsigned long arg)
{
	struct det_mr *mr;
	struct det_ioc_query_mr query;
	struct det_mr_attr attr;
	int err;

	if (unlikely(copy_from_user(&query, (void __user *)arg, sizeof(query))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	mr = idr_find(&detdev->map, query.mr_id);
	if (unlikely(!mr || mr->base.id != query.mr_id ||
		     mr->base.type != DET_TYPE_MR)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&mr->base.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_query_mr(mr, &attr);

	det_user_unlock();

	if (unlikely(err))
		goto out;

	if (unlikely(copy_to_user(query.attr, &attr, sizeof(attr))))
		err = -EFAULT;
out:
	if (atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);

	return err;
}


static int det_modify_mr_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_pd *pd;
	struct det_mr *mr;
	struct det_ioc_modify_mr modify;
	struct det_mr_mod mod;
	__u32 l_key;
	net32_t r_key;
	int err;

	if (unlikely(copy_from_user(&modify, (void __user *)arg,
				    sizeof(modify))))
		return -EFAULT;

	if (unlikely(copy_from_user(&mod, modify.mod, sizeof(mod))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	mr = idr_find(&detdev->map, modify.mr_id);
	if (unlikely(!mr || mr->base.id != modify.mr_id ||
		     mr->base.type != DET_TYPE_MR)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	if (mod.flags & DET_MR_MOD_PD) {
		pd = idr_find(&detdev->map, modify.pd_id);
		if (unlikely(!pd || pd->id != modify.pd_id ||
			     pd->type != DET_TYPE_PD)) {
			read_unlock(&detdev->map_lock);
			det_user_unlock();
			return -EINVAL;
		}
		atomic_inc(&pd->refcnt);
	} else
		pd = NULL;
	mod.pd = pd;
	atomic_inc(&mr->base.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_modify_mr(mr, &mod, &l_key, &r_key);

	det_user_unlock();

	if (atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);

	if (mod.flags & DET_MR_MOD_PD)
		atomic_dec(&pd->refcnt);

	if (unlikely(err))
		return err;

	err = put_user(l_key, modify.l_key);
	if (unlikely(err))
		return err;

	if (modify.r_key)
		err = put_user(r_key, modify.r_key);

	return err;
}


static int det_reg_shared_ioctl(struct det_device * const detdev,
			        const unsigned long arg)
{
	struct det_pd *pd;
	struct det_mr *mr;
	struct det_mr *shared_mr;
	struct det_ioc_reg_shared reg;
	struct det_sh_reg sh_reg;
	__u32 l_key;
	net32_t r_key;
	int err;

	if (unlikely(copy_from_user(&reg, (void __user *)arg, sizeof(reg))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	mr = idr_find(&detdev->map, reg.mr_id);
	if (unlikely(!mr || mr->base.id != reg.mr_id ||
		     mr->base.type != DET_TYPE_MR)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	pd = idr_find(&detdev->map, reg.pd_id);
	if (unlikely(!pd || pd->id != reg.pd_id ||
		     pd->type != DET_TYPE_PD)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&mr->base.refcnt);
	atomic_inc(&pd->refcnt);
	read_unlock(&detdev->map_lock);

	det_user_unlock();

	shared_mr = vmalloc(
		sizeof(*shared_mr) + (sizeof(struct page*) * mr->page_cnt));
	if (unlikely(!shared_mr)) {
		err = -ENOMEM;
		goto out;
	}
	shared_mr->page_cnt = mr->page_cnt;
	det_memcpy(shared_mr->pages, mr->pages,
		sizeof(struct page*) * shared_mr->page_cnt);

	sh_reg.pd = pd;
	sh_reg.access = reg.access;

	det_user_lock();

	err = det_reg_shared(mr, &sh_reg, &l_key, &r_key, shared_mr);
	if (unlikely(err))
		goto out1;

	do {
		if (unlikely(!det_idr_pre_get(&detdev->map, GFP_KERNEL))) {
			err = -ENOMEM;
			goto out2;
		}
		write_lock(&detdev->map_lock);
		err = det_get_id(&detdev->map, shared_mr, &shared_mr->base.id);
		write_unlock(&detdev->map_lock);
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		goto out2;

	det_user_unlock();

	err = put_user(shared_mr->base.id, reg.shared_id);
	if (unlikely(err))
		goto out3;

	err = put_user(l_key, reg.l_key);
	if (unlikely(err))
		goto out3;

	if (reg.r_key) {
		err = put_user(r_key, reg.r_key);
		if (unlikely(err))
			goto out3;
	}

	atomic_dec(&pd->refcnt);
	if (atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);

	return 0;

out3:
	det_user_lock();
	write_lock(&detdev->map_lock);
	idr_remove(&detdev->map, shared_mr->base.id);
	write_unlock(&detdev->map_lock);
out2:
	det_dereg_mr(shared_mr);
out1:
	det_user_unlock();
	vfree(shared_mr);
out:
	atomic_dec(&pd->refcnt);
	if (atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);

	return err;
}


static int det_dereg_mr_ioctl(struct det_device * const detdev,
			      const unsigned long arg)
{
	struct det_mr *mr;
	int mr_id;
	int err, i;

	err = get_user(mr_id, (int __user *)arg);
	if (unlikely(err))
		return err;

	det_user_lock();

	write_lock(&detdev->map_lock);
	mr = idr_find(&detdev->map, mr_id);
	if (unlikely(!mr || mr->base.id != mr_id ||
		     mr->base.type != DET_TYPE_MR)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	if (atomic_read(&mr->windows)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EBUSY;
	}
	idr_remove(&detdev->map, mr->base.id);
	write_unlock(&detdev->map_lock);

	err = det_dereg_mr(mr);

	det_user_unlock();

	if (err)
		return err;

	/* Release mapped pages. */
	for (i = 0; i < mr->page_cnt; i++)
		page_cache_release(mr->pages[i]);

	vfree(mr);
	return 0;
}


static int det_create_mw_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_pd *pd;
	struct det_mw *mw;
	struct det_ioc_create_mw create;
	int err;

	if (unlikely(copy_from_user(&create, (void __user *)arg,
				    sizeof(create))))
		return -EFAULT;

	mw = kmalloc(sizeof(*mw), GFP_KERNEL);
	if (unlikely(!mw))
		return -ENOMEM;

	det_user_lock();

	read_lock(&detdev->map_lock);
	pd = idr_find(&detdev->map, create.pd_id);
	if (unlikely(!pd || pd->id != create.pd_id ||
		     pd->type != DET_TYPE_PD)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		kfree(mw);
		return -EINVAL;
	}
	atomic_inc(&pd->refcnt);
	read_unlock(&detdev->map_lock);

	err = det_create_mw(pd, mw);
	if (unlikely(err))
		goto out1;

	do {
		if (unlikely(!det_idr_pre_get(&detdev->map, GFP_KERNEL))) {
			err = -ENOMEM;
			goto out2;
		}
		write_lock(&detdev->map_lock);
		err = det_get_id(&detdev->map, mw, &mw->base.id);
		write_unlock(&detdev->map_lock);
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		goto out2;

	det_user_unlock();

	err = put_user(mw->base.id, create.mw_id);
	if (unlikely(err))
		goto out3;

	atomic_dec(&pd->refcnt);

	return 0;

out3:
	det_user_lock();
	write_lock(&detdev->map_lock);
	idr_remove(&detdev->map, mw->base.id);
	write_unlock(&detdev->map_lock);
out2:
	det_destroy_mw(mw);
out1:
	det_user_unlock();
	kfree(mw);
	atomic_dec(&pd->refcnt);
	return err;
}


static int det_query_mw_ioctl(struct det_device * const detdev,
			      const unsigned long arg)
{
	struct det_mw *mw;
	struct det_ioc_query_mw query;
	struct det_mw_attr attr;
	int err;

	if (unlikely(copy_from_user(&query, (void __user *)arg, sizeof(query))))
		return -EFAULT;

	det_user_lock();

	read_lock(&detdev->map_lock);
	mw = idr_find(&detdev->map, query.mw_id);
	if (unlikely(!mw || mw->base.id != query.mw_id ||
		     mw->base.type != DET_TYPE_MW)) {
		read_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	atomic_inc(&mw->base.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_query_mw(mw, &attr);

	det_user_unlock();

	if (unlikely(err))
		goto out;

	if (unlikely(copy_to_user(query.attr, &attr, sizeof(attr))))
		err = -EFAULT;
out:
	if (atomic_dec_and_test(&mw->base.refcnt))
		complete(&mw->base.done);

	return err;
}


static int det_destroy_mw_ioctl(struct det_device * const detdev,
			        const unsigned long arg)
{
	struct det_mw *mw;
	int mw_id;
	int err;

	err = get_user(mw_id, (int __user *)arg);
	if (unlikely(err))
		return err;

	det_user_lock();

	write_lock(&detdev->map_lock);
	mw = idr_find(&detdev->map, mw_id);
	if (unlikely(!mw || mw->base.id != mw_id ||
		     mw->base.type != DET_TYPE_MW)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	idr_remove(&detdev->map, mw->base.id);
	write_unlock(&detdev->map_lock);

	det_destroy_mw(mw);

	det_user_unlock();

	kfree(mw);

	return 0;
}

#ifndef CONFIG_DET_DOORBELL
static int det_send_ioctl(struct det_device * const detdev,
			  const unsigned long arg)
{
	struct det_ioc_send send;
	struct det_local_ds ds_array[MAX_STACK_NUM_DS];
	struct det_local_ds *local_ds;
	struct det_qp *qp;
	int err;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (unlikely(copy_from_user(&send, (void __user *)arg, sizeof(send))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, send.qp_id);
	if (unlikely(!qp || qp->id != send.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&qp->refcnt);
	read_unlock(&detdev->map_lock);

	/* Determine where the data segments will fit. */
	if (send.num_ds <= MAX_IOC_NUM_DS) {
		local_ds = send.local_ds;		/* inline */
		goto ready;
	} else if (send.num_ds <= MAX_STACK_NUM_DS) {
		local_ds = ds_array;			/* stack */
	} else {
		local_ds = kmalloc(sizeof(*local_ds) * send.num_ds,
				   GFP_KERNEL);
		if (unlikely(!local_ds)) {
			err = -ENOMEM;
			goto out;
		}
	}

	if (unlikely(copy_from_user(local_ds, send.ds_array,
				    sizeof(*local_ds) * send.num_ds))) {
		err = -EFAULT;
		goto out1;
	}
ready:
	err = det_send(qp, send.wr_id, local_ds, send.num_ds,
		       send.flags, send.immediate_data);
out1:
	if (send.num_ds > MAX_STACK_NUM_DS)
		kfree(local_ds);
out:
	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	PERF_RECORD(PERF_SEND, start);
	return err;
}


static int det_recv_ioctl(struct det_device * const detdev,
			  const unsigned long arg)
{
	struct det_ioc_recv recv;
	struct det_local_ds ds_array[MAX_STACK_NUM_DS];
	struct det_local_ds *local_ds;
	struct det_qp *qp;
	int err;

	if (unlikely(copy_from_user(&recv, (void __user *)arg, sizeof(recv))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, recv.qp_id);
	if (unlikely(!qp || qp->id != recv.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&qp->refcnt);
	read_unlock(&detdev->map_lock);

	/* Determine where the data segments will fit. */
	if (recv.num_ds <= MAX_IOC_NUM_DS) {
		local_ds = recv.local_ds;		/* inline */
		goto ready;
	} else if (recv.num_ds <= MAX_STACK_NUM_DS) {
		local_ds = ds_array;			/* stack */
	} else {
		local_ds = kmalloc(sizeof(*local_ds) * recv.num_ds,
				   GFP_KERNEL);
		if (unlikely(!local_ds)) {
			err = -ENOMEM;
			goto out;
		}
	}

	if (unlikely(copy_from_user(local_ds, recv.ds_array,
				    sizeof(*local_ds) * recv.num_ds))) {
		err = -EFAULT;
		goto out1;
	}
ready:
	err = det_recv(qp, recv.wr_id, local_ds, recv.num_ds);
out1:
	if (recv.num_ds > MAX_STACK_NUM_DS)
		kfree(local_ds);
out:
	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	return err;
}


static int det_read_ioctl(struct det_device * const detdev,
			  const unsigned long arg)
{
	struct det_ioc_read read;
	struct det_local_ds ds_array[MAX_STACK_NUM_DS];
	struct det_local_ds *local_ds;
	struct det_qp *qp;
	int err;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (unlikely(copy_from_user(&read, (void __user *)arg, sizeof(read))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, read.qp_id);
	if (unlikely(!qp || qp->id != read.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&qp->refcnt);
	read_unlock(&detdev->map_lock);

	/* Determine where the data segments will fit. */
	if (read.num_ds <= MAX_IOC_NUM_DS) {
		local_ds = read.local_ds;		/* inline */
		goto ready;
	} else if (read.num_ds <= MAX_STACK_NUM_DS) {
		local_ds = ds_array;			/* stack */
	} else {
		local_ds = kmalloc(sizeof(*local_ds) * read.num_ds,
				   GFP_KERNEL);
		if (unlikely(!local_ds)) {
			err = -ENOMEM;
			goto out;
		}
	}

	if (unlikely(copy_from_user(local_ds, read.ds_array,
				    sizeof(*local_ds) * read.num_ds))) {
		err = -EFAULT;
		goto out1;
	}
ready:
	err = det_read(qp, read.wr_id, local_ds, read.num_ds, 
		       read.remote_address, read.remote_key, read.flags);
out1:
	if (read.num_ds > MAX_STACK_NUM_DS)
		kfree(local_ds);
out:
	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	PERF_RECORD(PERF_READ, start);
	return err;
}


static int det_write_ioctl(struct det_device * const detdev,
			   const unsigned long arg)
{
	struct det_ioc_write write;
	struct det_local_ds ds_array[MAX_STACK_NUM_DS];
	struct det_local_ds *local_ds;
	struct det_qp *qp;
	int err;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (unlikely(copy_from_user(&write, (void __user *)arg, sizeof(write))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, write.qp_id);
	if (unlikely(!qp || qp->id != write.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&qp->refcnt);
	read_unlock(&detdev->map_lock);

	/* Determine where the data segments will fit. */
	if (write.num_ds <= MAX_IOC_NUM_DS) {
		local_ds = write.local_ds;		/* inline */
		goto ready;
	} else if (write.num_ds <= MAX_STACK_NUM_DS) {
		local_ds = ds_array;			/* stack */
	} else {
		local_ds = kmalloc(sizeof(*local_ds) * write.num_ds,
				   GFP_KERNEL);
		if (unlikely(!local_ds)) {
			err = -ENOMEM;
			goto out;
		}
	}

	if (unlikely(copy_from_user(local_ds, write.ds_array,
				    sizeof(*local_ds) * write.num_ds))) {
		err = -EFAULT;
		goto out1;
	}
ready:
	err = det_write(qp, write.wr_id, local_ds, write.num_ds, 
			write.remote_address, write.remote_key, write.flags,
			write.immediate_data);
out1:
	if (write.num_ds > MAX_STACK_NUM_DS)
		kfree(local_ds);
out:
	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	PERF_RECORD(PERF_WRITE, start);
	return err;
}


static int det_bind_ioctl(struct det_device * const detdev,
			  const unsigned long arg)
{
	struct det_ioc_bind bind;
	struct det_qp *qp;
	struct det_mr *mr;
	struct det_mw *mw;
	net32_t r_key;
	int err;

	if (unlikely(copy_from_user(&bind, (void __user *)arg, sizeof(bind))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, bind.qp_id);
	if (unlikely(!qp || qp->id != bind.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	if (bind.length) {
		mr = idr_find(&detdev->map, bind.mr_id);
		if (unlikely(!mr || mr->base.id != bind.mr_id ||
			     mr->base.type != DET_TYPE_MR)) {
			read_unlock(&detdev->map_lock);
			return -EINVAL;
		}
	} else
		mr = NULL;
	mw = idr_find(&detdev->map, bind.mw_id);
	if (unlikely(!mw || mw->base.id != bind.mw_id ||
		     mw->base.type != DET_TYPE_MW)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&qp->refcnt);
	if (mr)
		atomic_inc(&mr->base.refcnt);
	atomic_inc(&mw->base.refcnt);
	read_unlock(&detdev->map_lock);

	/* Verify that put_user will succeed before initiating the bind. */
	err = put_user(r_key, bind.r_key);
	if (unlikely(err))
		goto out;

	err = det_bind(qp, bind.wr_id, mw, mr, &r_key, bind.vaddr, bind.length,
		       bind.access, bind.flags);
	if (unlikely(err))
		goto out;

	/* Now use put_user to return the actual bind r_key. */
	put_user(r_key, bind.r_key);

out:
	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	if (mr && atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);

	if (atomic_dec_and_test(&mw->base.refcnt))
		complete(&mw->base.done);

	return err;
}


static int det_comp_exch_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_ioc_comp_exch comp_exch;
	struct det_qp *qp;
	int err;

	if (unlikely(copy_from_user(&comp_exch, (void __user *)arg,
				    sizeof(comp_exch))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, comp_exch.qp_id);
	if (unlikely(!qp || qp->id != comp_exch.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&qp->refcnt);
	read_unlock(&detdev->map_lock);

	err = det_comp_exch(qp, comp_exch.wr_id,
			    comp_exch.comp_operand, comp_exch.exch_operand,
			    &comp_exch.local_ds, comp_exch.remote_address,
			    comp_exch.remote_key, comp_exch.flags);

	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	return err;
}


static int det_fetch_add_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_ioc_fetch_add fetch_add;
	struct det_qp *qp;
	int err;

	if (unlikely(copy_from_user(&fetch_add, (void __user *)arg,
				    sizeof(fetch_add))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	qp = idr_find(&detdev->map, fetch_add.qp_id);
	if (unlikely(!qp || qp->id != fetch_add.qp_id ||
		     qp->type != DET_TYPE_QP)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&qp->refcnt);
	read_unlock(&detdev->map_lock);

	err = det_fetch_add(qp, fetch_add.wr_id, fetch_add.add_operand,
			    &fetch_add.local_ds, fetch_add.remote_address,
			    fetch_add.remote_key, fetch_add.flags);

	if (atomic_dec_and_test(&qp->refcnt))
		complete(&qp->done);

	return err;
}

#endif /* CONFIG_DET_DOORBELL */

static int det_create_co_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_ioc_create_co create;
	struct det_pd *pd;
	struct det_cq *cq;
	struct det_co *co;
	int err;
#ifdef	CONFIG_DET_DOORBELL
	int page_cnt, mapped;
#endif

	if (unlikely(copy_from_user(&create, (void __user *)arg,
				    sizeof(create))))
		return -EFAULT;

	co = kmalloc(sizeof(*co), GFP_KERNEL);
	if (unlikely(!co))
		return -ENOMEM;

	det_user_lock();

	read_lock(&detdev->map_lock);
	pd = idr_find(&detdev->map, create.pd_id);
	if (unlikely(!pd || pd->id != create.pd_id ||
		     pd->type != DET_TYPE_PD)) {
		err = -EINVAL;
		goto out;
	}
	cq = idr_find(&detdev->map, create.cq_id);
	if (unlikely(!cq || cq->id != create.cq_id ||
		     cq->type != DET_TYPE_CQ)) {
		err = -EINVAL;
		goto out;
	}
	atomic_inc(&pd->refcnt);
	atomic_inc(&cq->refcnt);
	read_unlock(&detdev->map_lock);

	co->qp.valid = 0;	/* Prevent event reporting. */
	co->qp.context = create.context;

#ifdef	CONFIG_DET_DOORBELL

	co->qp.doorbell = NULL;
	co->qp.doorbell_page = NULL;

#ifdef	CONFIG_COMPAT
	/* Determine if this is a 32-bit process. */
	if (unlikely(get_personality & PER_LINUX32)) {
		err = -ENOEXEC;
		goto out1;
	}
#endif

	/* Calculate pages for doorbell.  We only allow one. */
	page_cnt = (((unsigned long)create.doorbell & ~PAGE_MASK) +
			sizeof(*create.doorbell) + ~PAGE_MASK) >> PAGE_SHIFT;

	if (page_cnt != 1) {
		err = -EINVAL;
		goto out1;
	}

	det_user_unlock();
	down_read(&current->mm->mmap_sem);
	mapped = get_user_pages(current, current->mm,
				(unsigned long)create.doorbell,
				page_cnt, 1, 1, &co->qp.doorbell_page, NULL);
	up_read(&current->mm->mmap_sem);

	if (unlikely((mapped < 0) || (mapped != page_cnt))) {
		err = -ENOMEM;
		goto out4;
	}

	co->qp.doorbell = kmap(co->qp.doorbell_page);
	if (unlikely(!co->qp.doorbell)) {
		err = -ENOMEM;
		goto out4;
	}

	det_user_lock();

	co->qp.doorbell = (void *)co->qp.doorbell +
		       ((unsigned long)create.doorbell & ~PAGE_MASK);

	/* Must initialize doorbell before calling det_create_co. */
	memset(co->qp.doorbell, 0, sizeof(*co->qp.doorbell));
#endif

	err = det_create_co(pd, cq, co);
	if (unlikely(err))
		goto out1;

	do {
		if (unlikely(!det_idr_pre_get(&detdev->map, GFP_KERNEL))) {
			err = -ENOMEM;
			goto out2;
		}
		write_lock(&detdev->map_lock);
		err = det_get_id(&detdev->map, co, &co->id);
		write_unlock(&detdev->map_lock);
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		goto out2;

	det_user_unlock();

	co->qp.id = co->id;

	err = put_user(co->id, create.co_id);
	if (unlikely(err))
		goto out3;

	atomic_dec(&cq->refcnt);
	atomic_dec(&pd->refcnt);

	co->qp.valid = 1;	/* Allow qp event reporting. */
	return 0;

out3:
	det_user_lock();
	write_lock(&detdev->map_lock);
	idr_remove(&detdev->map, co->id);
	write_unlock(&detdev->map_lock);
out2:
	det_destroy_co(co);
out1:
	det_user_unlock();

#ifdef	CONFIG_DET_DOORBELL
out4:
	if (co->qp.doorbell)
		kunmap(co->qp.doorbell_page);
	if (co->qp.doorbell_page)
		page_cache_release(co->qp.doorbell_page);
#endif
	kfree(co);
	atomic_dec(&cq->refcnt);
	atomic_dec(&pd->refcnt);
	return err;
out:
	read_unlock(&detdev->map_lock);
	det_user_unlock();
	kfree(co);
	return err;
}


static int det_destroy_co_ioctl(struct det_device * const detdev,
			        const unsigned long arg)
{
	struct det_ioc_destroy_co destroy;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&destroy, (void __user *)arg,
				    sizeof(destroy))))
		return -EFAULT;

	det_user_lock();
	write_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, destroy.co_id);
	if (unlikely(!co || co->id != destroy.co_id ||
		     co->type != DET_TYPE_CO)) {
		write_unlock(&detdev->map_lock);
		det_user_unlock();
		return -EINVAL;
	}
	idr_remove(&detdev->map, co->id);
	write_unlock(&detdev->map_lock);

	det_destroy_co(co);

	det_user_unlock();

	err = put_user(co->qp.nr_events, destroy.nr_events);

#ifdef	CONFIG_DET_DOORBELL
	kunmap(co->qp.doorbell_page);
	page_cache_release(co->qp.doorbell_page);
#endif

	kfree(co);
	return err;
}

#ifndef CONFIG_DET_DOORBELL
static int det_join_ioctl(struct det_device * const detdev,
			  const unsigned long arg)
{
	struct det_ioc_join join;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&join, (void __user *)arg,
				    sizeof(join))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, join.co_id);
	if (unlikely(!co || co->id != join.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_join(co, join.wr_id, join.tag, join.size,
		       join.rank, join.flags);

	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


static int det_barrier_ioctl(struct det_device * const detdev,
			     const unsigned long arg)
{
	struct det_ioc_barrier barrier;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&barrier, (void __user *)arg,
				    sizeof(barrier))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, barrier.co_id);
	if (unlikely(!co || co->id != barrier.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_barrier(co, barrier.wr_id, barrier.flags);

	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


static int det_bcast_ioctl(struct det_device * const detdev,
			   const unsigned long arg)
{
	struct det_ioc_bcast bcast;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&bcast, (void __user *)arg,
				    sizeof(bcast))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, bcast.co_id);
	if (unlikely(!co || co->id != bcast.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_bcast(co, bcast.wr_id, bcast.root, &bcast.ds, bcast.flags);

	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


static int det_scatter_ioctl(struct det_device * const detdev,
			     const unsigned long arg)
{
	struct det_ioc_scatter scatter;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&scatter, (void __user *)arg,
				    sizeof(scatter))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, scatter.co_id);
	if (unlikely(!co || co->id != scatter.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_scatter(co, scatter.wr_id, scatter.root,
			  get_ioc_ds(scatter.src_ds),
			  get_ioc_ds(scatter.dst_ds),
			  scatter.flags);

	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


static int det_scatterv_ioctl(struct det_device * const detdev,
			      const unsigned long arg)
{
	struct det_ioc_scatterv scatterv;
	struct det_local_ds src_ds_array[MAX_STACK_NUM_DS];
	struct det_local_ds *src_ds;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&scatterv, (void __user *)arg,
				    sizeof(scatterv))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, scatterv.co_id);
	if (unlikely(!co || co->id != scatterv.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	if (scatterv.src_ds_array) {
		/* Determine where the data segments will fit. */
		if (co->size <= MAX_IOC_NUM_DS) {
			src_ds = scatterv.src_ds;		/* inline */
			goto ready;
		} else if (co->size <= MAX_STACK_NUM_DS) {
			src_ds = src_ds_array;			/* stack */
		} else {
			src_ds = kmalloc(sizeof(*src_ds) * co->size, GFP_KERNEL);
			if (unlikely(!src_ds)) {
				err = -ENOMEM;
				goto out;
			}
		}

		if (unlikely(copy_from_user(src_ds, scatterv.src_ds_array,
					    sizeof(*src_ds) * co->size))) {
			err = -EFAULT;
			goto out1;
		}
	} else
		src_ds = NULL;
ready:
	err = det_scatterv(co, scatterv.wr_id, scatterv.root, src_ds,
			   get_ioc_ds(scatterv.dst_ds), scatterv.flags);
out1:
	if (co->size > MAX_STACK_NUM_DS)
		kfree(src_ds);
out:
	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


static int det_gather_ioctl(struct det_device * const detdev,
			    const unsigned long arg)
{
	struct det_ioc_gather gather;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&gather, (void __user *)arg,
				    sizeof(gather))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, gather.co_id);
	if (unlikely(!co || co->id != gather.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_gather(co, gather.wr_id, gather.root,
			 get_ioc_ds(gather.src_ds), get_ioc_ds(gather.dst_ds),
			 gather.flags);

	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


static int det_gatherv_ioctl(struct det_device * const detdev,
			     const unsigned long arg)
{
	struct det_ioc_gatherv gatherv;
	struct det_local_ds dst_ds_array[MAX_STACK_NUM_DS];
	struct det_local_ds *dst_ds;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&gatherv, (void __user *)arg,
				    sizeof(gatherv))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, gatherv.co_id);
	if (unlikely(!co || co->id != gatherv.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	if (gatherv.dst_ds_array) {
		/* Determine where the data segments will fit. */
		if (co->size <= MAX_IOC_NUM_DS) {
			dst_ds = gatherv.dst_ds;		/* inline */
			goto ready;
		} else if (co->size <= MAX_STACK_NUM_DS) {
			dst_ds = dst_ds_array;			/* stack */
		} else {
			dst_ds = kmalloc(sizeof(*dst_ds) * co->size, GFP_KERNEL);
			if (unlikely(!dst_ds)) {
				err = -ENOMEM;
				goto out;
			}
		}

		if (unlikely(copy_from_user(dst_ds, gatherv.dst_ds_array,
					    sizeof(*dst_ds) * co->size))) {
			err = -EFAULT;
			goto out1;
		}
	} else
		dst_ds = NULL;
ready:
	err = det_gatherv(co, gatherv.wr_id, gatherv.root,
			  get_ioc_ds(gatherv.src_ds), dst_ds, gatherv.flags);
out1:
	if (co->size > MAX_STACK_NUM_DS)
		kfree(dst_ds);
out:
	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


static int det_allgather_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_ioc_allgather allgather;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&allgather, (void __user *)arg,
				    sizeof(allgather))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, allgather.co_id);
	if (unlikely(!co || co->id != allgather.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_allgather(co, allgather.wr_id, get_ioc_ds(allgather.src_ds),
			    &allgather.dst_ds, allgather.flags);

	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


static int det_allgatherv_ioctl(struct det_device * const detdev,
			        const unsigned long arg)
{
	struct det_ioc_allgatherv allgatherv;
	struct det_local_ds dst_ds_array[MAX_STACK_NUM_DS];
	struct det_local_ds *dst_ds;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&allgatherv, (void __user *)arg,
				    sizeof(allgatherv))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, allgatherv.co_id);
	if (unlikely(!co || co->id != allgatherv.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	/* Determine where the data segments will fit. */
	if (co->size <= MAX_IOC_NUM_DS) {
		dst_ds = allgatherv.dst_ds;		/* inline */
		goto ready;
	} else if (co->size <= MAX_STACK_NUM_DS) {
		dst_ds = dst_ds_array;			/* stack */
	} else {
		dst_ds = kmalloc(sizeof(*dst_ds) * co->size, GFP_KERNEL);
		if (unlikely(!dst_ds)) {
			err = -ENOMEM;
			goto out;
		}
	}

	if (unlikely(copy_from_user(dst_ds, allgatherv.dst_ds_array,
				    sizeof(*dst_ds) * co->size))) {
		err = -EFAULT;
		goto out1;
	}
ready:
	err = det_allgatherv(co, allgatherv.wr_id,
			     get_ioc_ds(allgatherv.src_ds), dst_ds,
			     allgatherv.flags);
out1:
	if (co->size > MAX_STACK_NUM_DS)
		kfree(dst_ds);
out:
	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


static int det_alltoall_ioctl(struct det_device * const detdev,
			      const unsigned long arg)
{
	struct det_ioc_alltoall alltoall;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&alltoall, (void __user *)arg,
				    sizeof(alltoall))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, alltoall.co_id);
	if (unlikely(!co || co->id != alltoall.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	err = det_alltoall(co, alltoall.wr_id, &alltoall.src_ds,
			   &alltoall.dst_ds, alltoall.flags);

	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}
#endif /* CONFIG_DET_DOORBELL */

/*
 *  alltoallv may be called through ioctl as well as doorbell
 */
static int det_alltoallv_ioctl(struct det_device * const detdev,
			       const unsigned long arg)
{
	struct det_ioc_alltoallv alltoallv;
	struct det_local_ds src_ds_array[MAX_STACK_NUM_DS];
	struct det_local_ds dst_ds_array[MAX_STACK_NUM_DS];
	struct det_local_ds *src_ds;
	struct det_local_ds *dst_ds;
	struct det_co *co;
	int err;

	if (unlikely(copy_from_user(&alltoallv, (void __user *)arg,
				    sizeof(alltoallv))))
		return -EFAULT;

	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, alltoallv.co_id);
	if (unlikely(!co || co->id != alltoallv.co_id ||
		     co->type != DET_TYPE_CO)) {
		read_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	atomic_inc(&co->qp.refcnt);
	read_unlock(&detdev->map_lock);

	/* Determine where the data segments will fit. */
	if (co->size <= MAX_IOC_NUM_DS) {
		src_ds = alltoallv.src_ds;		/* inline */
		dst_ds = alltoallv.dst_ds;		/* inline */
		goto ready;
	} else if (co->size <= MAX_STACK_NUM_DS) {
		src_ds = src_ds_array;			/* stack */
		dst_ds = dst_ds_array;			/* stack */
	} else {
		src_ds = kmalloc(sizeof(*src_ds) * co->size, GFP_KERNEL);
		if (unlikely(!src_ds)) {
			err = -ENOMEM;
			goto out;
		}
		dst_ds = kmalloc(sizeof(*dst_ds) * co->size, GFP_KERNEL);
		if (unlikely(!dst_ds)) {
			err = -ENOMEM;
			goto out1;
		}
	}

	if (unlikely(copy_from_user(src_ds, alltoallv.src_ds_array,
				    sizeof(*src_ds) * co->size))) {
		err = -EFAULT;
		goto out1;
	}
	if (unlikely(copy_from_user(dst_ds, alltoallv.dst_ds_array,
				    sizeof(*dst_ds) * co->size))) {
		err = -EFAULT;
		goto out1;
	}
ready:
	err = det_alltoallv(co, alltoallv.wr_id, src_ds, dst_ds,
			    alltoallv.flags);
out1:
	if (co->size > MAX_STACK_NUM_DS) {
		kfree(src_ds);
		if (dst_ds)
			kfree(dst_ds);
	}
out:
	if (atomic_dec_and_test(&co->qp.refcnt))
		complete(&co->qp.done);

	return err;
}


void det_cleanup_events(struct det_device * const detdev)
{
	struct det_event *event, *next;

	write_lock(&detdev->map_lock);
	list_for_each_entry_safe(event, next, &detdev->event_list, entry) {
		idr_remove(&detdev->map, event->id);
		write_unlock(&detdev->map_lock);

		det_destroy_event(event);
		kfree(event);

		write_lock(&detdev->map_lock);
	}
	write_unlock(&detdev->map_lock);
}


void det_cleanup_nics(struct det_device * const detdev)
{
	struct det_nic *nic, *next;

	write_lock(&detdev->map_lock);
	list_for_each_entry_safe(nic, next, &detdev->nic_list, entry) {
		idr_remove(&detdev->map, nic->id);
		write_unlock(&detdev->map_lock);

		det_close_nic(nic);

		if (atomic_dec_and_test(&nic->event->refcnt))
			complete(&nic->event->done);

		kfree(nic);

		write_lock(&detdev->map_lock);
	}
	write_unlock(&detdev->map_lock);
}


void det_cleanup_pds(struct det_device * const detdev)
{
	struct det_pd *pd, *next;

	write_lock(&detdev->map_lock);
	list_for_each_entry_safe(pd, next, &detdev->pd_list, entry) {
		idr_remove(&detdev->map, pd->id);
		write_unlock(&detdev->map_lock);

		det_dealloc_pd(pd);
		kfree(pd);

		write_lock(&detdev->map_lock);
	}
	write_unlock(&detdev->map_lock);
}


void det_cleanup_cqs(struct det_device * const detdev)
{
	struct det_cq *cq, *next;

	write_lock(&detdev->map_lock);
	list_for_each_entry_safe(cq, next, &detdev->cq_list, entry) {
		idr_remove(&detdev->map, cq->id);
		write_unlock(&detdev->map_lock);

		det_destroy_cq(cq);

		if (atomic_dec_and_test(&cq->event->refcnt))
			complete(&cq->event->done);

		kfree(cq);

		write_lock(&detdev->map_lock);
	}
	write_unlock(&detdev->map_lock);
}


void det_cleanup_qps(struct det_device * const detdev)
{
	struct det_qp *qp, *next;

	write_lock(&detdev->map_lock);
	list_for_each_entry_safe(qp, next, &detdev->qp_list, entry) {
		idr_remove(&detdev->map, qp->id);
		write_unlock(&detdev->map_lock);

		det_destroy_qp(qp);

#ifdef	CONFIG_DET_DOORBELL
		kunmap(qp->doorbell_page);
		page_cache_release(qp->doorbell_page);
#endif

		kfree(qp);

		write_lock(&detdev->map_lock);
	}
	write_unlock(&detdev->map_lock);
}


void det_cleanup_mrs(struct det_device * const detdev)
{
	struct det_mr *mr, *next;
	int i;

	write_lock(&detdev->map_lock);
	list_for_each_entry_safe(mr, next, &detdev->mr_list, base.entry) {
		idr_remove(&detdev->map, mr->base.id);
		write_unlock(&detdev->map_lock);

		det_dereg_mr(mr);

		/* Release mapped pages. */
		for (i = 0; i < mr->page_cnt; i++)
			page_cache_release(mr->pages[i]);

		det_user_unlock();
		vfree(mr);
		det_user_lock();

		write_lock(&detdev->map_lock);
	}
	write_unlock(&detdev->map_lock);
}


void det_cleanup_mws(struct det_device * const detdev)
{
	struct det_mw *mw, *next;

	write_lock(&detdev->map_lock);
	list_for_each_entry_safe(mw, next, &detdev->mw_list, base.entry) {
		idr_remove(&detdev->map, mw->base.id);
		write_unlock(&detdev->map_lock);

		det_destroy_mw(mw);
		kfree(mw);

		write_lock(&detdev->map_lock);
	}
	write_unlock(&detdev->map_lock);
}


void det_cleanup_cos(struct det_device * const detdev)
{
	struct det_co *co, *next;

	write_lock(&detdev->map_lock);
	list_for_each_entry_safe(co, next, &detdev->co_list, entry) {
		idr_remove(&detdev->map, co->id);
		write_unlock(&detdev->map_lock);

		det_destroy_co(co);

#ifdef	CONFIG_DET_DOORBELL
		kunmap(co->qp.doorbell_page);
		page_cache_release(co->qp.doorbell_page);
#endif

		kfree(co);

		write_lock(&detdev->map_lock);
	}
	write_unlock(&detdev->map_lock);
}


int det_ioctl(struct inode *inode,
	      struct file *filp,
	      unsigned int cmd,
	      unsigned long arg)
{
	int err;

	switch (cmd) {
		case DET_IOC_QUERY:
			err = det_query_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_CREATE_EVENT:
			err = det_create_event_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_WAIT_ON_EVENT:
			err = det_wait_on_event_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_GENERATE_EVENT:
			err = det_generate_event_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_DESTROY_EVENT:
			err = det_destroy_event_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_OPEN_NIC:
			err = det_open_nic_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_QUERY_NIC:
			err = det_query_nic_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_CLOSE_NIC:
			err = det_close_nic_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_ALLOC_PD:
			err = det_alloc_pd_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_DEALLOC_PD:
			err = det_dealloc_pd_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_CREATE_CQ:
			err = det_create_cq_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_QUERY_CQ:
			err = det_query_cq_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_RESIZE_CQ:
			err = det_resize_cq_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_ARM_CQ:
			err = det_arm_cq_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_POLL_CQ:
			err = det_poll_cq_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_DESTROY_CQ:
			err = det_destroy_cq_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_CREATE_QP:
			err = det_create_qp_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_QUERY_QP:
			err = det_query_qp_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_MODIFY_QP:
			err = det_modify_qp_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_DESTROY_QP:
			err = det_destroy_qp_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_REG_MR:
			err = det_reg_mr_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_QUERY_MR:
			err = det_query_mr_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_MODIFY_MR:
			err = det_modify_mr_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_REG_SHARED:
			err = det_reg_shared_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_DEREG_MR:
			err = det_dereg_mr_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_CREATE_MW:
			err = det_create_mw_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_QUERY_MW:
			err = det_query_mw_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_DESTROY_MW:
			err = det_destroy_mw_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_CREATE_CO:
			err = det_create_co_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_DESTROY_CO:
			err = det_destroy_co_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_ALLTOALLV:
			err = det_alltoallv_ioctl(filp->private_data, arg);
			break;

#ifndef CONFIG_DET_DOORBELL
		case DET_IOC_SEND:
			err = det_send_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_RECV:
			err = det_recv_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_READ:
			err = det_read_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_WRITE:
			err = det_write_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_BIND:
			err = det_bind_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_COMP_EXCH:
			err = det_comp_exch_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_FETCH_ADD:
			err = det_fetch_add_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_JOIN:
			err = det_join_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_BARRIER:
			err = det_barrier_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_BCAST:
			err = det_bcast_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_SCATTER:
			err = det_scatter_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_SCATTERV:
			err = det_scatterv_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_GATHER:
			err = det_gather_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_GATHERV:
			err = det_gatherv_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_ALLGATHER:
			err = det_allgather_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_ALLGATHERV:
			err = det_allgatherv_ioctl(filp->private_data, arg);
			break;

		case DET_IOC_ALLTOALL:
			err = det_alltoall_ioctl(filp->private_data, arg);
			break;
#endif	/* CONFIG_DET_DOORBELL */

		default:
			err = -ENOIOCTLCMD;
			break;
	}

	return err;
}


#ifdef	HAVE_UNLOCKED_IOCTL
long det_unlocked_ioctl(struct file *filp,
			unsigned int cmd,
			unsigned long arg)
{
	return det_ioctl(filp->f_dentry->d_inode, filp, cmd, arg);
}
#endif


ssize_t det_verb(struct file *filp,
		 const char __user *buf,
		 size_t size,
		 loff_t *offset)
{
	struct det_verb verb;

	if (unlikely(size != sizeof(verb)))
		return -EINVAL;

	if (unlikely(copy_from_user(&verb, buf, sizeof(verb))))
		return -EFAULT;

#ifdef	CONFIG_COMPAT
	/* Determine if this is a 32-bit process. */
	if (unlikely(current->personality & PER_LINUX32)) {
		return det_compat_ioctl(filp, verb.cmd, verb.arg);
	}
#endif
	return det_ioctl(filp->f_dentry->d_inode, filp, verb.cmd, verb.arg);
}
