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


int det_create_event(struct det_device * const detdev,
		     struct det_event * const event)
{
	event->type = DET_TYPE_EVENT;
	event->detdev = detdev;
	det_spin_lock_init(&event->lock);
	INIT_LIST_HEAD(&event->event_queue);
	init_waitqueue_head(&event->wait_queue);
	init_completion(&event->done);
	atomic_set(&event->waitcnt, 0);
	atomic_set(&event->refcnt, 1);

	write_lock(&detdev->lock);
	list_add_tail(&event->entry, &detdev->event_list);
	write_unlock(&detdev->lock);

	return 0;
}


int det_wait_on_event(struct det_event * const event,
		      signed long timeout,
		      struct det_eqe ** const eqe)
{
	int ret;

	DECLARE_WAITQUEUE(wait, current);

	event_lock_bh(&event->lock);
	if (!list_empty(&event->event_queue)) {
		*eqe = list_remove_head_entry(&event->event_queue,
				struct det_eqe, entry);
		ret = 0;
		goto out;
	}

	if (timeout == 0) {
		ret = -EAGAIN;
		goto out;
	} else if (timeout != DET_NO_TIMEOUT) {
		struct timeval wait;

		wait.tv_sec  = 0;
		wait.tv_usec = timeout;
		timeout = timeval_to_jiffies(&wait);
	}

	add_wait_queue_exclusive(&event->wait_queue, &wait);
	set_current_state(TASK_INTERRUPTIBLE);

	atomic_inc(&event->waitcnt);
	atomic_dec(&event->refcnt);
	event_unlock_bh(&event->lock);

	det_user_unlock();
	timeout = schedule_timeout(timeout);
	det_user_lock();

	event_lock_bh(&event->lock);
	atomic_inc(&event->refcnt);
	if (atomic_dec_and_test(&event->waitcnt))
		wake_up(&event->wait_queue);

	remove_wait_queue(&event->wait_queue, &wait);

	if (timeout == 0) {
		ret = -ETIME;
		goto out;
	}

	if (unlikely(signal_pending(current))) {
		/*
		 * We got woken up because of a signal. This is different
		 * from being woken up because of the event we are waiting
		 * on or being timed out.
		 */
		ret = -EINTR;
		goto out;
	}

	if (unlikely(list_empty(&event->event_queue))) {
		ret = -EAGAIN;
		goto out;
	}

	*eqe = list_remove_head_entry(&event->event_queue,
			struct det_eqe, entry);
	ret = 0;
out:
	if (!ret) {
		switch ((*eqe)->event.record.type) {
			case DET_TYPE_CO:
			{
				struct det_co *co = (struct det_co *)
					(*eqe)->event.record.handle;
				(*eqe)->event.record.handle =
					(void *)(unsigned long)co->id;
				(*eqe)->event.context = co->qp.context;
				co->qp.nr_events++;
				break;
			}

			case DET_TYPE_CQ:
			{
				struct det_cq *cq = (struct det_cq *)
					(*eqe)->event.record.handle;
				(*eqe)->event.record.handle =
					(void *)(unsigned long)cq->id;
				(*eqe)->event.context = cq->context;
				cq->nr_events++;
				break;
			}

			case DET_TYPE_QP:
			{
				struct det_qp *qp = (struct det_qp *)
					(*eqe)->event.record.handle;
				(*eqe)->event.record.handle =
					(void *)(unsigned long)qp->id;
				(*eqe)->event.context = qp->context;
				qp->nr_events++;
				break;
			}

			case DET_TYPE_NIC:
			{
				struct det_nic *nic = (struct det_nic *)
					(*eqe)->event.record.handle;
				(*eqe)->event.record.handle =
					(void *)(unsigned long)nic->id;
				(*eqe)->event.context = nic->context;
				nic->nr_events++;
				break;
			}

			case DET_TYPE_UNKNOWN:
			default:
				break;
		}
	}

	event_unlock_bh(&event->lock);
	return ret;
}


int det_generate_event(struct det_event * const event,
		       void * const handle)
{
	struct det_record record;

	record.code = DET_AE_USER_GENERATED;
	record.type = DET_TYPE_UNKNOWN;
	record.handle = handle;

	det_event_callback(event, &record);

	return 0;
}


int det_destroy_event(struct det_event * const event)
{
	struct det_device *detdev = event->detdev;
	struct det_eqe *eqe, *next;

	event_lock_bh(&event->lock);

	/* Wake any up waiters and wait until all have exited. */
	if (unlikely(waitqueue_active(&event->wait_queue))) {
		wake_up_all(&event->wait_queue);
		event_unlock_bh(&event->lock);

		wait_event(event->wait_queue, !atomic_read(&event->waitcnt));
	}
	else
		event_unlock_bh(&event->lock);

	/* Release an event reference. */
	if (atomic_dec_and_test(&event->refcnt))
		complete(&event->done);

	/* Wait for all event references to go away. */
	det_user_unlock();
	wait_for_completion(&event->done);
	det_user_lock();

	/* Return any queued events to the cache. */
	list_for_each_entry_safe(eqe, next, &event->event_queue, entry)
		kmem_cache_free(det_eqe_cache, eqe);

	write_lock(&detdev->lock);
	list_del(&event->entry);
	write_unlock(&detdev->lock);

	return 0;
}


void det_event_callback(struct det_event * const event,
			const struct det_record * const record)
{
	struct det_eqe *eqe;
	int valid;

	eqe = kmem_cache_alloc(det_eqe_cache, GFP_ATOMIC);
	if (unlikely(!eqe)) {
		printk(KERN_ERR
			"det_event_callback: kmem_cache_alloc failed.\n");
		printk(KERN_ERR
			"Dropping event: code 0x%x, type %d, handle %p.\n",
			(unsigned)record->code, record->type, record->handle);
		return;
	}

	eqe->event.record.code = record->code;
	eqe->event.record.type = record->type;
	eqe->event.record.handle = record->handle;

	/* Convert context and handle for user-mode. */
	switch (record->type) {
		case DET_TYPE_CO:
			valid = ((struct det_co *)record->handle)->qp.valid;
			break;

		case DET_TYPE_CQ:
			valid = ((struct det_cq *)record->handle)->valid;
			break;

		case DET_TYPE_QP:
			valid = ((struct det_qp *)record->handle)->valid;
			break;

		case DET_TYPE_NIC:
			valid = ((struct det_nic *)record->handle)->valid;
			break;

		case DET_TYPE_UNKNOWN:
			eqe->event.context = 0;
			valid = 1;
			break;

		default:
			printk(KERN_ERR
		"Dropping unknown event: code 0x%x, type %d, handle %p.\n",
		(unsigned)record->code, record->type, record->handle);
			kmem_cache_free(det_eqe_cache, eqe);
			return;
	}

	if (unlikely(!valid)) {
		/*
		 * Dropping this event should be okay since if it is not
		 * yet valid the user cannot have a handle to the resource.
		 */
		printk(KERN_NOTICE "Resource not yet valid.\n");
		printk(KERN_NOTICE
			"Dropping event: code 0x%x, type %d, handle %p.\n",
			(unsigned)record->code, record->type, record->handle);
		kmem_cache_free(det_eqe_cache, eqe);
		return;
	}

	det_append_eqe(event, eqe);
}


void det_async_event(const struct det_nic * const nic,
		     const enum det_event_code code,
		     enum det_type type,
		     void * const handle)
{
	struct det_record record;

	/* Route async events for internal collective resources. */
	if (type == DET_TYPE_QP) {
		if (qp_is_co_member(handle)) {
			det_co_async_event(qp_get_co(handle), code, type, handle);
			return;
		} else if (qp_is_co(handle))
			type = DET_TYPE_CO;
	}
	if ((type == DET_TYPE_CQ) && cq_is_co_member(handle)) {
		det_co_async_event(cq_get_co(handle), code, type, handle);
		return;
	}

	record.code = code;
	record.type = type;
	record.handle = handle;
	nic->event_cb(nic->event, &record);
}


int det_remove_events(struct det_event * const event,
		      const void * const handle)
{
	struct det_eqe *eqe, *next;
	int nr_events = 0;

	if (!event)
		return nr_events;

	event_lock_bh(&event->lock);
	list_for_each_entry_safe(eqe, next, &event->event_queue, entry) {
		if ((eqe->event.record.handle != handle) ||
		    (eqe->event.record.code == DET_AE_USER_GENERATED))
			continue;
		list_del(&eqe->entry);
		kmem_cache_free(det_eqe_cache, eqe);
		nr_events++;
	}
	event_unlock_bh(&event->lock);

	return nr_events;
}
