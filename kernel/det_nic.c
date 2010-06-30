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


int det_open_nic(struct det_device * const detdev,
		 const char * const ifname,
		 const det_event_cb event_cb,
		 struct det_nic * const nic)
{
	struct det_scheduler *scheduler;
	int enable = 0;

	/* Get the NIC.  If successful, must call dev_put to release NIC. */
	nic->netdev = det_dev_get_by_name(ifname);
	if (unlikely(!nic->netdev))
		return -ENODEV;

	/*
	if (!(nic->netdev->features & NETIF_F_SG)) {
		dev_put(nic->netdev);
		return -EPROTONOSUPPORT;
	}
	*/

	/* Search for the net device in the global scheduler list. */
	sched_list_lock();
	list_for_each_entry(scheduler, &scheduler_list, entry) {
		if (scheduler->netdev == nic->netdev)
			break;
	}
	if (&scheduler->entry == &scheduler_list) {
		/* Not found.  Allocate a new scheduler entry for this NIC. */
		scheduler = kmalloc(sizeof(*scheduler), GFP_ATOMIC);
		if (unlikely(!scheduler))
			goto out;
		/* Construct the scheduler entry for this NIC. */
		scheduler->netdev = nic->netdev;
		scheduler->count = 0;
		scheduler->refcnt = 0;
		/* loopback has queue len of zero */
		if (nic->netdev->tx_queue_len)
			scheduler->schedule_max =
				(nic->netdev->tx_queue_len / 5) * 4;
		else
			scheduler->schedule_max = 1000;
		atomic_set(&scheduler->available, scheduler->schedule_max);
		atomic_set(&scheduler->stopped, 0);
		atomic_set(&scheduler->was_new, 0);
		atomic_set(&scheduler->was_retry, 0);
		atomic_set(&scheduler->was_timeout, 0);
		INIT_LIST_HEAD(&scheduler->qp_list);
		det_spin_lock_init(&scheduler->lock);
		det_spin_lock_init(&scheduler->atomic_lock);
		list_add_tail(&scheduler->entry, &scheduler_list);
		enable = 1;
	}
	scheduler->refcnt++;
	nic->scheduler = scheduler;
	sched_list_unlock();

	nic->type = DET_TYPE_NIC;
	nic->detdev = detdev;
	nic->nr_events = 0;
	nic->event_cb = event_cb;
	atomic_set(&nic->refcnt, 1);

	write_lock(&detdev->lock);
	list_add_tail(&nic->entry, &detdev->nic_list);
	write_unlock(&detdev->lock);

	if (enable)
		DET_NIC_POLL_ENABLE(nic->netdev);

	return 0;

out:
	sched_list_unlock();
	dev_put(nic->netdev);
	return -ENOMEM;
}
EXPORT_SYMBOL(det_open_nic);


void det_get_mac(struct det_mac_addr * const mac,
		 struct net_device * const netdev)
{
	read_lock(&dev_base_lock);
	det_memcpy(&mac->addr[0], netdev->dev_addr,
		min(sizeof(mac->addr), (size_t)netdev->addr_len));
	read_unlock(&dev_base_lock);
}


int det_query_nic(struct det_nic * const nic,
		  struct det_nic_attr * const nic_attr)
{
	strncpy(nic_attr->ifname, nic->netdev->name, IFNAMSIZ);

	nic_attr->vendor_id = DET_VENDOR_ID;
	nic_attr->device_id = DET_DEVICE_ID;
	nic_attr->hw_rev = DET_HW_REV;
	nic_attr->fw_rev = DET_FW_REV;

	nic_attr->min_pds = MIN_PDS;
	nic_attr->max_pds = MAX_PDS;

	nic_attr->min_mrs = MIN_MRS;
	nic_attr->max_mrs = MAX_MRS;

	nic_attr->min_mr_size = MIN_MR_SIZE;
	nic_attr->max_mr_size = MAX_MR_SIZE;

	nic_attr->min_mws = MIN_MWS;
	nic_attr->max_mws = MAX_MWS;

	nic_attr->min_cqs = MIN_CQS;
	nic_attr->max_cqs = MAX_CQS;

	nic_attr->min_cq_size = MIN_CQ_SIZE;
	nic_attr->max_cq_size = MAX_CQ_SIZE;

	nic_attr->cqe_size = sizeof(struct det_wc);

	nic_attr->min_qps = MIN_QPS;
	nic_attr->max_qps = MAX_QPS;

	nic_attr->min_sq_size = MIN_SQ_SIZE;
	nic_attr->max_sq_size = MAX_SQ_SIZE;

	nic_attr->min_rq_size = MIN_RQ_SIZE;
	nic_attr->max_rq_size = MAX_RQ_SIZE;

	nic_attr->wqe_size = sizeof(struct det_wr);

	nic_attr->min_msg_size = MIN_MSG_SIZE;
	nic_attr->max_msg_size = MAX_MSG_SIZE;

	nic_attr->min_rdma_size = MIN_RDMA_SIZE;
	nic_attr->max_rdma_size = MAX_RDMA_SIZE;

	nic_attr->min_sges = MIN_SGES;
	nic_attr->max_sges = MAX_SGES;

	nic_attr->sge_size = sizeof(struct det_ds);

	nic_attr->min_or = MIN_OR;
	nic_attr->max_or = MAX_OR;

	nic_attr->min_ir = MIN_IR;
	nic_attr->max_ir = MAX_IR;

	nic_attr->min_cos = MIN_COS;
	nic_attr->max_cos = MAX_COS;

	nic_attr->page_size = PAGE_SIZE;

	return 0;
}
EXPORT_SYMBOL(det_query_nic);


int det_close_nic(struct det_nic * const nic)
{
	struct det_device *detdev = nic->detdev;
	struct det_scheduler *scheduler = nic->scheduler;
	int disable = 0;

	assert(atomic_read(&nic->refcnt) == 1);
	assert(scheduler);

	sched_list_lock();
	if (!(--scheduler->refcnt)) {
		list_del(&scheduler->entry);
		kfree(scheduler);
		disable++;
	}
	sched_list_unlock();
	if (disable)
		DET_NIC_POLL_DISABLE(nic->netdev);

	/* Release the NIC. */
	dev_put(nic->netdev);

	det_remove_events(nic->event, nic);

	write_lock(&detdev->lock);
	list_del(&nic->entry);
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_close_nic);
