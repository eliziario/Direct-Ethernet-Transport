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


int det_alloc_pd(struct det_nic * const nic,
		 struct det_pd * const pd)
{
	struct det_device *detdev = nic->detdev;

	if (unlikely(detdev->pd_cnt >= MAX_PDS))
		return -EAGAIN;

	pd->type = DET_TYPE_PD;
	pd->detdev = detdev;
	pd->nic = nic;
	atomic_set(&pd->refcnt, 1);

	atomic_inc(&nic->refcnt);

	write_lock(&detdev->lock);
	list_add_tail(&pd->entry, &detdev->pd_list);
	detdev->pd_cnt++;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_alloc_pd);


int det_dealloc_pd(struct det_pd * const pd)
{
	struct det_device *detdev = pd->detdev;

	assert(atomic_read(&pd->refcnt) == 1);

	atomic_dec(&pd->nic->refcnt);

	write_lock(&detdev->lock);
	list_del(&pd->entry);
	detdev->pd_cnt--;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_dealloc_pd);
