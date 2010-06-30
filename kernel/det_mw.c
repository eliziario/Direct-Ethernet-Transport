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


int det_create_mw(struct det_pd * const pd,
		  struct det_mw * const mw)
{
	struct det_device *detdev = pd->detdev;

	if (unlikely(detdev->mw_cnt >= MAX_MWS))
		return -EAGAIN;

	mw->base.type = DET_TYPE_MW;
	mw->base.detdev = detdev;
	mw->mr = NULL;
	mw->attr.base.pd = pd;
	mw->attr.base.access = 0;
	mw->attr.base.length = 0;
	mw->attr.base.r_key = HTON32(0);
	init_completion(&mw->base.done);
	atomic_set(&mw->base.refcnt, 1);

	atomic_inc(&pd->refcnt);

	write_lock(&detdev->lock);
	list_add_tail(&mw->base.entry, &detdev->mw_list);
	detdev->mw_cnt++;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_create_mw);


int det_query_mw(struct det_mw * const mw,
		 struct det_mw_attr * const mw_attr)
{
	*mw_attr = mw->attr;
	return 0;
}
EXPORT_SYMBOL(det_query_mw);


static void det_unbind_mw(struct det_mw * const mw)
{
	/* Determine if the MW is currently bound. */
	if (!mw->attr.base.length)
		return;

	/* Remove the r_key from the map. */
	wiremap_write_lock_bh();
	idr_remove(&det_wire_map, NTOH32(mw->attr.base.r_key));
	wiremap_write_unlock_bh();

	atomic_dec(&mw->mr->windows);
	mw->mr = NULL;

	mw->attr.base.length = 0;
	mw->attr.base.access = 0;
	mw->attr.base.r_key = HTON32(0);
}


int det_bind_mw(struct det_mw * const mw,
		struct det_mr * const mr,
		net32_t * const r_key,
		const __u64 vaddr,
		const __u32 length,
		const enum det_access_ctrl access)
{
	int mr_key, err;

	/*
	 * A previously bound MW can be bound to a new virtual address
	 * range in the same or a different MR, causing the previous
	 * binding to be invalidated.  Binding a previously bound MW
	 * to a zero-length virtual address range will invalidate the
	 * previous binding and return an r_key that is unbound.
	 */
	det_unbind_mw(mw);

	/* Determine if the MW was just being unbound. */
	if (!length) {
		/* Return the unbound r_key to the client. */
		*r_key = mw->attr.base.r_key;
		return 0;
	}

	if (unlikely((length < MIN_MR_SIZE) ||
		     (length > MAX_MR_SIZE)))
		return -EINVAL;

	/* The MR and MW must belong to the same PD. */
	if (unlikely(mr->attr.base.pd != mw->attr.base.pd))
		return -EPERM;

	/* Perform immediate checks on MR address and length. */
	if (unlikely((vaddr < mr->vaddr) ||
		     ((vaddr + (length - 1)) < vaddr) ||
		     ((vaddr + length) > (mr->vaddr + mr->attr.base.length))))
		return -ERANGE;

	/* Verify the MW and MR access rights. */
	if (unlikely(!(access & (DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE)) ||
		     !(mr->attr.base.access & DET_AC_MW_BIND) ||
		     ((access & DET_AC_REMOTE_WRITE) &&
		      !(mr->attr.base.access & DET_AC_LOCAL_WRITE)) ||
		     ((access & DET_AC_REMOTE_READ) &&
		      !(mr->attr.base.access & DET_AC_LOCAL_READ))))
		return -EACCES;

	/* Bind the MW. */
	mw->mr = mr;
	mw->mr_offset = vaddr - mr->vaddr;
	mw->attr.base.length = length;
	mw->attr.base.access = access;
	do {
		if (unlikely(!det_idr_pre_get(&det_wire_map, GFP_KERNEL)))
			return -ENOMEM;
		wiremap_write_lock_bh();
		err = det_get_id(&det_wire_map, mw, &mr_key);
		wiremap_write_unlock_bh();
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		return err;

	mw->attr.base.r_key = HTON32(mr_key);

	/* Return the r_key to the client. */
	*r_key = mw->attr.base.r_key;

	/*
	 * Increment the window count on the MR.
	 * It will be decremented when the memory window is unbound.
	 */
	atomic_inc(&mr->windows);

	return 0;
}


int det_destroy_mw(struct det_mw * const mw)
{
	struct det_device *detdev = mw->base.detdev;

	/* Release an MW reference. */
	if (atomic_dec_and_test(&mw->base.refcnt))
		complete(&mw->base.done);

	/* Wait for all MW references to go away. */
	det_user_unlock();
	wait_for_completion(&mw->base.done);
	det_user_lock();

	det_unbind_mw(mw);

	atomic_dec(&mw->attr.base.pd->refcnt);

	write_lock(&detdev->lock);
	list_del(&mw->base.entry);
	detdev->mw_cnt--;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_destroy_mw);
