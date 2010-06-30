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


/*
 * This function assumes the caller has allocated and populated the mr->pages
 * array with pinned pages for the memory region and set mr->page_cnt.
 */
int det_reg_mr(struct det_pd * const pd,
	       const struct det_mr_reg * const mr_reg,
	       __u32 * const l_key,
	       net32_t * const r_key,
	       struct det_mr * const mr)
{
	struct det_device *detdev = pd->detdev;
	int i, mr_key, err;

	if (unlikely(((mr_reg->access & DET_AC_REMOTE_READ) &&
		      !(mr_reg->access & DET_AC_LOCAL_READ)) ||
		     ((mr_reg->access & DET_AC_REMOTE_WRITE) &&
		      !(mr_reg->access & DET_AC_LOCAL_WRITE))))
		return -EINVAL;

	if (unlikely((mr_reg->length < MIN_MR_SIZE) ||
		     (mr_reg->length > MAX_MR_SIZE)))
		return -EINVAL;

	if (unlikely((mr_reg->vaddr + (mr_reg->length - 1)) < mr_reg->vaddr))
		return -ERANGE;

	if (unlikely(detdev->mr_cnt >= MAX_MRS))
		return -EAGAIN;

	/* Restrict to percentage of kernel pages. */
	if (mr->page_cnt > (det_max_pages - atomic_read(&det_page_count)))
		return -EDQUOT;

	do {
		if (unlikely(!det_idr_pre_get(&det_wire_map, GFP_KERNEL)))
			return -ENOMEM;
		wiremap_write_lock_bh();
		err = det_get_id(&det_wire_map, mr, &mr_key);
		wiremap_write_unlock_bh();
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		return err;

	mr->base.type = DET_TYPE_MR;
	mr->base.detdev = detdev;
	det_spin_lock_init(&mr->lock);
	mr->vaddr = mr_reg->vaddr;
	mr->attr.l_key = mr_key;
	mr->attr.base.length = mr_reg->length;
	mr->attr.base.access = mr_reg->access;
	mr->attr.base.pd = pd;
	mr->attr.base.r_key =
		(mr_reg->access & (DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE)) ?
			HTON32(mr_key) : HTON32(0);
	init_completion(&mr->base.done);
	atomic_set(&mr->base.refcnt, 1);
	atomic_set(&mr->windows, 0);
	atomic_inc(&pd->refcnt);

	atomic_add(mr->page_cnt, &det_page_count);

	/* Take a reference on the pages. */
	for (i = 0; i < mr->page_cnt; i++)
		get_page(mr->pages[i]);

	*l_key = mr->attr.l_key;
	if (r_key)
		*r_key = mr->attr.base.r_key;

	write_lock(&detdev->lock);
	list_add_tail(&mr->base.entry, &detdev->mr_list);
	detdev->mr_cnt++;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_reg_mr);


int det_query_mr(struct det_mr * const mr,
		 struct det_mr_attr * const mr_attr)
{
	mr_lock(&mr->lock);
	*mr_attr = mr->attr;
	mr_unlock(&mr->lock);

	return 0;
}
EXPORT_SYMBOL(det_query_mr);


int det_modify_mr(struct det_mr * const mr,
		  const struct det_mr_mod * const mr_mod,
		  __u32 * const l_key,
		  net32_t * const r_key)
{
	int mr_key, err;

	if (atomic_read(&mr->windows))
		return -EBUSY;

	if ((mr_mod->flags & DET_MR_MOD_ACCESS) &&
	    (unlikely(((mr_mod->access & DET_AC_REMOTE_READ) &&
		      !(mr_mod->access & DET_AC_LOCAL_READ)) ||
		     ((mr_mod->access & DET_AC_REMOTE_WRITE) &&
		      !(mr_mod->access & DET_AC_LOCAL_WRITE)))))
		return -EINVAL;

	do {
		if (unlikely(!det_idr_pre_get(&det_wire_map, GFP_KERNEL)))
			return -ENOMEM;
		wiremap_write_lock_bh();
		err = det_get_id(&det_wire_map, mr, &mr_key);
		wiremap_write_unlock_bh();
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		return err;

	mr_lock(&mr->lock);

	wiremap_write_lock_bh();
	idr_remove(&det_wire_map, mr->attr.l_key);
	wiremap_write_unlock_bh();

	mr->attr.l_key = mr_key;
	mr->attr.base.r_key =
		(mr_mod->access & (DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE)) ?
			HTON32(mr_key) : HTON32(0);

	if (mr_mod->flags & DET_MR_MOD_PD) {
		atomic_dec(&mr->attr.base.pd->refcnt);
		mr->attr.base.pd = mr_mod->pd;
		atomic_inc(&mr->attr.base.pd->refcnt);
	}

	if (mr_mod->flags & DET_MR_MOD_ACCESS)
		mr->attr.base.access = mr_mod->access;

	*l_key = mr->attr.l_key;
	if (r_key)
		*r_key = mr->attr.base.r_key;

	mr_unlock(&mr->lock);

	return 0;
}
EXPORT_SYMBOL(det_modify_mr);


/*
 * This function assumes the caller has allocated and populated the
 * shared_mr->pages array with pinned pages for the memory region
 * and set shared_mr->page_cnt.
 */
int det_reg_shared(struct det_mr * const mr,
		   const struct det_sh_reg * const sh_reg,
		   __u32 * const l_key,
		   net32_t * const r_key,
		   struct det_mr * const shared_mr)
{
	struct det_device *detdev = mr->base.detdev;
	int i, shared_key, err;

	if (unlikely(((sh_reg->access & DET_AC_REMOTE_READ) &&
		      !(sh_reg->access & DET_AC_LOCAL_READ)) ||
		     ((sh_reg->access & DET_AC_REMOTE_WRITE) &&
		      !(sh_reg->access & DET_AC_LOCAL_WRITE))))
		return -EINVAL;

	if (unlikely(detdev->mr_cnt >= MAX_MRS))
		return -EAGAIN;

	do {
		if (unlikely(!det_idr_pre_get(&det_wire_map, GFP_KERNEL)))
			return -ENOMEM;
		wiremap_write_lock_bh();
		err = det_get_id(&det_wire_map, shared_mr, &shared_key);
		wiremap_write_unlock_bh();
	} while (unlikely(err == -EAGAIN));
	if (unlikely(err))
		return err;

	shared_mr->base.type = DET_TYPE_MR;
	shared_mr->base.detdev = detdev;
	det_spin_lock_init(&shared_mr->lock);
	shared_mr->vaddr = sh_reg->vaddr;
	shared_mr->attr.l_key = shared_key;
	shared_mr->attr.base.length = mr->attr.base.length;
	shared_mr->attr.base.access = sh_reg->access;
	shared_mr->attr.base.pd = sh_reg->pd;
	shared_mr->attr.base.r_key =
		(sh_reg->access & (DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE)) ?
			HTON32(shared_key) : HTON32(0);
	init_completion(&shared_mr->base.done);
	atomic_set(&shared_mr->base.refcnt, 1);
	atomic_set(&shared_mr->windows, 0);
	atomic_inc(&sh_reg->pd->refcnt);

	/* Take a reference on the pages. */
	for (i = 0; i < shared_mr->page_cnt; i++)
		get_page(shared_mr->pages[i]);

	*l_key = shared_mr->attr.l_key;
	if (r_key)
		*r_key = shared_mr->attr.base.r_key;

	write_lock(&detdev->lock);
	list_add_tail(&shared_mr->base.entry, &detdev->mr_list);
	detdev->mr_cnt++;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_reg_shared);


/*
 * This function assumes that the caller will free the mr->pages array.
 */
int det_dereg_mr(struct det_mr * const mr)
{
	struct det_device *detdev = mr->base.detdev;
	int i;

	if (atomic_read(&mr->windows))
		return -EBUSY;

	/* Remove the key from the map. */
	wiremap_write_lock_bh();
	idr_remove(&det_wire_map, mr->attr.l_key);
	wiremap_write_unlock_bh();

	/* Release an MR reference. */
	if (atomic_dec_and_test(&mr->base.refcnt))
		complete(&mr->base.done);

	/* Wait for all MR references to go away. */
	det_user_unlock();
	wait_for_completion(&mr->base.done);
	det_user_lock();

	atomic_sub(mr->page_cnt, &det_page_count);

	/* Drop a reference on the pages. */
	for (i = 0; i < mr->page_cnt; i++)
		put_page(mr->pages[i]);

	atomic_dec(&mr->attr.base.pd->refcnt);

	write_lock(&detdev->lock);
	list_del(&mr->base.entry);
	detdev->mr_cnt--;
	write_unlock(&detdev->lock);

	return 0;
}
EXPORT_SYMBOL(det_dereg_mr);
