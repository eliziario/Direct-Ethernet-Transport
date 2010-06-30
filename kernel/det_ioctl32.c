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


#ifdef	CONFIG_COMPAT

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
int det_ioctl(struct inode *, struct file *, unsigned int, unsigned long);
long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	struct file *filp;
	int err;

	filp = fget(fd);
	if (unlikely(!filp))
		return -EBADF;

	err = det_ioctl(filp->f_dentry->d_inode, filp, cmd, arg);

	fput(filp);

	return err;
}
#endif

/*
 * Conversion routines for mixed-mode operation.
 * (64-bit kernel conversion for 32-bit user-mode ioctl calls).
 */

static int det_query_ioctl32(unsigned int fd,
			     unsigned int cmd,
			     unsigned long arg,
			     struct file *filp)
{
	struct det_attr attr;
	mm_segment_t oldfs;
	int err;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_QUERY, (unsigned long)&attr);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	if (unlikely(copy_to_user(compat_ptr(arg), &attr, sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_create_event_ioctl32(unsigned int fd,
				    unsigned int cmd,
				    unsigned long arg,
				    struct file *filp)
{
	mm_segment_t oldfs;
	int event_id, err;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_CREATE_EVENT, (unsigned long)&event_id);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	err = put_user(event_id, (int __user *)arg);
	if (unlikely(err))
		sys_ioctl(fd, DET_IOC_DESTROY_EVENT, (unsigned long)&event_id);

	return err;
}


static int det_wait_on_event_ioctl32(unsigned int fd,
				     unsigned int cmd,
				     unsigned long arg,
				     struct file *filp)
{
	struct det_ioc32_wait_on_event wait32;
	struct det_ioc_wait_on_event wait;
	struct det_ioc32_event event32;
	struct det_ioc_event event;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&wait32, (void __user *)arg,
				    sizeof(wait32))))
		return -EFAULT;

	wait.event    = (wait32.event) ? &event : NULL;
	wait.event_id = wait32.event_id;
	wait.timeout  = wait32.timeout;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_WAIT_ON_EVENT, (unsigned long)&wait);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	event32.context	    = event.context;
	event32.record.code = event.record.code;
	event32.record.type = event.record.type;

	if (wait32.event &&
	    unlikely(copy_to_user(compat_ptr(wait32.event), &event32,
				  sizeof(event32))))
		return -EFAULT;

	return 0;
}


static int det_generate_event_ioctl32(unsigned int fd,
				      unsigned int cmd,
				      unsigned long arg,
				      struct file *filp)
{
	struct det_ioc32_generate_event generate32;
	struct det_ioc_generate_event generate;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&generate32, (void __user *)arg,
				    sizeof(generate32))))
		return -EFAULT;

	generate.event_id = generate32.event_id;
	generate.handle	  = (void *)(unsigned long)generate32.handle;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_GENERATE_EVENT, (unsigned long)&generate);
	set_fs(oldfs);

	return err;
}


static int det_destroy_event_ioctl32(unsigned int fd,
				     unsigned int cmd,
				     unsigned long arg,
				     struct file *filp)
{
	mm_segment_t oldfs;
	int event_id, err;

	err = get_user(event_id, (int __user *)arg);
	if (unlikely(err))
		return err;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_DESTROY_EVENT, (unsigned long)&event_id);
	set_fs(oldfs);

	return err;
}


static int det_open_nic_ioctl32(unsigned int fd,
				unsigned int cmd,
				unsigned long arg,
				struct file *filp)
{
	struct det_ioc32_open_nic open32;
	struct det_ioc_open_nic open;
	mm_segment_t oldfs;
	int nic_id, err;

	if (unlikely(copy_from_user(&open32, (void __user *)arg,
				    sizeof(open32))))
		return -EFAULT;

	open.context  = open32.context;
	open.nic_id   = &nic_id;
	strncpy(open.ifname, open32.ifname, IFNAMSIZ);
	open.event_id = open32.event_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_OPEN_NIC, (unsigned long)&open);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	err = put_user(nic_id, (int __user *)(unsigned long)open32.nic_id);
	if (unlikely(err))
		sys_ioctl(fd, DET_IOC_CLOSE_NIC, (unsigned long)&nic_id);

	return err;
}


static int det_query_nic_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_query_nic query32;
	struct det_ioc_query_nic query;
	struct det_nic_attr attr;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&query32, (void __user *)arg,
				    sizeof(query32))))
		return -EFAULT;

	query.attr   = &attr;
	query.nic_id = query32.nic_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_QUERY_NIC, (unsigned long)&query);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	if (unlikely(copy_to_user(compat_ptr(query32.attr), &attr,
				  sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_close_nic_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_close_nic close32;
	struct det_ioc_close_nic close;
	mm_segment_t oldfs;
	int nr_events, err;

	if (unlikely(copy_from_user(&close32, (void __user *)arg,
				    sizeof(close32))))
		return -EFAULT;

	close.nr_events = &nr_events;
	close.nic_id	= close32.nic_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_CLOSE_NIC, (unsigned long)&close);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	return put_user(nr_events,
			(int __user *)(unsigned long)close32.nr_events);
}


static int det_alloc_pd_ioctl32(unsigned int fd,
				unsigned int cmd,
				unsigned long arg,
				struct file *filp)
{
	struct det_ioc32_alloc_pd alloc32;
	struct det_ioc_alloc_pd alloc;
	mm_segment_t oldfs;
	int pd_id, err;

	if (unlikely(copy_from_user(&alloc32, (void __user *)arg,
				    sizeof(alloc32))))
		return -EFAULT;

	alloc.pd_id  = &pd_id;
	alloc.nic_id = alloc32.nic_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_ALLOC_PD, (unsigned long)&alloc);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	err = put_user(pd_id, (int __user *)(unsigned long)alloc32.pd_id);
	if (unlikely(err))
		sys_ioctl(fd, DET_IOC_DEALLOC_PD, (unsigned long)&pd_id);

	return err;
}


static int det_dealloc_pd_ioctl32(unsigned int fd,
				  unsigned int cmd,
				  unsigned long arg,
				  struct file *filp)
{
	mm_segment_t oldfs;
	int pd_id, err;

	err = get_user(pd_id, (int __user *)arg);
	if (unlikely(err))
		return err;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_DEALLOC_PD, (unsigned long)&pd_id);
	set_fs(oldfs);

	return err;
}


static int det_create_cq_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_create_cq create32;
	struct det_ioc_create_cq create;
	struct det_cq_attr attr;
	mm_segment_t oldfs;
	int cq_id, err;

	if (unlikely(copy_from_user(&create32, (void __user *)arg,
				    sizeof(create32))))
		return -EFAULT;

	create.context	= create32.context;
	create.cq_id	= &cq_id;
	create.attr	= (create32.attr) ? &attr : NULL;
	create.size	= create32.size;
	create.nic_id	= create32.nic_id;
	create.event_id = create32.event_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_CREATE_CQ, (unsigned long)&create);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	if (create32.attr &&
	    unlikely(copy_to_user(compat_ptr(create32.attr), &attr,
				  sizeof(attr)))) {
		err = -EFAULT;
		goto out;
	}

	err = put_user(cq_id, (int __user *)(unsigned long)create32.cq_id);
	if (unlikely(err))
		goto out;

	return 0;

out:
	sys_ioctl(fd, DET_IOC_DESTROY_CQ, (unsigned long)&cq_id);
	return err;
}


static int det_query_cq_ioctl32(unsigned int fd,
				unsigned int cmd,
				unsigned long arg,
				struct file *filp)
{
	struct det_ioc32_query_cq query32;
	struct det_ioc_query_cq query;
	struct det_cq_attr attr;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&query32, (void __user *)arg,
				    sizeof(query32))))
		return -EFAULT;

	query.attr  = &attr;
	query.cq_id = query32.cq_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_QUERY_CQ, (unsigned long)&query);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	if (unlikely(copy_to_user(compat_ptr(query32.attr), &attr,
				  sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_resize_cq_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_resize_cq resize32;
	struct det_ioc_resize_cq resize;
	struct det_cq_attr attr;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&resize32, (void __user *)arg,
				    sizeof(resize32))))
		return -EFAULT;

	resize.attr  = (resize32.attr) ? &attr : NULL;
	resize.size  = resize32.size;
	resize.cq_id = resize32.cq_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_RESIZE_CQ, (unsigned long)&resize);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	if (resize32.attr &&
	    unlikely(copy_to_user(compat_ptr(resize32.attr), &attr,
				  sizeof(attr))))
		return -EFAULT;

	return 0;
}


static int det_poll_cq_ioctl32(unsigned int fd,
			       unsigned int cmd,
			       unsigned long arg,
			       struct file *filp)
{
	struct det_ioc32_poll_cq poll32;
	struct det_ioc_poll_cq poll;
	mm_segment_t oldfs;
	u32 num_wc;
	int err;

	if (unlikely(copy_from_user(&poll32, (void __user *)arg,
				    sizeof(poll32))))
		return -EFAULT;

	poll.wc_array = compat_ptr(poll32.wc_array);
	poll.p_num_wc = &num_wc;
	poll.num_wc   = poll32.num_wc;
	poll.cq_id    = poll32.cq_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_POLL_CQ, (unsigned long)&poll);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	return put_user(num_wc, (__u32 __user *)(unsigned long)poll32.p_num_wc);
}


static int det_destroy_cq_ioctl32(unsigned int fd,
				  unsigned int cmd,
				  unsigned long arg,
				  struct file *filp)
{
	struct det_ioc32_destroy_cq destroy32;
	struct det_ioc_destroy_cq destroy;
	mm_segment_t oldfs;
	int nr_events, err;

	if (unlikely(copy_from_user(&destroy32, (void __user *)arg,
				    sizeof(destroy32))))
		return -EFAULT;

	destroy.nr_events = &nr_events;
	destroy.cq_id	  = destroy32.cq_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_DESTROY_CQ, (unsigned long)&destroy);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	return put_user(nr_events,
			(int __user *)(unsigned long)destroy32.nr_events);
}


static int det_create_qp_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_create_qp create32;
	struct det_ioc_create_qp create;
	struct det_qp_create32 qp_create32;
	struct det_qp_create qp_create;
	struct det_qp_attr32 attr32;
	struct det_qp_attr attr;
	mm_segment_t oldfs;
	int qp_id, err;

	if (unlikely(copy_from_user(&create32, (void __user *)arg,
				    sizeof(create32))))
		return -EFAULT;

	if (unlikely(copy_from_user(&qp_create32, compat_ptr(create32.create),
				    sizeof(qp_create32))))
		return -EFAULT;

	create.context	= create32.context;
	create.qp_id	= &qp_id;
	create.create	= &qp_create;
	create.attr	= (create32.attr) ? &attr : NULL;
	create.sq_cq_id = create32.sq_cq_id;
	create.rq_cq_id = create32.sq_cq_id;
	create.pd_id	= create32.pd_id;

	qp_create.sq_size = qp_create32.sq_size;
	qp_create.rq_size = qp_create32.rq_size;
	qp_create.sq_sges = qp_create32.sq_sges;
	qp_create.rq_sges = qp_create32.rq_sges;
	qp_create.max_or  = qp_create32.max_or;
	qp_create.max_ir  = qp_create32.max_ir;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_CREATE_QP, (unsigned long)&create);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	if (create32.attr) {
		attr32.state	     = attr.state;
		attr32.mtu_size      = attr.mtu_size;
		attr32.sq_size	     = attr.sq_size;
		attr32.rq_size	     = attr.rq_size;
		attr32.sq_sges	     = attr.sq_sges;
		attr32.rq_sges	     = attr.rq_sges;
		attr32.max_or	     = attr.max_or;
		attr32.max_ir	     = attr.max_ir;
		attr32.local_qp_num  = attr.local_qp_num;
		attr32.remote_qp_num = attr.remote_qp_num;
		attr32.local_mac     = attr.local_mac;
		attr32.remote_mac    = attr.remote_mac;

		if (unlikely(copy_to_user(compat_ptr(create32.attr), &attr32,
				sizeof(attr32)))) {
			err = -EFAULT;
			goto out;
		}
	}

	err = put_user(qp_id, (int __user *)(unsigned long)create32.qp_id);
	if (unlikely(err))
		goto out;

	return 0;

out:
	sys_ioctl(fd, DET_IOC_DESTROY_QP, (unsigned long)&qp_id);
	return err;
}


static int det_query_qp_ioctl32(unsigned int fd,
				unsigned int cmd,
				unsigned long arg,
				struct file *filp)
{
	struct det_ioc32_query_qp query32;
	struct det_ioc_query_qp query;
	struct det_qp_attr32 attr32;
	struct det_qp_attr attr;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&query32, (void __user *)arg,
				    sizeof(query32))))
		return -EFAULT;

	query.attr  = &attr;
	query.qp_id = query32.qp_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_QUERY_QP, (unsigned long)&query);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	attr32.state	     = attr.state;
	attr32.mtu_size	     = attr.mtu_size;
	attr32.sq_size	     = attr.sq_size;
	attr32.rq_size	     = attr.rq_size;
	attr32.sq_sges	     = attr.sq_sges;
	attr32.rq_sges	     = attr.rq_sges;
	attr32.max_or	     = attr.max_or;
	attr32.max_ir	     = attr.max_ir;
	attr32.local_qp_num  = attr.local_qp_num;
	attr32.remote_qp_num = attr.remote_qp_num;
	attr32.local_mac     = attr.local_mac;
	attr32.remote_mac    = attr.remote_mac;

	if (unlikely(copy_to_user(compat_ptr(query32.attr), &attr32,
				  sizeof(attr32))))
		return -EFAULT;

	return 0;
}


static int det_modify_qp_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_modify_qp modify32;
	struct det_ioc_modify_qp modify;
	struct det_qp_mod mod;
	struct det_qp_attr32 attr32;
	struct det_qp_attr attr;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&modify32, (void __user *)arg,
				    sizeof(modify32))))
		return -EFAULT;

	if (unlikely(copy_from_user(&mod, compat_ptr(modify32.mod),
				    sizeof(mod))))
		return -EFAULT;

	modify.mod   = &mod;
	modify.attr  = (modify32.attr) ? &attr : NULL;
	modify.qp_id = modify32.qp_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_MODIFY_QP, (unsigned long)&modify);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	if (modify32.attr) {
		attr32.state	     = attr.state;
		attr32.mtu_size	     = attr.mtu_size;
		attr32.sq_size	     = attr.sq_size;
		attr32.rq_size	     = attr.rq_size;
		attr32.sq_sges	     = attr.sq_sges;
		attr32.rq_sges	     = attr.rq_sges;
		attr32.max_or	     = attr.max_or;
		attr32.max_ir	     = attr.max_ir;
		attr32.local_qp_num  = attr.local_qp_num;
		attr32.remote_qp_num = attr.remote_qp_num;
		attr32.local_mac     = attr.local_mac;
		attr32.remote_mac    = attr.remote_mac;

		if (unlikely(copy_to_user(compat_ptr(modify32.attr), &attr32,
					  sizeof(attr32))))
			return -EFAULT;
	}

	return 0;
}


static int det_destroy_qp_ioctl32(unsigned int fd,
				  unsigned int cmd,
				  unsigned long arg,
				  struct file *filp)
{
	struct det_ioc32_destroy_qp destroy32;
	struct det_ioc_destroy_qp destroy;
	mm_segment_t oldfs;
	int nr_events, err;

	if (unlikely(copy_from_user(&destroy32, (void __user *)arg,
				    sizeof(destroy32))))
		return -EFAULT;

	destroy.nr_events = &nr_events;
	destroy.qp_id	  = destroy32.qp_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_DESTROY_QP, (unsigned long)&destroy);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	return put_user(nr_events,
			(int __user *)(unsigned long)destroy32.nr_events);
}


static int det_reg_mr_ioctl32(unsigned int fd,
			      unsigned int cmd,
			      unsigned long arg,
			      struct file *filp)
{
	struct det_ioc32_reg_mr reg32;
	struct det_ioc_reg_mr reg;
	__u32 l_key;
	net32_t r_key;
	mm_segment_t oldfs;
	int mr_id, err;

	if (unlikely(copy_from_user(&reg32, (void __user *)arg, sizeof(reg32))))
		return -EFAULT;

	reg.mr_id  = &mr_id;
	reg.l_key  = &l_key;
	reg.r_key  = (reg32.r_key) ? &r_key : NULL;
	reg.mr_reg = reg32.mr_reg;
	reg.pd_id  = reg32.pd_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_REG_MR, (unsigned long)&reg);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	err = put_user(mr_id, (int __user *)(unsigned long)reg32.mr_id);
	if (unlikely(err))
		goto out;

	err = put_user(l_key, (__u32 __user *)(unsigned long)reg32.l_key);
	if (unlikely(err))
		goto out;

	if (reg32.r_key) {
		err = put_user(r_key,
			       (net32_t __user *)(unsigned long)reg32.r_key);
		if (unlikely(err))
			goto out;
	}

	return 0;

out:
	sys_ioctl(fd, DET_IOC_DEREG_MR, (unsigned long)&mr_id);
	return err;
}


static int det_query_mr_ioctl32(unsigned int fd,
				unsigned int cmd,
				unsigned long arg,
				struct file *filp)
{
	struct det_ioc32_query_mr query32;
	struct det_ioc_query_mr query;
	struct det_mr_attr32 attr32;
	struct det_mr_attr attr;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&query32, (void __user *)arg,
				    sizeof(query32))))
		return -EFAULT;

	query.attr  = &attr;
	query.mr_id = query32.mr_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_QUERY_MR, (unsigned long)&query);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	attr32.base.r_key  = attr.base.r_key;
	attr32.base.length = attr.base.length;
	attr32.base.access = attr.base.access;
	attr32.l_key	   = attr.l_key;

	if (unlikely(copy_to_user(compat_ptr(query32.attr), &attr32,
				  sizeof(attr32))))
		return -EFAULT;

	return 0;
}


static int det_modify_mr_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_modify_mr modify32;
	struct det_ioc_modify_mr modify;
	struct det_mr_mod32 mod32;
	struct det_mr_mod mod;
	__u32 l_key;
	net32_t r_key;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&modify32, (void __user *)arg,
				    sizeof(modify32))))
		return -EFAULT;

	if (unlikely(copy_from_user(&mod32, compat_ptr(modify32.mod),
				    sizeof(mod32))))
		return -EFAULT;

	modify.mod   = &mod;
	modify.l_key = &l_key;
	modify.r_key = (modify32.r_key) ? &r_key : NULL;
	modify.mr_id = modify32.mr_id;
	modify.pd_id = modify32.pd_id;

	mod.flags  = mod32.flags;
	mod.access = mod32.access;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_MODIFY_MR, (unsigned long)&modify);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	err = put_user(l_key, (__u32 __user *)(unsigned long)modify32.l_key);
	if (unlikely(err))
		return err;

	if (modify32.r_key) {
		err = put_user(r_key,
			       (net32_t __user *)(unsigned long)modify32.r_key);
		if (unlikely(err))
			return err;
	}

	return 0;
}


static int det_reg_shared_ioctl32(unsigned int fd,
				  unsigned int cmd,
				  unsigned long arg,
				  struct file *filp)
{
	struct det_ioc32_reg_shared reg32;
	struct det_ioc_reg_shared reg;
	__u32 l_key;
	net32_t r_key;
	mm_segment_t oldfs;
	int shared_id, err;

	if (unlikely(copy_from_user(&reg32, (void __user *)arg, sizeof(reg32))))
		return -EFAULT;

	reg.shared_id = &shared_id;
	reg.l_key     = &l_key;
	reg.r_key     = (reg32.r_key) ? &r_key : NULL;
	reg.access    = reg32.access;
	reg.pd_id     = reg32.pd_id;
	reg.mr_id     = reg32.mr_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_REG_SHARED, (unsigned long)&reg);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	err = put_user(shared_id, (int __user *)(unsigned long)reg32.shared_id);
	if (unlikely(err))
		goto out;

	err = put_user(l_key, (__u32 __user *)(unsigned long)reg32.l_key);
	if (unlikely(err))
		goto out;

	if (reg32.r_key) {
		err = put_user(r_key,
			       (net32_t __user *)(unsigned long)reg32.r_key);
		if (unlikely(err))
			goto out;
	}

	return 0;

out:
	sys_ioctl(fd, DET_IOC_DEREG_MR, (unsigned long)&shared_id);
	return err;
}


static int det_dereg_mr_ioctl32(unsigned int fd,
				unsigned int cmd,
				unsigned long arg,
				struct file *filp)
{
	mm_segment_t oldfs;
	int mr_id, err;

	err = get_user(mr_id, (int __user *)arg);
	if (unlikely(err))
		return err;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_DEREG_MR, (unsigned long)&mr_id);
	set_fs(oldfs);

	return err;
}


static int det_create_mw_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_create_mw create32;
	struct det_ioc_create_mw create;
	mm_segment_t oldfs;
	int mw_id, err;

	if (unlikely(copy_from_user(&create32, (void __user *)arg,
				    sizeof(create32))))
		return -EFAULT;

	create.mw_id = &mw_id;
	create.pd_id = create32.pd_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_CREATE_MW, (unsigned long)&create);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	err = put_user(mw_id, (int __user *)(unsigned long)create32.mw_id);
	if (unlikely(err))
		sys_ioctl(fd, DET_IOC_DESTROY_MW, (unsigned long)&mw_id);

	return err;
}


static int det_query_mw_ioctl32(unsigned int fd,
				unsigned int cmd,
				unsigned long arg,
				struct file *filp)
{
	struct det_ioc32_query_mw query32;
	struct det_ioc_query_mw query;
	struct det_mw_attr32 attr32;
	struct det_mw_attr attr;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&query32, (void __user *)arg,
				    sizeof(query32))))
		return -EFAULT;

	query.attr  = &attr;
	query.mw_id = query32.mw_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_QUERY_MW, (unsigned long)&query);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	attr32.base.r_key  = attr.base.r_key;
	attr32.base.length = attr.base.length;
	attr32.base.access = attr.base.access;

	if (unlikely(copy_to_user(compat_ptr(query32.attr), &attr32,
				  sizeof(attr32))))
		return -EFAULT;

	return 0;
}


static int det_destroy_mw_ioctl32(unsigned int fd,
				  unsigned int cmd,
				  unsigned long arg,
				  struct file *filp)
{
	mm_segment_t oldfs;
	int mw_id, err;

	err = get_user(mw_id, (int __user *)arg);
	if (unlikely(err))
		return err;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_DESTROY_MW, (unsigned long)&mw_id);
	set_fs(oldfs);

	return err;
}


static int det_send_ioctl32(unsigned int fd,
			    unsigned int cmd,
			    unsigned long arg,
			    struct file *filp)
{
	struct det_ioc32_send send32;
	struct det_ioc_send send;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&send32, (void __user *)arg,
				    sizeof(send32))))
		return -EFAULT;

	send.wr_id	    = send32.wr_id;
	send.ds_array	    = compat_ptr(send32.ds_array);
	send.num_ds	    = send32.num_ds;
	send.immediate_data = send32.immediate_data;
	send.flags	    = send32.flags;
	send.qp_id	    = send32.qp_id;

	if (send32.num_ds && (send32.num_ds <= MAX_IOC_NUM_DS))
		det_memcpy(send.local_ds, send32.local_ds,
			sizeof(send32.local_ds[0]) * send32.num_ds);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_SEND, (unsigned long)&send);
	set_fs(oldfs);

	return err;
}


static int det_recv_ioctl32(unsigned int fd,
			    unsigned int cmd,
			    unsigned long arg,
			    struct file *filp)
{
	struct det_ioc32_recv recv32;
	struct det_ioc_recv recv;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&recv32, (void __user *)arg,
				    sizeof(recv32))))
		return -EFAULT;

	recv.wr_id    = recv32.wr_id;
	recv.ds_array = compat_ptr(recv32.ds_array);
	recv.num_ds   = recv32.num_ds;
	recv.qp_id    = recv32.qp_id;

	if (recv32.num_ds && (recv32.num_ds <= MAX_IOC_NUM_DS))
		det_memcpy(recv.local_ds, recv32.local_ds,
			sizeof(recv32.local_ds[0]) * recv32.num_ds);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_RECV, (unsigned long)&recv);
	set_fs(oldfs);

	return err;
}


static int det_read_ioctl32(unsigned int fd,
			    unsigned int cmd,
			    unsigned long arg,
			    struct file *filp)
{
	struct det_ioc32_read read32;
	struct det_ioc_read read;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&read32, (void __user *)arg,
				    sizeof(read32))))
		return -EFAULT;

	read.wr_id	    = read32.wr_id;
	read.ds_array	    = compat_ptr(read32.ds_array);
	read.num_ds	    = read32.num_ds;
	read.remote_address = read32.remote_address;
	read.remote_key	    = read32.remote_key;
	read.flags	    = read32.flags;
	read.qp_id	    = read32.qp_id;

	if (read32.num_ds && (read32.num_ds <= MAX_IOC_NUM_DS))
		det_memcpy(read.local_ds, read32.local_ds,
			sizeof(read32.local_ds[0]) * read32.num_ds);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_READ, (unsigned long)&read);
	set_fs(oldfs);

	return err;
}


static int det_write_ioctl32(unsigned int fd,
			     unsigned int cmd,
			     unsigned long arg,
			     struct file *filp)
{
	struct det_ioc32_write write32;
	struct det_ioc_write write;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&write32, (void __user *)arg,
				    sizeof(write32))))
		return -EFAULT;

	write.wr_id	     = write32.wr_id;
	write.ds_array	     = compat_ptr(write32.ds_array);
	write.num_ds	     = write32.num_ds;
	write.remote_address = write32.remote_address;
	write.remote_key     = write32.remote_key;
	write.immediate_data = write32.immediate_data;
	write.flags	     = write32.flags;
	write.qp_id	     = write32.qp_id;

	if (write32.num_ds && (write32.num_ds <= MAX_IOC_NUM_DS))
		det_memcpy(write.local_ds, write32.local_ds,
			sizeof(write32.local_ds[0]) * write32.num_ds);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_WRITE, (unsigned long)&write);
	set_fs(oldfs);

	return err;
}


static int det_bind_ioctl32(unsigned int fd,
			    unsigned int cmd,
			    unsigned long arg,
			    struct file *filp)
{
	struct det_ioc32_bind bind32;
	struct det_ioc_bind bind;
	net32_t r_key;
	mm_segment_t oldfs;
	int err;

	if (unlikely(copy_from_user(&bind32, (void __user *)arg,
				    sizeof(bind32))))
		return -EFAULT;

	bind.wr_id  = bind32.wr_id;
	bind.qp_id  = bind32.qp_id;
	bind.mr_id  = bind32.mr_id;
	bind.mw_id  = bind32.mw_id;
	bind.r_key  = &r_key;
	bind.vaddr  = bind32.vaddr;
	bind.length = bind32.length;
	bind.access = bind32.access;
	bind.flags  = bind32.flags;

	/* Verify that put_user will succeed before initiating the bind. */
	err = put_user(r_key, (net32_t __user *)(unsigned long)bind32.r_key);
	if (unlikely(err))
		return err;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_BIND, (unsigned long)&bind);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	/* Now use put_user to return the actual bind r_key. */
	return put_user(r_key, (net32_t __user *)(unsigned long)bind32.r_key);
}


static int det_create_co_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_create_co create32;
	struct det_ioc_create_co create;
	mm_segment_t oldfs;
	int co_id, err;

	if (unlikely(copy_from_user(&create32, (void __user *)arg,
				    sizeof(create32))))
		return -EFAULT;

	create.context = create32.context;
	create.co_id   = &co_id;
	create.pd_id   = create32.pd_id;
	create.cq_id   = create32.cq_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_CREATE_CO, (unsigned long)&create);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	err = put_user(co_id, (int __user *)(unsigned long)create32.co_id);
	if (unlikely(err))
		sys_ioctl(fd, DET_IOC_DESTROY_CO, (unsigned long)&co_id);

	return err;
}


static int det_destroy_co_ioctl32(unsigned int fd,
				  unsigned int cmd,
				  unsigned long arg,
				  struct file *filp)
{
	struct det_ioc32_destroy_co destroy32;
	struct det_ioc_destroy_co destroy;
	mm_segment_t oldfs;
	int nr_events, err;

	if (unlikely(copy_from_user(&destroy32, (void __user *)arg,
				    sizeof(destroy32))))
		return -EFAULT;

	destroy.nr_events = &nr_events;
	destroy.co_id	  = destroy32.co_id;

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_DESTROY_CO, (unsigned long)&destroy);
	set_fs(oldfs);

	if (unlikely(err))
		return err;

	return put_user(nr_events,
			(int __user *)(unsigned long)destroy32.nr_events);
}


static int det_scatterv_ioctl32(unsigned int fd,
				unsigned int cmd,
				unsigned long arg,
				struct file *filp)
{
	struct det_ioc32_scatterv scatterv32;
	struct det_ioc_scatterv scatterv;
	struct det_device *detdev;
	struct det_co *co;
	mm_segment_t oldfs;
	int size, err;

	if (unlikely(copy_from_user(&scatterv32, (void __user *)arg,
				    sizeof(scatterv32))))
		return -EFAULT;

	scatterv.wr_id	      = scatterv32.wr_id;
	scatterv.src_ds_array = compat_ptr(scatterv32.src_ds_array);
	scatterv.dst_ds	      = scatterv32.dst_ds;
	scatterv.root	      = scatterv32.root;
	scatterv.flags	      = scatterv32.flags;
	scatterv.co_id	      = scatterv32.co_id;

	if (scatterv.src_ds_array) {
		detdev = filp->private_data;
		det_user_lock();
		read_lock(&detdev->map_lock);
		co = idr_find(&detdev->map, scatterv.co_id);
		if (unlikely(!co || co->id != scatterv.co_id ||
			     co->type != DET_TYPE_CO)) {
			write_unlock(&detdev->map_lock);
			return -EINVAL;
		}
		size = co->size;
		read_unlock(&detdev->map_lock);
		det_user_unlock();

		if (size <= MAX_IOC_NUM_DS)
			det_memcpy((void*)scatterv.src_ds_array,
			  compat_ptr(scatterv32.src_ds_array),
			  sizeof(*compat_ptr(scatterv32.src_ds_array)) * size);
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_SCATTERV, (unsigned long)&scatterv);
	set_fs(oldfs);

	return err;
}


static int det_gatherv_ioctl32(unsigned int fd,
			       unsigned int cmd,
			       unsigned long arg,
			       struct file *filp)
{
	struct det_ioc32_gatherv gatherv32;
	struct det_ioc_gatherv gatherv;
	struct det_device *detdev;
	struct det_co *co;
	mm_segment_t oldfs;
	int size, err;

	if (unlikely(copy_from_user(&gatherv32, (void __user *)arg,
				    sizeof(gatherv32))))
		return -EFAULT;

	gatherv.wr_id	     = gatherv32.wr_id;
	gatherv.src_ds	     = gatherv32.src_ds;
	gatherv.dst_ds_array = compat_ptr(gatherv32.dst_ds_array);
	gatherv.root	     = gatherv32.root;
	gatherv.flags	     = gatherv32.flags;
	gatherv.co_id	     = gatherv32.co_id;

	if (gatherv32.dst_ds_array) {
		detdev = filp->private_data;
		det_user_lock();
		read_lock(&detdev->map_lock);
		co = idr_find(&detdev->map, gatherv.co_id);
		if (unlikely(!co || co->id != gatherv.co_id ||
			     co->type != DET_TYPE_CO)) {
			write_unlock(&detdev->map_lock);
			return -EINVAL;
		}
		size = co->size;
		read_unlock(&detdev->map_lock);
		det_user_unlock();

		if (size <= MAX_IOC_NUM_DS)
			det_memcpy((void*)gatherv.dst_ds_array,
			  compat_ptr(gatherv32.dst_ds_array),
			  sizeof(*compat_ptr(gatherv32.dst_ds_array)) * size);
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_GATHERV, (unsigned long)&gatherv);
	set_fs(oldfs);

	return err;
}


static int det_allgatherv_ioctl32(unsigned int fd,
				  unsigned int cmd,
				  unsigned long arg,
				  struct file *filp)
{
	struct det_ioc32_allgatherv allgatherv32;
	struct det_ioc_allgatherv allgatherv;
	struct det_device *detdev;
	struct det_co *co;
	mm_segment_t oldfs;
	int size, err;

	if (unlikely(copy_from_user(&allgatherv32, (void __user *)arg,
				    sizeof(allgatherv32))))
		return -EFAULT;

	allgatherv.wr_id	= allgatherv32.wr_id;
	allgatherv.src_ds	= allgatherv32.src_ds;
	allgatherv.dst_ds_array = compat_ptr(allgatherv32.dst_ds_array);
	allgatherv.flags	= allgatherv32.flags;
	allgatherv.co_id	= allgatherv32.co_id;

	detdev = filp->private_data;
	det_user_lock();
	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, allgatherv.co_id);
	if (unlikely(!co || co->id != allgatherv.co_id ||
		     co->type != DET_TYPE_CO)) {
		write_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	size = co->size;
	read_unlock(&detdev->map_lock);
	det_user_unlock();

	if (size <= MAX_IOC_NUM_DS)
		det_memcpy((void*)allgatherv.dst_ds_array,
		   compat_ptr(allgatherv32.dst_ds_array),
		   sizeof(*compat_ptr(allgatherv32.dst_ds_array)) * size);

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_ALLGATHERV, (unsigned long)&allgatherv);
	set_fs(oldfs);

	return err;
}


static int det_alltoallv_ioctl32(unsigned int fd,
				 unsigned int cmd,
				 unsigned long arg,
				 struct file *filp)
{
	struct det_ioc32_alltoallv alltoallv32;
	struct det_ioc_alltoallv alltoallv;
	struct det_device *detdev;
	struct det_co *co;
	mm_segment_t oldfs;
	int size, err;

	if (unlikely(copy_from_user(&alltoallv32, (void __user *)arg,
				    sizeof(alltoallv32))))
		return -EFAULT;

	alltoallv.wr_id	       = alltoallv32.wr_id;
	alltoallv.src_ds_array = compat_ptr(alltoallv32.src_ds_array);
	alltoallv.dst_ds_array = compat_ptr(alltoallv32.dst_ds_array);
	alltoallv.flags	       = alltoallv32.flags;
	alltoallv.co_id	       = alltoallv32.co_id;

	detdev = filp->private_data;
	det_user_lock();
	read_lock(&detdev->map_lock);
	co = idr_find(&detdev->map, alltoallv.co_id);
	if (unlikely(!co || co->id != alltoallv.co_id ||
		     co->type != DET_TYPE_CO)) {
		write_unlock(&detdev->map_lock);
		return -EINVAL;
	}
	size = co->size;
	read_unlock(&detdev->map_lock);
	det_user_unlock();

	if (size <= MAX_IOC_NUM_DS) {
		det_memcpy((void*)alltoallv.src_ds_array,
		   compat_ptr(alltoallv32.src_ds_array),
		   sizeof(*compat_ptr(alltoallv32.src_ds_array)) * size);
		det_memcpy((void*)alltoallv.dst_ds_array,
		   compat_ptr(alltoallv32.dst_ds_array),
		   sizeof(*compat_ptr(alltoallv32.dst_ds_array)) * size);
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	err = sys_ioctl(fd, DET_IOC_ALLTOALLV, (unsigned long)&alltoallv);
	set_fs(oldfs);

	return err;
}


long det_compat_ioctl(struct file *filp,
		      unsigned int cmd,
		      unsigned long arg)
{
	struct files_struct *files;
	unsigned int max_fds;
	unsigned int fd;
	long err;

	/* Lookup the fd for this filp. */
	files = current->files;
	spin_lock(&files->file_lock);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
	max_fds = files_fdtable(files)->max_fds;
#else
	max_fds = files->max_fds;
#endif
	for (fd = 0; fd < max_fds; fd++) {
		if (fcheck_files(files, fd) == filp)
			break;
	}
	spin_unlock(&files->file_lock);
	if (fd >= max_fds)
		return -EBADF;

	switch (cmd) {
		case DET_IOC_QUERY:
			err = det_query_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_CREATE_EVENT:
			err = det_create_event_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_WAIT_ON_EVENT:
			err = det_wait_on_event_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_GENERATE_EVENT:
			err = det_generate_event_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_DESTROY_EVENT:
			err = det_destroy_event_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_OPEN_NIC:
			err = det_open_nic_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_QUERY_NIC:
			err = det_query_nic_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_CLOSE_NIC:
			err = det_close_nic_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_ALLOC_PD:
			err = det_alloc_pd_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_DEALLOC_PD:
			err = det_dealloc_pd_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_CREATE_CQ:
			err = det_create_cq_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_QUERY_CQ:
			err = det_query_cq_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_RESIZE_CQ:
			err = det_resize_cq_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_ARM_CQ:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_POLL_CQ:
			err = det_poll_cq_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_DESTROY_CQ:
			err = det_destroy_cq_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_CREATE_QP:
			err = det_create_qp_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_QUERY_QP:
			err = det_query_qp_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_MODIFY_QP:
			err = det_modify_qp_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_DESTROY_QP:
			err = det_destroy_qp_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_REG_MR:
			err = det_reg_mr_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_QUERY_MR:
			err = det_query_mr_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_MODIFY_MR:
			err = det_modify_mr_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_REG_SHARED:
			err = det_reg_shared_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_DEREG_MR:
			err = det_dereg_mr_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_CREATE_MW:
			err = det_create_mw_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_QUERY_MW:
			err = det_query_mw_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_DESTROY_MW:
			err = det_destroy_mw_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_SEND:
			err = det_send_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_RECV:
			err = det_recv_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_READ:
			err = det_read_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_WRITE:
			err = det_write_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_BIND:
			err = det_bind_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_COMP_EXCH:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_FETCH_ADD:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_CREATE_CO:
			err = det_create_co_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_JOIN:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_DESTROY_CO:
			err = det_destroy_co_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_BARRIER:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_BCAST:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_SCATTER:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_SCATTERV:
			err = det_scatterv_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_GATHER:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_GATHERV:
			err = det_gatherv_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_ALLGATHER:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_ALLGATHERV:
			err = det_allgatherv_ioctl32(fd, cmd, arg, filp);
			break;

		case DET_IOC_ALLTOALL:	/* 32-bit compatible */
			err = sys_ioctl(fd, cmd, arg);
			break;

		case DET_IOC_ALLTOALLV:
			err = det_alltoallv_ioctl32(fd, cmd, arg, filp);
			break;

		default:
			err = -ENOIOCTLCMD;
			break;
	}

	return err;
}

#ifndef	HAVE_COMPAT_IOCTL

/*
 * 32/64-bit ioctl conversion routine registration.
 */

static struct det_ioctl32 {
	unsigned int			cmd;
	ioctl_trans_handler_t		handler;
	int				registered;
} det_ioctl32_map[] = {
	{ DET_IOC_QUERY,		det_query_ioctl32,		0 },

	{ DET_IOC32_CREATE_EVENT,	det_create_event_ioctl32,	0 },
	{ DET_IOC32_WAIT_ON_EVENT,	det_wait_on_event_ioctl32,	0 },
	{ DET_IOC32_GENERATE_EVENT,	det_generate_event_ioctl32,	0 },
	{ DET_IOC32_DESTROY_EVENT,	det_destroy_event_ioctl32,	0 },

	{ DET_IOC32_OPEN_NIC,		det_open_nic_ioctl32,		0 },
	{ DET_IOC32_QUERY_NIC,		det_query_nic_ioctl32,		0 },
	{ DET_IOC32_CLOSE_NIC,		det_close_nic_ioctl32,		0 },

	{ DET_IOC32_ALLOC_PD,		det_alloc_pd_ioctl32,		0 },
	{ DET_IOC32_DEALLOC_PD,		det_dealloc_pd_ioctl32,		0 },

	{ DET_IOC32_CREATE_CQ,		det_create_cq_ioctl32,		0 },
	{ DET_IOC32_QUERY_CQ,		det_query_cq_ioctl32,		0 },
	{ DET_IOC32_RESIZE_CQ,		det_resize_cq_ioctl32,		0 },
	{ DET_IOC_ARM_CQ,		NULL, /* 32-bit compatible */	0 },
	{ DET_IOC32_POLL_CQ,		det_poll_cq_ioctl32,		0 },
	{ DET_IOC32_DESTROY_CQ,		det_destroy_cq_ioctl32,		0 },

	{ DET_IOC32_CREATE_QP,		det_create_qp_ioctl32,		0 },
	{ DET_IOC32_QUERY_QP,		det_query_qp_ioctl32,		0 },
	{ DET_IOC32_MODIFY_QP,		det_modify_qp_ioctl32,		0 },
	{ DET_IOC32_DESTROY_QP,		det_destroy_qp_ioctl32,		0 },

	{ DET_IOC32_REG_MR,		det_reg_mr_ioctl32,		0 },
	{ DET_IOC32_QUERY_MR,		det_query_mr_ioctl32,		0 },
	{ DET_IOC32_MODIFY_MR,		det_modify_mr_ioctl32,		0 },
	{ DET_IOC32_REG_SHARED,		det_reg_shared_ioctl32,		0 },
	{ DET_IOC32_DEREG_MR,		det_dereg_mr_ioctl32,		0 },

	{ DET_IOC32_CREATE_MW,		det_create_mw_ioctl32,		0 },
	{ DET_IOC32_QUERY_MW,		det_query_mw_ioctl32,		0 },
	{ DET_IOC32_DESTROY_MW,		det_destroy_mw_ioctl32,		0 },

	{ DET_IOC32_SEND,		det_send_ioctl32,		0 },
	{ DET_IOC32_RECV,		det_recv_ioctl32,		0 },
	{ DET_IOC32_READ,		det_read_ioctl32,		0 },
	{ DET_IOC32_WRITE,		det_write_ioctl32,		0 },
	{ DET_IOC32_BIND,		det_bind_ioctl32,		0 },
	{ DET_IOC_COMP_EXCH,		NULL, /* 32-bit compatible */	0 },
	{ DET_IOC_FETCH_ADD,		NULL, /* 32-bit compatible */	0 },

	{ DET_IOC32_CREATE_CO,		det_create_co_ioctl32,		0 },
	{ DET_IOC_JOIN,			NULL, /* 32-bit compatible */	0 },
	{ DET_IOC32_DESTROY_CO,		det_destroy_co_ioctl32,		0 },
	{ DET_IOC_BARRIER,		NULL, /* 32-bit compatible */	0 },
	{ DET_IOC_BCAST,		NULL, /* 32-bit compatible */	0 },
	{ DET_IOC_SCATTER,		NULL, /* 32-bit compatible */	0 },
	{ DET_IOC32_SCATTERV,		det_scatterv_ioctl32,		0 },
	{ DET_IOC_GATHER,		NULL, /* 32-bit compatible */	0 },
	{ DET_IOC32_GATHERV,		det_gatherv_ioctl32,		0 },
	{ DET_IOC_ALLGATHER,		NULL, /* 32-bit compatible */	0 },
	{ DET_IOC32_ALLGATHERV,		det_allgatherv_ioctl32,		0 },
	{ DET_IOC_ALLTOALL,		NULL, /* 32-bit compatible */	0 },
	{ DET_IOC32_ALLTOALLV,		det_alltoallv_ioctl32,		0 }
};

#define DET_IOCTL32_ENTRIES						\
		(sizeof(det_ioctl32_map) / sizeof(det_ioctl32_map[0]))


#endif	/* HAVE_COMPAT_IOCTL */

#endif	/* CONFIG_COMPAT */


void det_register_ioctl32(void)
{
#if	defined(CONFIG_COMPAT) && !defined(HAVE_COMPAT_IOCTL)
	int i, err;

	for (i = 0; i < DET_IOCTL32_ENTRIES; i++) {
		err = register_ioctl32_conversion(det_ioctl32_map[i].cmd,
						  det_ioctl32_map[i].handler);
		if (unlikely(err)) {
			printk(KERN_WARNING
			"Failed to register 32-bit compatible ioctl 0x%x\n",
				det_ioctl32_map[i].cmd);
			det_ioctl32_map[i].registered = 0;
		} else
			det_ioctl32_map[i].registered = 1;
	}
#endif
}


void det_unregister_ioctl32(void)
{
#if	defined(CONFIG_COMPAT) && !defined(HAVE_COMPAT_IOCTL)
	int i, err;

	for (i = 0; i < DET_IOCTL32_ENTRIES; i++) {
		if (!det_ioctl32_map[i].registered)
			continue;

		err = unregister_ioctl32_conversion(det_ioctl32_map[i].cmd);
		if (unlikely(err)) {
			printk(KERN_WARNING
			"Failed to unregister 32-bit compatible ioctl 0x%x\n",
				det_ioctl32_map[i].cmd);
		} else
			det_ioctl32_map[i].registered = 0;
	}
#endif
}
