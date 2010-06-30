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

#define DET_MODULE_NAME		"Intel(R) Direct Ethernet Transport"
#define DET_MODULE_ALIAS	"det"
#define DET_MODULE_VERSION	"1.1" " - " __DATE__ " " __TIME__
#define DET_MODULE_COPYRIGHT	"Copyright (c) 2004-2008 Intel Corporation"

MODULE_AUTHOR("Intel Corporation");
MODULE_LICENSE("GPL");

MODULE_DESCRIPTION(DET_MODULE_NAME);
MODULE_ALIAS(DET_MODULE_ALIAS);
MODULE_VERSION(DET_MODULE_VERSION);


int det_max_pages;
atomic_t det_page_count = ATOMIC_INIT(0);
static int det_max_memory = DEFAULT_MAX_MEMORY;
module_param(det_max_memory, int, 0664);
MODULE_PARM_DESC(det_max_memory,		\
	" Maximum percent of physical memory that may be pinned");

int det_memops_method = MEMOPS_USE_STDLIB + 1;
#ifdef memops_broken
module_param(det_memops_method, int, 0664);
MODULE_PARM_DESC(det_memops_method,		\
	" Memory operations method: 0=auto, 1=regs, 2=mmx, 3=sse2, 4=memcpy");
#endif

int det_timer_period = DEFAULT_DET_TIMER_PERIOD;
module_param(det_timer_period, int, 0664);
MODULE_PARM_DESC(det_timer_period,		\
	" Protocol retry timer interval in milliseconds");

int det_thread_affinity = DEFAULT_DET_THREAD_AFFINITY;
module_param(det_thread_affinity, int, 0664);
MODULE_PARM_DESC(det_thread_affinity,		\
	" Processor affinity relationship for det_thread");

int det_timer_ack = 0;
module_param(det_timer_ack, int, 0664);
MODULE_PARM_DESC(det_timer_ack,			\
	" Perform timer based acknowledgement of unacknowledged packets");

int det_ack_timeout = DEFAULT_DET_ACK_TIMEOUT;
module_param(det_ack_timeout, int, 0664);
MODULE_PARM_DESC(det_ack_timeout,		\
	" Maximum time to wait for a protocol acknowledgement in seconds");

int det_max_retries;	/* Calculated from det_timer_period & det_ack_timeout */

int det_window_size = DEFAULT_DET_WINDOW_SIZE;
module_param(det_window_size, int, 0664);
MODULE_PARM_DESC(det_window_size,		\
	" Maximum number of outstanding unacknowledged packets");

int det_do_atomic_copy = 1;
module_param(det_do_atomic_copy, int, 0664);
MODULE_PARM_DESC(det_do_atomic_copy,		\
	" Perform atomic copy of first four integers of a buffer");

int det_bcast_short_msg = DEFAULT_BCAST_SHORT_MSG;
module_param(det_bcast_short_msg, int, 0664);
MODULE_PARM_DESC(det_bcast_short_msg,		\
	" Bcast message size cutoff for binomial tree method");

int det_bcast_long_msg = DEFAULT_BCAST_LONG_MSG;
module_param(det_bcast_long_msg, int, 0664);
MODULE_PARM_DESC(det_bcast_long_msg,		\
	" Bcast message size cutoff for doubling method on powers of 2");

int det_bcast_min_procs = DEFAULT_BCAST_MIN_PROCS;
module_param(det_bcast_min_procs, int, 0664);
MODULE_PARM_DESC(det_bcast_min_procs,		\
	" Bcast message size cutoff for scatter/allgather method on powers of 2");

int det_allgather_short_msg = DEFAULT_ALLGATHER_SHORT_MSG;
module_param(det_allgather_short_msg, int, 0664);
MODULE_PARM_DESC(det_det_allgather_short_msg,		\
	" Allgather message size cutoff for dissemination method on non-powers of 2");

int det_allgather_long_msg = DEFAULT_ALLGATHER_LONG_MSG;
module_param(det_allgather_long_msg, int, 0664);
MODULE_PARM_DESC(det_allgather_long_msg,		\
	" Allgather message size cutoff for doubling method on powers of 2");

int det_alltoall_min_procs = DEFAULT_ALLTOALL_MIN_PROCS;
module_param(det_alltoall_min_procs, int, 0664);
MODULE_PARM_DESC(det_alltoall_min_procs,		\
	" Alltoall minimum process cutoff for indexing method with short messages");

int det_alltoall_short_msg = DEFAULT_ALLTOALL_SHORT_MSG;
module_param(det_alltoall_short_msg, int, 0664);
MODULE_PARM_DESC(det_alltoall_short_msg,		\
	" Allgather message size cutoff for indexing method with >= minimum processes");

int det_alltoall_medium_msg = DEFAULT_ALLTOALL_MEDIUM_MSG;
module_param(det_alltoall_medium_msg, int, 0664);
MODULE_PARM_DESC(det_alltoall_medium_msg,		\
	" Allgather message size cutoff for send/receive method");

int det_tm_stamp_wc = 0;
module_param(det_tm_stamp_wc, int, 0664);
MODULE_PARM_DESC(det_tm_stamp_wc,		\
	" Work completion latency timing hook not for normal operation");

int det_sched_type = DET_SCHED_BLOCKING;
module_param(det_sched_type, int, 0664);
MODULE_PARM_DESC(det_sched_type,		\
	" Queue Pair scheduling policy: 0=non-blocking, 1=blocking");

#ifdef CONFIG_DET_SEQUESTER
int det_idle_timeout = DEFAULT_DET_IDLE_TIMEOUT;
module_param(det_idle_timeout, int, 0664);
MODULE_PARM_DESC(det_idle_timeout,		\
	" Idle timeout for sequestered CPU");
#endif

#ifdef CONFIG_DET_DEBUG
int det_cur_drop_count = 0;
int det_drop_count = 0;
module_param(det_drop_count, int, 0664);
MODULE_PARM_DESC(det_drop_count,		\
	" Receive packet drop count interval (for protocol debug)");

unsigned long _trace_heartbeat;
#endif


int det_create_procfs(char * const);
void det_delete_procfs(char * const);
static int det_open(struct inode *, struct file *);
static int det_close(struct inode *, struct file *);
ssize_t det_verb(struct file *, const char __user *, size_t, loff_t *);
int det_ioctl(struct inode *, struct file *, unsigned int, unsigned long);
#ifdef	HAVE_UNLOCKED_IOCTL
long det_unlocked_ioctl(struct file *, unsigned int, unsigned long);
#endif
void det_cleanup_events(struct det_device * const);
void det_cleanup_nics(struct det_device * const);
void det_cleanup_pds(struct det_device * const);
void det_cleanup_cqs(struct det_device * const);
void det_cleanup_qps(struct det_device * const);
void det_cleanup_mrs(struct det_device * const);
void det_cleanup_mws(struct det_device * const);
void det_cleanup_cos(struct det_device * const);
int det_notifier(struct notifier_block *, unsigned long, void *);

static struct file_operations det_fops = {
	owner:		THIS_MODULE,
	open:		det_open,
	release:	det_close,
	write:		det_verb,
	ioctl:		det_ioctl,
#ifdef	HAVE_UNLOCKED_IOCTL
	unlocked_ioctl:	det_unlocked_ioctl,
#endif
#if	defined(CONFIG_COMPAT) && defined(HAVE_COMPAT_IOCTL)
	compat_ioctl:	det_compat_ioctl,
#endif
};

#ifndef	CONFIG_DET_LOOPBACK
static struct packet_type det_packet_type = {
	.type		= __constant_htons(DET_PACKET_TYPE),
	.func		= det_recv_pkt,
};
#endif

static struct notifier_block det_notifier_block = {
	.notifier_call	= det_notifier,
};

rwlock_t detdev_list_lock = RW_LOCK_UNLOCKED;
LIST_HEAD(detdev_list);

static int det_major = 0; /* Set to 0 for dynamic major allocation. */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
struct kmem_cache *det_eqe_cache;
#else
kmem_cache_t *det_eqe_cache;
#endif

DEFINE_IDR(det_wire_map);
rwlock_t det_wire_map_lock = RW_LOCK_UNLOCKED;
static u32 reserved_key = 0;

det_spinlock_t scheduler_list_lock = DET_SPIN_LOCK_UNLOCKED;
LIST_HEAD(scheduler_list);

det_spinlock_t collective_grp_list_lock = DET_SPIN_LOCK_UNLOCKED;
LIST_HEAD(collective_grp_list);

#ifdef CONFIG_DET_SEQUESTER
det_spinlock_t det_recv_queue_lock = DET_SPIN_LOCK_UNLOCKED;
struct sk_buff_head det_recv_queue;
#endif

#ifdef DET_USER_LOCK
det_spinlock_t	__det_user_lock__ = DET_SPIN_LOCK_UNLOCKED;
#endif


static int det_init_wiremap(int gfp_mask)
{
	int err;

	/*
	 * Instead of treating them as opaque, some applications
	 * assert that returned key values are non-zero.  As a
	 * work-around, reserve the first key from the wiremap.
	 */
	do {
		if (unlikely(!det_idr_pre_get(&det_wire_map, gfp_mask)))
			return -ENOMEM;
		write_lock(&det_wire_map_lock);
		err = det_get_id(&det_wire_map, &reserved_key, &reserved_key);
		write_unlock(&det_wire_map_lock);
	} while (unlikely(err == -EAGAIN));

	return err;
}


static void det_idr_free(struct idr * const idp,
			 rwlock_t * const lock)
{
	int id, cnt, err;

	write_lock(lock);

	/* Remove the reserved key from the wiremap. */
	if (idp == &det_wire_map)
		idr_remove(idp, reserved_key);

	/* Now clean up any leftover idr cache entries. */
	while (idp->id_free_cnt) {

		/* Get without calling idr_pre_get to consume a cache entry. */
		err = det_get_id(idp, idp, &id);
		if (err)
			break;

		/* Set id_free_cnt to force an idr_remove kmem_cache_free. */
		cnt = idp->id_free_cnt;
		idp->id_free_cnt = IDR_FREE_MAX;
		idr_remove(idp, id);
		idp->id_free_cnt = cnt;
	}

	write_unlock(lock);
}


#ifndef	CONFIG_DET_LOOPBACK

static void det_schedule_timeout(void)
{
	struct det_scheduler *scheduler;
	PERF_DECL(start)

	det_user_lock();

	/* Walk the scheduler list. */
	PERF_GET_HRC(start);
	sched_list_lock();
	list_for_each_entry(scheduler, &scheduler_list, entry)
		det_schedule(DET_SCHEDULE_TIMEOUT, scheduler);
	sched_list_unlock();
	PERF_RECORD(TIMER_THREAD, start);

	det_user_unlock();
}

struct task_struct *det_task;

#ifdef CONFIG_DET_SEQUESTER

static unsigned long det_timeout = 0;


static inline void det_check_timeout(void)
{
	if (time_after(jiffies, det_timeout)) {
		det_schedule_timeout();
		det_timeout = jiffies + msecs_to_jiffies(det_timer_period);
	}
}

#ifdef CONFIG_DET_DOORBELL

#define det_doorbell_offset2ptr(doorbell, offset) \
	(doorbell)->offset ? \
 		(void*)((unsigned long)((doorbell)->offset) + (char*)(doorbell)) : NULL

static void det_answer_doorbell(struct det_qp *qp)
{
	struct det_doorbell *doorbell = qp->doorbell;
	int err;

	switch (doorbell->ioctl_cmd) {

	case DET_IOC_SEND:
		err = det_send(qp, doorbell->send.wr_id,
			doorbell->send.local_ds, doorbell->send.num_ds,
			doorbell->send.flags, doorbell->send.immediate_data);
		break;

	case DET_IOC_RECV:
		err = det_recv(qp, doorbell->recv.wr_id,
			doorbell->recv.local_ds, doorbell->recv.num_ds);
		break;

	case DET_IOC_READ:
		err = det_read(qp, doorbell->read.wr_id,
			doorbell->read.local_ds, doorbell->read.num_ds,
			doorbell->read.remote_address,
			doorbell->read.remote_key, doorbell->read.flags);
		break;

	case DET_IOC_WRITE:
		err = det_write(qp, doorbell->write.wr_id,
			doorbell->write.local_ds, doorbell->write.num_ds,
			doorbell->write.remote_address,
			doorbell->write.remote_key, doorbell->write.flags,
			doorbell->write.immediate_data);
		break;

	case DET_IOC_COMP_EXCH:
		err = det_comp_exch(qp, doorbell->comp_exch.wr_id,
			doorbell->comp_exch.comp_operand,
			doorbell->comp_exch.exch_operand,
			&doorbell->comp_exch.local_ds,
			doorbell->comp_exch.remote_address,
			doorbell->comp_exch.remote_key,
			doorbell->comp_exch.flags);
		break;

	case DET_IOC_FETCH_ADD:
		err = det_fetch_add(qp, doorbell->fetch_add.wr_id,
			doorbell->fetch_add.add_operand,
			&doorbell->fetch_add.local_ds,
			doorbell->fetch_add.remote_address,
			doorbell->fetch_add.remote_key,
			doorbell->fetch_add.flags);
		break;

	case DET_IOC_JOIN:
		err = det_join((struct det_co *)qp, doorbell->join.wr_id,
			doorbell->join.tag,
			doorbell->join.size,
			doorbell->join.rank,
			doorbell->join.flags);
		break;

	case DET_IOC_BARRIER:
		err = det_barrier((struct det_co *)qp,
			doorbell->barrier.wr_id,
			doorbell->barrier.flags);
		break;

	case DET_IOC_BCAST:
		err = det_bcast((struct det_co *)qp,
			doorbell->bcast.wr_id,
			doorbell->bcast.root,
			&doorbell->bcast.ds,
			doorbell->bcast.flags);
		break;

	case DET_IOC_SCATTER:
		err = det_scatter((struct det_co *)qp,
			doorbell->scatter.wr_id,
			doorbell->scatter.root,
			get_ioc_ds(doorbell->scatter.src_ds),
			get_ioc_ds(doorbell->scatter.dst_ds),
			doorbell->scatter.flags);
		break;

	case DET_IOC_SCATTERV:
		err = det_scatterv((struct det_co *)qp,
			doorbell->scatterv.wr_id,
			doorbell->scatterv.root,
			det_doorbell_offset2ptr(doorbell, scatterv.src_ds_array),
			get_ioc_ds(doorbell->scatterv.dst_ds),
			doorbell->scatterv.flags);
		break;

	case DET_IOC_GATHER:
		err = det_gather((struct det_co *)qp,
			doorbell->gather.wr_id,
			doorbell->gather.root,
			get_ioc_ds(doorbell->gather.src_ds),
			get_ioc_ds(doorbell->gather.dst_ds),
			doorbell->gather.flags);
		break;

	case DET_IOC_GATHERV:
		err = det_gatherv((struct det_co *)qp,
			doorbell->gatherv.wr_id,
			doorbell->gatherv.root,
			get_ioc_ds(doorbell->gatherv.src_ds),
			det_doorbell_offset2ptr(doorbell, gatherv.dst_ds_array),
			doorbell->gatherv.flags);
		break;

	case DET_IOC_ALLGATHER:
		err = det_allgather((struct det_co *)qp,
			doorbell->allgather.wr_id,
			get_ioc_ds(doorbell->allgather.src_ds),
			&doorbell->allgather.dst_ds,
			doorbell->allgather.flags);
		break;

	case DET_IOC_ALLGATHERV:
		err = det_allgatherv((struct det_co *)qp,
			doorbell->allgatherv.wr_id,
			get_ioc_ds(doorbell->allgatherv.src_ds),
			det_doorbell_offset2ptr(doorbell, allgatherv.dst_ds_array),
			doorbell->allgatherv.flags);
		break;

	case DET_IOC_ALLTOALL:
		err = det_alltoall((struct det_co *)qp,
			doorbell->alltoall.wr_id,
			&doorbell->alltoall.src_ds,
			&doorbell->alltoall.dst_ds,
			doorbell->alltoall.flags);
		break;

	case DET_IOC_ALLTOALLV:
		err = det_alltoallv((struct det_co *)qp,
			doorbell->alltoallv.wr_id,
			det_doorbell_offset2ptr(doorbell, alltoallv.src_ds_array),
			det_doorbell_offset2ptr(doorbell, alltoallv.dst_ds_array),
			doorbell->alltoallv.flags);
		break;

	default:
		err = -EINVAL;
		printk(KERN_ERR "det_answer_doorbell: Unknown command %d\n",
			doorbell->ioctl_cmd);
		break;
	}

	doorbell->ring = err;
}

static void det_poll_doorbell(struct det_scheduler *scheduler)
{
	struct det_qp *qp;

	sched_obj_lock(&scheduler->lock);
	list_for_each_entry(qp, &scheduler->qp_list, scheduler_entry) {
		if (qp->doorbell && qp->doorbell->ring)
			det_answer_doorbell(qp);
	}
	sched_obj_unlock(&scheduler->lock);
}

#else

static void det_poll_doorbell(struct det_scheduler *scheduler)
{
}

#endif /* CONFIG_DET_DOORBELL */

static int det_poll_io(void)
{
	struct det_scheduler *scheduler;
	struct sk_buff *skb;
	int serviced = 0;

	det_user_lock();

	/* Walk the scheduler list. */
	sched_list_lock();
	list_for_each_entry(scheduler, &scheduler_list, entry) {
		det_poll_doorbell(scheduler);
		DET_NIC_POLL(scheduler->netdev);
		serviced++;
	}
	sched_list_unlock();

	// TBD: Should there be a limit to this loop?
	recv_queue_lock();
	while ((skb = skb_dequeue(&det_recv_queue))) {
		recv_queue_unlock();
		det_process_pkt(skb, skb->dev);
		recv_queue_lock();
	}
	recv_queue_unlock();

	det_user_unlock();

	return serviced;
}

static int det_poll(void *data)
{
//	set_user_nice(current, 19);
//	current->flags |= PF_NOFREEZE;

	while (likely(!kthread_should_stop())) {

		CODE_TRACE();

		if (det_poll_io()) {
			det_check_timeout();
			schedule();
		} else {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule_timeout(det_idle_timeout);
			__set_current_state(TASK_RUNNING);
		}
	}

	/* Flush the receive skb queue. */
	recv_queue_lock();
	skb_queue_purge(&det_recv_queue);
	recv_queue_unlock();

	return 0;
}
#endif

static int det_timer(void *data)
{
	signed long sleep, snooze;

	snooze = sleep = msecs_to_jiffies(det_timer_period);

	while (likely(!kthread_should_stop())) {

		/* Go to sleep. */
		set_current_state(TASK_INTERRUPTIBLE);
		snooze = schedule_timeout(snooze);
		if (unlikely(snooze))
			continue;

		det_schedule_timeout();

		snooze = sleep;
	}
	return 0;
}
#endif	/* CONFIG_DET_LOOPBACK */


static int __init det_init(void)
{
	int (*det_thread)(void *);
	int ret;

	/* Set the maximum page limit. */
	if (!det_max_memory)
		det_max_memory = DEFAULT_MAX_MEMORY;
	else if (det_max_memory > ONE_HUNDRED_PERCENT)
		det_max_memory = ONE_HUNDRED_PERCENT;
	det_max_pages =
		det_max_memory * (totalram_pages / ONE_HUNDRED_PERCENT);

	/* Override bogus user settings for other module parameters. */
	memops_method = (!det_memops_method) ?
		MEMOPS_UNINITIALIZED : det_memops_method - 1;
	det_init_memops();
	if (!det_timer_period)
		det_timer_period = DEFAULT_DET_TIMER_PERIOD;
	if (!det_ack_timeout)
		det_ack_timeout = DEFAULT_DET_ACK_TIMEOUT;
	else if (det_ack_timeout < DET_MIN_ACK_TIMEOUT)
		det_ack_timeout = DET_MIN_ACK_TIMEOUT;
	if (!det_window_size)
		det_window_size = DEFAULT_DET_WINDOW_SIZE;
	else if (det_window_size < DET_MIN_WINDOW_SIZE)
		det_window_size = DET_MIN_WINDOW_SIZE;

	/* Calculate the det_max_retries value. */
	det_max_retries = (det_ack_timeout * MSEC_PER_SEC) / det_timer_period;

	ret = register_chrdev(det_major, DET_MODULE_ALIAS, &det_fops);
	if (unlikely(ret < 0))
		return -ENODEV;
	if (likely(det_major == 0))
		det_major = ret; /* Dynamic allocation */

	ret = det_create_procfs(DET_MODULE_ALIAS);
	if (unlikely(ret))
		goto out;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
	det_eqe_cache = kmem_cache_create("det_eqe_cache",
		sizeof(struct det_eqe), 0, SLAB_HWCACHE_ALIGN, 0);
#else
	det_eqe_cache = kmem_cache_create("det_eqe_cache",
		sizeof(struct det_eqe), 0, SLAB_HWCACHE_ALIGN, 0, 0);
#endif
	if (unlikely(!det_eqe_cache))
		goto out1;

	ret = det_init_wiremap(GFP_KERNEL);
	if (unlikely(ret))
		goto out3;

	ret = register_netdevice_notifier(&det_notifier_block);
	if (unlikely(ret))
		goto out4;

#ifndef	CONFIG_DET_LOOPBACK
#ifdef	CONFIG_DET_SEQUESTER
	skb_queue_head_init(&det_recv_queue);

	det_thread = (num_online_cpus() > 1) ? det_poll : det_timer;
	det_timeout = jiffies;
#else
	det_thread = det_timer;
#endif
	if (det_thread_affinity == -1) {
		/* let the timer processor affinity float */
		det_task = kthread_run(det_thread, NULL, "det_thread");
		if (det_task == NULL) {
			ret = -EIO;
			goto out5;
		}
	} else {

		preempt_disable();
		if ((det_thread_affinity < 0) ||
		    (det_thread_affinity >= NR_CPUS) ||
		     !cpu_online(det_thread_affinity))
			det_thread_affinity = smp_processor_id();
		preempt_enable();

		/* assign processor affinity */
		det_task = kthread_create(det_thread, NULL,
					"det_thread/%d", det_thread_affinity);
		if (det_task == NULL) {
			ret = -EIO;
			goto out4;
		}
		kthread_bind(det_task, det_thread_affinity);

		wake_up_process(det_task);
	}

	/* Register a handler for inbound DET packets. */
	dev_add_pack(&det_packet_type);
#endif

	/* Display a sign on message. */
	printk(KERN_INFO "\n");
	printk(KERN_INFO "%s (%s) V%s\n",
		DET_MODULE_NAME, DET_MODULE_ALIAS, DET_MODULE_VERSION);
	printk(KERN_INFO "%s\n", DET_MODULE_COPYRIGHT);
#ifdef	CONFIG_DET_LOOPBACK
	printk(KERN_INFO "---> Loopback Configuration <---\n");
#endif
	printk(KERN_INFO "Physical page limit: %d of %lu pages [%d%%]\n",  
		det_max_pages, totalram_pages, det_max_memory);
#if !defined(CONFIG_DET_LOOPBACK) && defined(CONFIG_DET_SEQUESTER)
	if (num_online_cpus() > 1) {
		if (det_thread_affinity == -1)
			printk(KERN_INFO "Sequestered Core: Floating thread");
		else
			printk(KERN_INFO "Sequestered Core: CPU %d",
				det_thread_affinity);
#ifdef CONFIG_DET_DOORBELL
		printk(": Doorbell interface\n");
#else
		printk("\n");
#endif
	}
#endif
	printk(KERN_INFO "Memops method:    %d (%s)\n",
		memops_method + 1, det_memops_method_str(memops_method));
	printk(KERN_INFO "Timer period:     %d msec\n", det_timer_period);
	printk(KERN_INFO "ACK timeout:      %d sec\n", det_ack_timeout);
	printk(KERN_INFO "Window size:      %d\n", det_window_size);

	det_register_ioctl32();

	det_reset_statistics(&det_statistics);

	return 0;

#ifndef	CONFIG_DET_LOOPBACK
out5:
	unregister_netdevice_notifier(&det_notifier_block);
#endif
out4:
	det_idr_free(&det_wire_map, &det_wire_map_lock);
out3:
	kmem_cache_destroy(det_eqe_cache);
out1:
	det_delete_procfs(DET_MODULE_ALIAS);
out:
	unregister_chrdev(det_major, DET_MODULE_ALIAS);

	return ret;
}


static void __exit det_exit(void)
{
	struct det_scheduler *scheduler, *next;
	int err;

	det_unregister_ioctl32();

#ifndef	CONFIG_DET_LOOPBACK
	/* Deregister the inbound DET packet handler. */
	dev_remove_pack(&det_packet_type);

	kthread_stop(det_task);
#endif

	err = unregister_netdevice_notifier(&det_notifier_block);
	if (unlikely(err))
		printk(KERN_ERR
			"unregister_netdevice_notifier error %d.\n", err);

	kmem_cache_destroy(det_eqe_cache);

	/*
	 * Clean up the scheduler list.   Lock since we are paranoid.
	 * No need to dereference any of the netdev devices in the
	 * scheduler list structures since all opened DET NIC devices
	 * have been closed.
	 */
	sched_list_lock();
	list_for_each_entry_safe(scheduler, next, &scheduler_list, entry) {
		assert(list_empty(&scheduler->qp_list));
		kfree(scheduler);
	}
	sched_list_unlock();

	det_delete_procfs(DET_MODULE_ALIAS);

	unregister_chrdev(det_major, DET_MODULE_ALIAS);

	det_idr_free(&det_wire_map, &det_wire_map_lock);

	WARN_ON(!list_empty(&collective_grp_list));

	printk(KERN_INFO "%s (%s) Exit\n",
		DET_MODULE_NAME, DET_MODULE_ALIAS);
	printk(KERN_INFO "\n");
}


static int det_open(struct inode *inode,
		    struct file *filp)
{
	struct det_device *detdev;

	detdev = kmalloc(sizeof(*detdev), GFP_KERNEL);
	if (unlikely(!detdev))
		return -ENOMEM;

	memset(detdev, 0, sizeof(*detdev));
	rwlock_init(&detdev->map_lock);
	idr_init(&detdev->map);
	rwlock_init(&detdev->lock);
	INIT_LIST_HEAD(&detdev->event_list);
	INIT_LIST_HEAD(&detdev->nic_list);
	INIT_LIST_HEAD(&detdev->pd_list);
	INIT_LIST_HEAD(&detdev->cq_list);
	INIT_LIST_HEAD(&detdev->qp_list);
	INIT_LIST_HEAD(&detdev->mr_list);
	INIT_LIST_HEAD(&detdev->mw_list);
	INIT_LIST_HEAD(&detdev->co_list);

	det_user_lock();
	write_lock(&detdev_list_lock);
	list_add_tail(&detdev->entry, &detdev_list);
	write_unlock(&detdev_list_lock);
	det_user_unlock();

	filp->private_data = detdev;
	try_module_get(THIS_MODULE);

	return 0;
}


static int det_close(struct inode *inode,
		     struct file *filp)
{
	struct det_device *detdev = filp->private_data;

	det_user_lock();

	/*
	 * Clean up any resources that may have been left by the user.
	 * Order of clean up is important due to reference counting.
	 */
	det_cleanup_cos(detdev);
	det_cleanup_qps(detdev);
	det_cleanup_cqs(detdev);
	det_cleanup_mws(detdev);
	det_cleanup_mrs(detdev);
	det_cleanup_pds(detdev);
	det_cleanup_nics(detdev);
	det_cleanup_events(detdev);

	write_lock(&detdev_list_lock);
	list_del(&detdev->entry);
	write_unlock(&detdev_list_lock);

	det_idr_free(&detdev->map, &detdev->map_lock);

	det_user_unlock();

	kfree(detdev);
	module_put(THIS_MODULE);

	return 0;
}


int det_query(struct det_device * const detdev,
	      struct det_attr * const attr)
{
	attr->timer_period = det_timer_period;
	attr->ack_timeout  = det_ack_timeout;
	attr->max_window   = det_window_size;
	attr->max_memory   = det_max_memory;
	attr->page_count   = atomic_read(&det_page_count);

	return 0;
}
EXPORT_SYMBOL(det_query);


/* Hold read_lock(&detdev_list_lock) during this call for synchronization. */
void det_nic_notifier(struct net_device * const netdev,
		      struct det_device * const detdev,
		      struct det_nic * const nic,
		      const unsigned long event)
{
	struct det_scheduler *scheduler;
	struct det_qp *qp;

	det_user_lock();

	switch (event) {
	case NETDEV_CHANGEMTU:
		/* This assumes read_lock(&detdev_list_lock) is held. */
		list_for_each_entry(qp, &detdev->qp_list, entry) {

			if (netdev != qp->netdev)
				continue;

			qp_lock_bh(&qp->lock);
			if (qp->attr.state != DET_QP_CONNECTED) {
				qp_unlock_bh(&qp->lock);
				continue;
			}

			read_lock(&dev_base_lock);
			if (netdev->mtu < qp->attr.mtu_size) {
				read_unlock(&dev_base_lock);
				det_qp_error(qp);
				qp_unlock_bh(&qp->lock);
				det_async_event(nic, DET_AE_QP_FATAL,
					DET_TYPE_QP, qp);
			} else {
				read_unlock(&dev_base_lock);
				qp_unlock_bh(&qp->lock);
			}
		}
		break;

	case NETDEV_UP:
	case NETDEV_DOWN:
	case NETDEV_UNREGISTER:
	case NETDEV_CHANGE:
		/* Walk the scheduler list. */
		sched_list_lock();
		list_for_each_entry(scheduler, &scheduler_list, entry) {
			if (scheduler->netdev != netdev)
				continue;
			if (netif_queue_stopped(netdev) || /* XOFF */
			    !netif_carrier_ok(netdev)   ||
			    !netif_device_present(netdev)) {
				atomic_set(&scheduler->stopped, 1);
				dprintk("Scheduler stopped for device %s (0x%lx)\n",
				    	netdev->name, netdev->state);
			} else {
				atomic_set(&scheduler->stopped, 0);
				dprintk("Scheduler started for device %s (0x%lx)\n",
				    	netdev->name, netdev->state);
			}
		}
		sched_list_unlock();

		if ((event == NETDEV_DOWN) ||
		    (event == NETDEV_UNREGISTER)) {
			/*
			 * Note that netdev_wait_allrefs() will broadcast
			 * this notification until all users close the NIC.
			 */
			det_async_event(nic, DET_AE_NIC_REMOVED,
				DET_TYPE_NIC, nic);
		}
		break;

	default:
		break;
	}

	det_user_unlock();
}

/* Hold read_lock(&detdev_list_lock) during this call for synchronization. */
void detdev_notifier(struct net_device * const netdev,
		     struct det_device * const detdev,
		     const unsigned long event)
{
	struct det_nic *nic;

	read_lock(&detdev->lock);
	list_for_each_entry(nic, &detdev->nic_list, entry) {
		if (netdev == nic->netdev)
			det_nic_notifier(netdev, detdev, nic, event);
	}
	read_unlock(&detdev->lock);
}


int det_notifier(struct notifier_block *nb,
		 unsigned long event,
		 void *ptr)
{
	struct net_device *netdev = (struct net_device *)ptr;
	struct det_device *detdev;

	if (netdev->type != ARPHRD_ETHER)
		return NOTIFY_DONE;

	read_lock(&detdev_list_lock);
	list_for_each_entry(detdev, &detdev_list, entry)
		detdev_notifier(netdev, detdev, event);
	read_unlock(&detdev_list_lock);

	return NOTIFY_DONE;
}

module_init(det_init);
module_exit(det_exit);
