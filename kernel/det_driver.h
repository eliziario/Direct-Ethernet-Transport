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

#ifndef __DET_DRIVER_H__
#define __DET_DRIVER_H__

#include <linux/version.h>	/* for kernel version	  */
#include <linux/kthread.h>	/* for kthread routines	  */
#include <linux/vmalloc.h>	/* for vmalloc, vfree	  */
#include <linux/pagemap.h>	/* for page_cache_release */
#include <linux/syscalls.h>	/* for sys_ioctl	  */
#include <linux/pkt_sched.h>	/* for TC_PRIO_CONTROL	  */
#include <linux/if_arp.h>	/* for ARPHRD_ETHER	  */
#include <linux/swap.h>		/* for totalram_pages	  */
#include <linux/file.h>		/* for files_struct       */
#include <linux/moduleparam.h>	/* for pre-2.6.9 kernels  */
#include <linux/personality.h>	/* for pre-2.6.9 kernels  */
#include <linux/etherdevice.h>	/* for eth_type_trans     */
#include <linux/delay.h>	/* for jiffies_per_loop	  */
#include <asm/io.h>		/* for page_to_phys       */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include <linux/fdtable.h>	/* for files_struct	  */
#endif

/* some compilers complain about uninitialized out parameters */
#define uninitialized_var(x) x = x

#define DET_TRIGGERED_WR
//#define DET_CO_TASKLET
#define DET_PERF
#define DET_STATS
#define DET_PROFILE_LOCKS

/* adjust dependencies before det specific includes */
#ifdef DET_PROFILE_LOCKS
#ifndef DET_PERF
#define DET_PERF  /* DET_PROFILE_LOCKS depends on DET_PERF */
#endif
#endif

#ifdef DET_PERF
#ifndef DET_STATS  /* DET_PERF depend on DET_STATS */
#define DET_STATS
#endif
#endif

#if defined(CONFIG_DET_SEQUESTER) && defined(CONFIG_DET_DOORBELL)
#define DET_USER_LOCK
#endif

#include "det_debug.h"
#include "det_ioctl.h"
#include "det_ioctl32.h"
#include "det_perf.h"
#include "det_memops.h"
#include "det.h"

#ifndef	__KERNEL__
#error Kernel mode header file included in user mode build
#endif


/*
 * Maximum local DS array size on the stack.
 */
#define	MAX_STACK_NUM_DS	8


/*
 * NIC attribute limits.
 * In most cases, the minimum values indicate the actual amount created.
 * E.g.,  MIN_CQ_SIZE is the number of work completion structures that
 * will fit in a page (because vmalloc is used when creating the CQ);
 * if a size of one is requested, this is the size returned.  Note that
 * minimum values are not checked by the code, they are provided as hints
 * to the client.  E.g., it is legal to create a CQ with a size of zero
 * and resize it later.  Only the maximum values are checked and enforced
 * as hard limits.  The definitions are intended to show the thinking
 * behind the values; e.g., MAX_PDS defined as MAX_QPS is intended to
 * allow each QP to be on a separate PD, although there is no requirement
 * that it be used that way.
 */
#define	MIN_PDS			1
#define	MAX_PDS			MAX_QPS		/* 1 per QP */
#define	MIN_MRS			1
#define	MAX_MRS			(MAX_QPS * 4)	/* x4:local/remote,read/write */
#define	MIN_MR_SIZE		1
#define	MAX_MR_SIZE		INT_MIN
#define	MIN_MWS			1
#define	MAX_MWS			(MAX_MRS * 2)	/* 2 MWs per MR */
#define	MIN_CQS			1
#define	MAX_CQS			(MAX_QPS * 2)	/* x2:send queue / recv queue */
#define	MIN_CQ_SIZE		(PAGE_SIZE / sizeof(struct det_wc))
#define	MAX_CQ_SIZE		(MAX_SQ_SIZE + MAX_RQ_SIZE)  /* or combined */ 
#define	MIN_QPS			1
#define	MAX_QPS			(64 * 1024)
#define	MIN_SQ_SIZE		1		/* min varies with num sges */
#define	MAX_SQ_SIZE		(64 * 1024)
#define	MIN_RQ_SIZE		MIN_SQ_SIZE	/* balance recvs with sends */
#define	MAX_RQ_SIZE		MAX_SQ_SIZE	/* balance recvs with sends */
#define	MIN_MSG_SIZE		0
#define	MAX_MSG_SIZE		INT_MIN
#define	MIN_RDMA_SIZE		0
#define	MAX_RDMA_SIZE		INT_MIN
#ifdef CONFIG_DET_DOORBELL
#define	MIN_SGES		MAX_SGES
#define	MAX_SGES		( (PAGE_SIZE - sizeof(struct det_doorbell)) \
					     / sizeof(struct det_local_ds) )
#else
#define	MIN_SGES		MAX_STACK_NUM_DS
#define	MAX_SGES		(PAGE_SIZE / sizeof(struct det_local_ds))
#endif
#define	MIN_OR			(MIN_SQ_SIZE / 2) /* SQ half outbound reqs */
#define	MAX_OR			(MAX_SQ_SIZE / 2) /* SQ half outbound reqs */
#define	MIN_IR			MIN_OR	/* balance inbound with outbound */
#define	MAX_IR			MAX_OR	/* balance inbound with outbound */
#define	MIN_COS			1
#define	MAX_COS			MAX_PDS		/* 1 per PD */


#ifndef	MSEC_PER_SEC
#define MSEC_PER_SEC			1000
#endif
#define ONE_HUNDRED_PERCENT		100
#define DEFAULT_MAX_MEMORY		50	/* percent of physical memory */
#define	MAX_KERNEL_PAGES	((unsigned long)((-PAGE_OFFSET) >> PAGE_SHIFT))
#define	NUM_KERNEL_PAGES	(min(totalram_pages, MAX_KERNEL_PAGES))
#define DEFAULT_DET_THREAD_AFFINITY	(-1)	/* float */
#define DEFAULT_DET_IDLE_TIMEOUT	20	/* in msecs */


#define PROCESS_FRAME		0
#define SEND_ACK		1
#define	DONT_PLACE		2
#define	DEFER_PLACEMENT		3


#define	DEFAULT_BCAST_SHORT_MSG		8192
#define	DEFAULT_BCAST_LONG_MSG		262144
#define	DEFAULT_BCAST_MIN_PROCS		8
#define	DEFAULT_ALLGATHER_SHORT_MSG	200000
#define	DEFAULT_ALLGATHER_LONG_MSG	0
#define	DEFAULT_ALLTOALL_MIN_PROCS	8
#define	DEFAULT_ALLTOALL_SHORT_MSG	0
#define	DEFAULT_ALLTOALL_MEDIUM_MSG	2087152

#define	BCAST_SHORT_MSG			det_bcast_short_msg
#define	BCAST_LONG_MSG			det_bcast_long_msg
#define	BCAST_MIN_PROCS			det_bcast_min_procs
#define	ALLGATHER_SHORT_MSG		det_allgather_short_msg
#define	ALLGATHER_LONG_MSG		det_allgather_long_msg
#define	ALLTOALL_MIN_PROCS		det_alltoall_min_procs
#define	ALLTOALL_SHORT_MSG		det_alltoall_short_msg
#define	ALLTOALL_MEDIUM_MSG		det_alltoall_medium_msg

extern int det_bcast_short_msg;
extern int det_bcast_long_msg;
extern int det_bcast_min_procs;
extern int det_allgather_short_msg;
extern int det_allgather_long_msg;
extern int det_alltoall_min_procs;
extern int det_alltoall_short_msg;
extern int det_alltoall_medium_msg;
extern int det_tm_stamp_wc;
extern int det_sched_type;

#define DET_SCHED_NONBLOCKING	0
#define DET_SCHED_BLOCKING	1

extern int det_max_pages;
extern atomic_t det_page_count;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
extern struct kmem_cache *det_eqe_cache;
#else
extern kmem_cache_t *det_eqe_cache;
#endif

extern struct idr det_wire_map;
extern rwlock_t det_wire_map_lock;

extern det_spinlock_t __det_user_lock__;

extern det_spinlock_t scheduler_list_lock;
extern struct list_head scheduler_list;

extern det_spinlock_t collective_grp_list_lock;
extern struct list_head collective_grp_list;

#ifdef CONFIG_DET_SEQUESTER
extern det_spinlock_t det_recv_queue_lock;
extern struct sk_buff_head det_recv_queue;

int det_process_pkt(struct sk_buff *skb,
		    struct net_device *netdev);

void _det_poll_enable(struct net_device *netdev);
void _det_poll_disable(struct net_device *netdev);
irqreturn_t _det_poll(struct net_device *netdev);

#define DET_NIC_POLL_ENABLE(dev)	\
do {					\
	det_user_unlock()		\
	_det_poll_enable(dev);	\
	det_user_lock()			\
} while(0)

#define DET_NIC_POLL_DISABLE(dev)	\
do {					\
	det_user_unlock()		\
	_det_poll_disable(dev);	\
	det_user_lock()			\
} while(0)

#define DET_NIC_POLL(dev)		\
do {					\
	local_bh_disable();		\
	_det_poll(dev);		\
	local_bh_enable();		\
} while(0)

#else

#define DET_NIC_POLL_ENABLE(dev)
#define DET_NIC_POLL_DISABLE(dev)
#define DET_NIC_POLL(dev)

#endif

extern int det_do_atomic_copy;

struct det_eqe {
	struct list_head	entry;
	struct det_ioc_event	event;
};


static inline struct list_head *list_remove_head(const struct list_head * const head)
{
	struct list_head *entry = head->next;
	list_del(entry);
	return entry;
}


#define list_remove_head_entry(head, type, member) \
	list_entry(list_remove_head(head), type, member)

/**********************************************
 *
 *   Stats/performance stuff
 *
 *********************************************/

/* these must be defined for all conditions */
enum det_timing {
#ifdef DET_USER_LOCK
	USER_LOCK,
#else
	WIRE_MAP_RD,
	WIRE_MAP_WR,
	SQ_LOCK,
	IQ_LOCK,
	WQ_LOCK,
	RQ_LOCK,
	QP_LOCK,
	CQ_LOCK,
	MR_LOCK,
	CO_LOCK,
	CO_GRP_LOCK,
	RECV_QUEUE_LOCK,
	EVENT_LOCK,
	GRP_LOCK,
	WIRE_STATE,
	SCHED_LIST_LOCK,
	SCHED_OBJ_LOCK,
#endif
	SCHED_DELAY,
	WR_SQ_XMIT,
	WR_SQ_CMPLT,
	WR_IQ_XMIT,
	WR_IQ_CMPLT,
	TX_FRAG,
	SKB_RECV,
	RECV_PATH,
	RECV_COPY,
	RX_COMP_RQ,
	RX_COMP_IQ,
	LOOPBACK_PATH,
	LOOPBACK_COPY,
	ATOMIC_COPY,
	PERF_SEND,
	PERF_READ,
	PERF_WRITE,
	PERF_POLL_HIT,
	PERF_POLL_MISS,
	TIMER_THREAD,
	PERF_ECHO,
	POST_SNDRCV,
	SNDRCV_COMPLT,
	SEND_BYTES,
	READ_BYTES,
	WRITE_BYTES,
	GP_0,
	GP_1,
	GP_2,
	GP_3,
	MAX_TIMINGS	/* Must be last */
};


#ifdef DET_STATS

extern struct det_stats det_statistics;
#define	DET_STAT(f)	det_statistics.f

/*
 *  We should be using a cycle_t for DET_CNTR but the kernel source erroneously
 *  defines a cycle_t as long long for x86_64 so we have to do it ourself.
 */
#if   BITS_PER_LONG == 32
#define	DET_CNTR	unsigned long long
#elif BITS_PER_LONG == 64
#define	DET_CNTR	unsigned long
#else
#error BITS_PER_LONG is not defined as 32 or 64
#endif

struct clk_cnts {
	DET_CNTR	min;
	DET_CNTR	max;
	DET_CNTR	total;
	DET_CNTR	cnt;
};


struct det_stats {
	unsigned long	packets_recvd;
	unsigned long	packets_sent;
	unsigned long	snacks_recvd;
	unsigned long	snacks_sent;
	unsigned long	timer_acks;
	unsigned long	timeouts;
	unsigned long	retries;
	unsigned long	duplicates;
	unsigned long	invalid_qp;
	unsigned long	bad_addr;
	unsigned long	tx_errors;
	unsigned long	zero_tx_limit;
	unsigned long	busted_snacks;
	unsigned long	sched_exhaust;
	unsigned long	sched_abort;
	unsigned long	loopback;
	unsigned long	code_trace;
	unsigned long	co_deferred;
	unsigned long	co_lb_deferred;
	unsigned long	wr_types[DET_WR_ATOMIC_RESP+1];
	struct clk_cnts	timings[MAX_TIMINGS];
};

static inline void det_reset_statistics(struct det_stats * const statistics)
{
	int i;
	memset(statistics, 0, sizeof(*statistics));
	for (i = 0; i < MAX_TIMINGS; i++)
		statistics->timings[i].min = -1;
}

static inline void clk_cnt_update(const int i,
				  const DET_CNTR start,
				  const DET_CNTR stop)
{
	DET_CNTR delta = stop > start ? stop-start : (~0-start)+stop;
	DET_STAT(timings[i].cnt++);
	DET_STAT(timings[i].total+=delta);
	DET_STAT(timings[i].min) > delta ? DET_STAT(timings[i].min=delta) : 0;
	DET_STAT(timings[i].max) < delta ? DET_STAT(timings[i].max=delta) : 0;
}

#ifdef CONFIG_DET_DEBUG
#define CODE_TRACE()						\
do {								\
	extern unsigned long _trace_heartbeat;			\
        DET_STAT(code_trace) = (_trace_heartbeat + __LINE__);	\
        _trace_heartbeat += 10000;				\
} while(0)

#else
#define CODE_TRACE()
#endif

#else /* !DET_STATS */

#define	DET_STAT(f)
#define DET_CNTR
#define det_reset_statistics( junk )
#define CODE_TRACE()
#define clk_cnt_update(i, start, stop)

#endif

#ifdef DET_PERF

/*
 *  The kernel code erroneously defines a cycle_t as long long for x86_64 so we
 *  can't use get_cycles() until they fix it.
 */
#ifdef __ia64__
#define PERF_GET_HRC(x)		x = get_cycles()
#else /* non-ia64 */
#define PERF_GET_HRC(x)		rdtscll(x)
#endif

#define PERF_DECL(var)		DET_CNTR var;
#define PERF_RECORD(i, start) \
	do {	\
		PERF_DECL(stop) \
		PERF_GET_HRC(stop); \
		clk_cnt_update(i, start, stop); \
	} while (0)

#else /* !DET_PERF */

#define PERF_GET_HRC(x)
#define PERF_DECL(var)
#define PERF_RECORD(i, start)

#endif /* DET_PERF */


/************************ end perf/stats stuff ********************************/

static inline int det_dbg_drop_packet( const union det_pdu * const pdu )
{
#ifdef CONFIG_DET_DEBUG
	extern int det_drop_count, det_cur_drop_count;
	/* yes, this will only work for the first 2 billon packes... */
	if (det_drop_count && !(++det_cur_drop_count % det_drop_count)) {
		printk(KERN_INFO "**** droping packet opcode=0x%x seq=%d\n",
				pdu->hdr.opcode, pdu->hdr.seq_num);
		return 1;
	}
#endif
	return 0;
}


#ifdef	CONFIG_COMPAT
long det_compat_ioctl(struct file *filp,
		      unsigned int cmd,
		      unsigned long arg);
#endif

void det_get_mac(struct det_mac_addr * const mac,
		 struct net_device * const netdev);

void det_clear_cqes(struct det_cq * const cq,
		    const struct det_wq * const wq);

void det_completion_callback(struct det_cq * const cq);

void det_event_callback(struct det_event * const event,
			const struct det_record * const record);

int det_create_event(struct det_device * const detdev,
		     struct det_event * const event);

int det_wait_on_event(struct det_event * const event,
		      signed long timeout,
		      struct det_eqe ** const eqe);

int det_generate_event(struct det_event * const event,
		       void * const handle);

int det_destroy_event(struct det_event * const event);

void det_async_event(const struct det_nic * const nic,
		     const enum det_event_code code,
		     const enum det_type type,
		     void * const handle);

int det_remove_events(struct det_event * const event,
		      const void * const handle);

void det_qp_error(struct det_qp * const qp);

void det_qp_idle(struct det_qp * const qp);

void det_qp_loopback(struct det_qp * const qp);

void det_qp_internal_disconnect(struct det_qp * const qp,
				const enum det_event_code reason);

void det_qp_remote_disconnect(struct det_qp * const qp,
			      const enum det_event_code reason);

void det_send_disconnect(struct det_qp * const qp,
			 const enum det_event_code reason);

void det_qp_disconnect_ack(struct det_qp * const qp,
			   const enum det_event_code reason);

void det_send_ack(struct det_qp * const qp);

int det_validate_ds(const struct det_pd * const pd,
		    const struct det_local_ds *ds_array,
		    struct det_ds *ds,
		    __u32 num_ds,
		    const enum det_access_ctrl access,
		    const int take_ref);

int det_copy_data(struct det_ds const *dst_ds,
		  struct det_ds const *src_ds,
		  u32 length);

int det_xmit_wr(struct det_qp * const qp,
		struct det_wq * const wq,
		struct det_wr * const wr,
		const int tx_limit,
		const int retransmit,
		u32 from_seq,
		atomic_t *posted);

u32 det_get_msg_id(const union det_pdu * const pdu);

int det_process_sq_completions(struct det_qp *qp,
			       struct det_wq *wq);

int det_schedule_rx_completions(struct det_qp * const qp,
				const int is_iq);

int det_wait_on_dma(struct det_qp * const qp);

int det_process_pdu(struct det_qp * const qp,
		    const union det_pdu * const pdu,
		    struct sk_buff * const skb,
		    int user_cntx);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
int det_recv_pkt(struct sk_buff *skb,
		 struct net_device *netdev,
		 struct packet_type *pt,
		 struct net_device *orig_dev);
#else
int det_recv_pkt(struct sk_buff *skb,
		 struct net_device *netdev,
		 struct packet_type *pt);
#endif

void det_schedule(enum det_schedule_op op,
		  const void * const arg);

int det_bind_mw(struct det_mw * const mw,
		struct det_mr * const mr,
		net32_t * const r_key,
		const __u64 vaddr,
		const __u32 length,
		const enum det_access_ctrl access);

void det_loopback_sq(struct det_qp * const qp);

void det_loopback_rq(struct det_qp * const qp);

void det_loopback_disconnect(struct det_qp * const qp,
			     const enum det_event_code reason);

void det_co_async_event(struct det_co * const co,
			const enum det_event_code code,
			const enum det_type type,
			void * const handle);

int det_process_broadcast_pkt(struct sk_buff *skb);

void det_dump_locks(void);

int det_print_tunables(char *buf);
int det_set_tunables(char *args, size_t count);

int det_print_tunables(char *buf);
int det_set_tunables(char *args, size_t count);

#ifdef	CONFIG_DET_LOOPBACK
#define	det_schedule(op, arg)		det_loopback_sq((arg))
#define	det_send_disconnect(qp, reason)	det_loopback_disconnect((qp), (reason))
#endif

static inline void det_reset_timeout(struct det_wr * const wr)
{
	wr->sar.seg.timeout_cnt = 0;
	wr->sar.seg.timeout_trigger = 2;
}

static inline void det_read_lock(rwlock_t * const lock,
				 const enum det_timing bucket)
{
#ifdef DET_PROFILE_LOCKS
	PERF_DECL(start)
	PERF_GET_HRC(start);

	read_lock(lock);

	PERF_RECORD(bucket, start);
#else
	read_lock(lock);
#endif
}

static inline void det_read_unlock(rwlock_t * const lock)
{
	read_unlock(lock);
}

#ifdef DET_LOCK_DEBUG

#define DET_SPINLOCK_MAGIC		0xfeedbeef
#define DET_SPINLOCK_OWNER_INIT		((void*)-1L)
#define DET_SPIN_LOCK_UNLOCKED				 \
{	.lock = SPIN_LOCK_UNLOCKED,			 \
	.magic = DET_SPINLOCK_MAGIC,			 \
	.owner_cpu = -1,				 \
	.owner = DET_SPINLOCK_OWNER_INIT,		 \
	.eip = DET_SPINLOCK_OWNER_INIT,			 \
	.waiters = { { .owner = DET_SPINLOCK_OWNER_INIT, \
		       .eip = DET_SPINLOCK_OWNER_INIT }, \
		     { .owner = DET_SPINLOCK_OWNER_INIT, \
		       .eip = DET_SPINLOCK_OWNER_INIT }, \
		     { .owner = DET_SPINLOCK_OWNER_INIT, \
		       .eip = DET_SPINLOCK_OWNER_INIT }, \
		     { .owner = DET_SPINLOCK_OWNER_INIT, \
		       .eip = DET_SPINLOCK_OWNER_INIT }, \
		   } \
}

#define det_spin_lock_init(x)  do {*(x) = (det_spinlock_t) DET_SPIN_LOCK_UNLOCKED; } while(0)

static inline void det_lock_print(det_spinlock_t *lock, char *msg)
{
	int i;
	struct task_struct *owner = NULL;

	if (lock->owner && lock->owner != DET_SPINLOCK_OWNER_INIT)
		owner = lock->owner;

	printk("%s: lock %p owner info: CPU %d comm %s pid %d eip %p\n"
	       "current info: CPU, %d comm %s pid %d\n",
		msg,
		lock,
		lock->owner_cpu,
		owner ? owner->comm : "<none>",
		owner ? owner->pid : -1,
		lock->eip,
		smp_processor_id(),
		current->comm,
		current->pid);

	printk("lock waiters: ");
	for (i = 0; i < num_online_cpus(); i++) {
		owner = lock->waiters[i].owner;
		if (!owner || owner == DET_SPINLOCK_OWNER_INIT)
			continue;
		printk("CPU %d comm %s eip %p ", i,
			owner->comm, lock->waiters[i].eip);
	}
	printk("\n");
}

static inline void det_lock_print_stack(det_spinlock_t *lock, char *msg)
{
	det_lock_print(lock, msg);
	dump_stack();
	det_dump_locks();
}

#else

#define DET_SPIN_LOCK_UNLOCKED	{ .lock = SPIN_LOCK_UNLOCKED }
#define det_spin_lock_init(x)	spin_lock_init((spinlock_t*)(x))
#define det_lock_print_stack	det_lock_print
static inline void det_lock_print(det_spinlock_t *lock, char *msg)
{
	printk("%s: lock %p\n", msg, lock);
}
#endif

static inline void det_spin_lock(det_spinlock_t *lock)
{
#ifdef DET_LOCK_DEBUG
	int i, dumped = 0;
	int cpu;

	preempt_disable();
	cpu = smp_processor_id();
here:
	if (lock->magic != DET_SPINLOCK_MAGIC)
		det_lock_print_stack(lock, "spin_lock bad magic");
	if (lock->owner == current)
		det_lock_print_stack(lock, "spin_lock recursion");
	if (lock->owner_cpu == cpu)
		det_lock_print_stack(lock, "spin_lock cpu recursion");
		
	lock->waiters[cpu].owner = current;
	lock->waiters[cpu].eip = &&here;
	while (1) {
		for (i = 0; i < 1000000; i++) {
			if (spin_trylock(&lock->lock)) {
				lock->owner_cpu = cpu;
				lock->owner = current;
				lock->eip = &&here;
				lock->waiters[cpu].owner = DET_SPINLOCK_OWNER_INIT;
				lock->waiters[cpu].eip = 0;
				return;
			}
			udelay(1);
		}
		if (!dumped) {
			det_lock_print_stack(lock, "stuck spin_lock");
			dumped = 1;
		}
	}
#else
	spin_lock((spinlock_t*)lock);
#endif
}

static inline void det_spin_unlock(det_spinlock_t *lock)
{
#ifdef DET_LOCK_DEBUG
	if (lock->magic != DET_SPINLOCK_MAGIC)
		det_lock_print_stack(lock, "spin_unlock bad magic");
	if (!spin_is_locked(&lock->lock))
		det_lock_print_stack(lock, "spin_unlock already unlocked");
	if (lock->owner != current)
		det_lock_print_stack(lock, "spin_unlock wrong owner");
	if (lock->owner_cpu != smp_processor_id())
		det_lock_print_stack(lock, "spin_unlock wrong CPU");

	lock->owner = DET_SPINLOCK_OWNER_INIT;
	lock->owner_cpu = -1;
	preempt_enable();
#endif
	spin_unlock((spinlock_t*)lock);
}

static inline void det_spin_lock_bh(det_spinlock_t *lock)
{
#ifdef DET_LOCK_DEBUG
	int i, dumped = 0;
	int cpu;

	preempt_disable();
	cpu = smp_processor_id();
here:
	if (lock->magic != DET_SPINLOCK_MAGIC)
		det_lock_print_stack(lock, "spin_lock_bh bad magic");
	if (lock->owner == current)
		det_lock_print_stack(lock, "spin_lock_bh recursion");
	if (lock->owner_cpu == cpu)
		det_lock_print_stack(lock, "spin_lock_bh cpu recursion");

	lock->waiters[cpu].owner = current;
	lock->waiters[cpu].eip = &&here;
	while (1) {
		for (i = 0; i < 1000000; i++) {
			if (spin_trylock_bh(&lock->lock)) {
				lock->owner_cpu = cpu;
				lock->owner = current;
				lock->eip = &&here;
				lock->waiters[cpu].owner = DET_SPINLOCK_OWNER_INIT;
				lock->waiters[cpu].eip = 0;
				return;
			}
			udelay(1);
		}
		if (!dumped) {
			det_lock_print_stack(lock, "stuck spin_lock_bh");
			dumped = 1;
		}
	}
#else
	spin_lock_bh((spinlock_t*)lock);
#endif
}

static inline void det_spin_unlock_bh(det_spinlock_t *lock)
{
#ifdef DET_LOCK_DEBUG
	if (lock->magic != DET_SPINLOCK_MAGIC)
		det_lock_print_stack(lock, "spin_unlock_bh bad magic");
	if (!spin_is_locked(&lock->lock))
		det_lock_print_stack(lock, "spin_unlock_bh already unlocked");
	if (lock->owner != current)
		det_lock_print_stack(lock, "spin_unlock_bh wrong owner");
	if (lock->owner_cpu != smp_processor_id())
		det_lock_print_stack(lock, "spin_unlock_bh wrong CPU");

	lock->owner = DET_SPINLOCK_OWNER_INIT;
	lock->owner_cpu = -1;
	preempt_enable();
#endif
	spin_unlock_bh((spinlock_t*)lock);
}
static inline void det_write_lock_bh(rwlock_t * const lock,
				     const enum det_timing bucket)
{
#ifdef DET_PROFILE_LOCKS
	PERF_DECL(start)
	PERF_GET_HRC(start);

	write_lock_bh(lock);

	PERF_RECORD(bucket, start);
#else
	write_lock_bh(lock);
#endif
}


static inline void det_write_unlock_bh(rwlock_t * const lock)
{
	write_unlock_bh(lock);
}

static inline void det_lock(det_spinlock_t * const lock,
			    const enum det_timing bucket)
{
#ifdef DET_PROFILE_LOCKS
	PERF_DECL(start)
	PERF_GET_HRC(start);

	det_spin_lock(lock);

	PERF_RECORD(bucket, start);
#else
	det_spin_lock(lock);
#endif
}

static inline void det_unlock(det_spinlock_t * const lock)
{
	det_spin_unlock(lock);
}

static inline void det_lock_bh(det_spinlock_t * const lock,
			       const enum det_timing bucket)
{
#ifdef DET_PROFILE_LOCKS
	PERF_DECL(start)
	PERF_GET_HRC(start);

	det_spin_lock_bh(lock);

	PERF_RECORD(bucket, start);
#else
	det_spin_lock_bh(lock);
#endif
}

static inline void det_unlock_bh(det_spinlock_t * const lock)
{
	det_spin_unlock_bh(lock);
}

static inline int det_spin_trylock_bh(det_spinlock_t *const lock)
{
#ifdef DET_LOCK_DEBUG
	preempt_disable();
here:
	if (spin_trylock_bh((spinlock_t*)lock)) {
		lock->owner_cpu = smp_processor_id();
		lock->owner = current;
		lock->eip = &&here;
		return 1;
	}
	preempt_enable();
	return 0;
#else
	return spin_trylock_bh((spinlock_t*)lock);
#endif
}

static inline int det_trylock_bh(det_spinlock_t * const lock,
				 const enum det_timing bucket)
{
#ifdef DET_PROFILE_LOCKS
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (det_spin_trylock_bh(lock)) {
		PERF_RECORD(bucket, start);
		return 1;
	}
	return 0;
#else
	return det_spin_trylock_bh(lock);
#endif
}

static inline int det_spin_is_locked(det_spinlock_t * const lock)
{
#ifdef DET_LOCK_DEBUG
	if (spin_is_locked((spinlock_t*)lock)) {
		if ((lock->owner == DET_SPINLOCK_OWNER_INIT) ||
		    (lock->owner_cpu == -1))
			det_lock_print_stack(lock, "spin_is_locked false");
		return 1;
	}
	return 0;
#else
	return spin_is_locked((spinlock_t*)lock);
#endif
}

#ifdef DET_USER_LOCK

extern det_spinlock_t	__det_user_lock__;

#define det_user_lock()		det_lock_bh(&__det_user_lock__, USER_LOCK);
#define det_user_unlock()	det_unlock_bh(&__det_user_lock__);

#define	wiremap_read_lock()
#define wiremap_read_unlock()

#define	wiremap_write_lock_bh()
#define wiremap_write_unlock_bh()

#define	sq_lock(lock)
#define	sq_unlock(lock)

#define	sq_lock_bh(lock)
#define	sq_unlock_bh(lock)
#define sq_trylock_bh(lock)	1

#define	iq_lock(lock)	
#define	iq_unlock(lock)

#define	iq_lock_bh(lock)
#define	iq_unlock_bh(lock)
#define iq_trylock_bh(lock)	1

#define	wq_lock(lock)
#define	wq_unlock(lock)

#define	wq_lock_bh(lock)
#define	wq_unlock_bh(lock)
#define wq_trylock_bh(lock)	1

#define	rq_lock(lock)
#define	rq_unlock(lock)

#define	rq_lock_bh(lock)
#define	rq_unlock_bh(lock)

#define	qp_lock(lock)
#define	qp_unlock(lock)

#define	qp_lock_bh(lock)
#define	qp_unlock_bh(lock)
#define qp_trylock_bh(lock)	1

#define	cq_lock_bh(lock)
#define	cq_unlock_bh(lock)

#define	event_lock_bh(lock)
#define	event_unlock_bh(lock)

#define	mr_lock(lock)
#define	mr_unlock(lock)

#define	wirestate_lock(lock)
#define	wirestate_unlock(lock)

#define	sched_obj_lock(lock)
#define	sched_obj_trylock(lock)	1
#define	sched_obj_unlock(lock)

#define	sched_list_lock()
#define	sched_list_unlock()

#define collective_grp_lock()
#define collective_grp_unlock()

#define co_lock(co)
#define co_unlock(co)

#define recv_queue_lock()
#define recv_queue_unlock()

#define group_lock(lock)
#define group_unlock(lock)

#define det_serialize_start(mutex, ref, comp)		\
do {							\
	while(!atomic_dec_and_test(mutex.count)) {	\
		atomic_inc(mutex.count);		\
		det_user_unlock();			\
		yield();				\
		det_user_lock();			\
	}						\
} while(0)

#define det_serialize_end(mutex)			\
do {							\
	atomic_inc(mutex.count);			\
} while(0)

#else

#define det_user_lock()
#define det_user_unlock()

#define	wiremap_read_lock()		det_read_lock(&det_wire_map_lock, WIRE_MAP_RD)
#define wiremap_read_unlock()		det_read_unlock(&det_wire_map_lock)

#define	wiremap_write_lock_bh()		det_write_lock_bh(&det_wire_map_lock, WIRE_MAP_WR)
#define wiremap_write_unlock_bh()	det_write_unlock_bh(&det_wire_map_lock)

#define	sq_lock(lock)			det_lock(lock, SQ_LOCK)
#define	sq_unlock(lock)			det_unlock(lock)

#define	sq_lock_bh(lock)		det_lock_bh(lock, SQ_LOCK)
#define	sq_unlock_bh(lock)		det_unlock_bh(lock)
#define sq_trylock_bh(lock)		det_trylock_bh(lock, SQ_LOCK)

#define	iq_lock(lock)			det_lock(lock, IQ_LOCK)
#define	iq_unlock(lock)			det_unlock(lock)

#define	iq_lock_bh(lock)		det_lock_bh(lock, IQ_LOCK)
#define	iq_unlock_bh(lock)		det_unlock_bh(lock)
#define iq_trylock_bh(lock)		det_trylock_bh(lock, IQ_LOCK)

#define	wq_lock(lock)			det_lock(lock, WQ_LOCK)
#define	wq_unlock(lock)			det_unlock(lock)

#define	wq_lock_bh(lock)		det_lock_bh(lock, WQ_LOCK)
#define	wq_unlock_bh(lock)		det_unlock_bh(lock)
#define wq_trylock_bh(lock)		det_trylock_bh(lock, WQ_LOCK)

#define	rq_lock(lock)			det_lock(lock, RQ_LOCK)
#define	rq_unlock(lock)			det_unlock(lock)

#define	rq_lock_bh(lock)		det_lock_bh(lock, RQ_LOCK)
#define	rq_unlock_bh(lock)		det_unlock_bh(lock)

#define	qp_lock(lock)			det_lock(lock, QP_LOCK)
#define	qp_unlock(lock)			det_unlock(lock)

#define	qp_lock_bh(lock)		det_lock_bh(lock, QP_LOCK)
#define	qp_unlock_bh(lock)		det_unlock_bh(lock)
#define qp_trylock_bh(lock)		det_trylock_bh(lock, QP_LOCK)

#define	cq_lock_bh(lock)		det_lock_bh(lock, CQ_LOCK)
#define	cq_unlock_bh(lock)		det_unlock_bh(lock)

#define	event_lock_bh(lock)		det_lock_bh(lock, EVENT_LOCK)
#define	event_unlock_bh(lock)		det_unlock_bh(lock)

#define	mr_lock(lock)			det_lock(lock, MR_LOCK)
#define	mr_unlock(lock)			det_unlock(lock)

#define	wirestate_lock(lock)		det_lock_bh(lock, WIRE_STATE)
#define	wirestate_unlock(lock)		det_unlock_bh(lock)

#define	sched_obj_lock(lock)		det_lock_bh(lock, SCHED_OBJ_LOCK)
#define	sched_obj_trylock(lock)		det_trylock_bh(lock, SCHED_OBJ_LOCK)
#define	sched_obj_unlock(lock)		det_unlock_bh(lock)

#define	sched_list_lock()		det_lock(&scheduler_list_lock, SCHED_LIST_LOCK)
#define	sched_list_unlock()		det_unlock(&scheduler_list_lock)

#define collective_grp_lock()		det_lock_bh(&collective_grp_list_lock, CO_GRP_LOCK)
#define collective_grp_unlock()		det_unlock_bh(&collective_grp_list_lock)

#define co_lock(co)			det_lock_bh(&co->lock, CO_LOCK);
#define co_unlock(co)			det_unlock_bh(&co->lock);

#ifdef CONFIG_DET_SEQUESTER

#define recv_queue_lock()		det_lock_bh(&det_recv_queue_lock, RECV_QUEUE_LOCK)
#define recv_queue_unlock()		det_unlock_bh(&det_recv_queue_lock)
#endif

#define group_lock(lock)		det_lock(lock, GRP_LOCK)
#define group_unlock(lock)		det_unlock(lock)

#define det_serialize_start(mutex, ref, comp)				\
do {									\
	if (down_interruptible(mutex)) {				\
		if (comp && atomic_dec_and_test((atomic_t*)ref))	\
			complete(comp);					\
		else if (ref)						\
			atomic_dec((atomic_t*)ref);			\
		return -ERESTARTSYS;					\
	}								\
} while(0)

#define det_serialize_end(mutex)	up(mutex)

#endif

#define qp_get_co(qp)		(((struct det_qp *)(qp))->co)
#define qp_set_co(qp, co)	((qp)->co = (co))
#define qp_is_co(qp)		(qp_get_co(qp) == (struct det_co *)(qp))
#define qp_is_co_member(qp)	(qp_get_co(qp) && !qp_is_co(qp))


#define cq_get_co(cq)		(((struct det_cq *)(cq))->co)
#define cq_set_co(cq, co)	((cq)->co = (co))
#define cq_is_co_member(cq)	cq_get_co(cq)


#define	get_ioc_ds(ioc_ds)	(ioc_ds.vaddr ? &ioc_ds : NULL)


/* Hold a lock during this call for synchronization. */
static inline int det_get_id(struct idr *idp, void *ptr, int *id)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,8)
	return idr_get_new(idp, ptr, id);
#else
	return unlikely((*id = idr_get_new(idp, ptr)) == -1) ? -EAGAIN : 0;
#endif
}


/*
 *  Because idr_pre_get takes the same internal spinlock that is taken
 *  by idr_get/remove calls under a bottom half write_lock, we need to
 *  do the pre_get with bottom half disabled.  We can't simply take the
 *  det_wiremap_write_lock_bh because pre_get does a blocking memory
 *  allocation call.  Since BH is disabled, mask must be GFP_ATOMIC.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
static inline int det_idr_pre_get(struct idr *idp, gfp_t gfp_mask)
#else
static inline int det_idr_pre_get(struct idr *idp, unsigned gfp_mask)
#endif
{
	int ret;

	local_bh_disable();
	ret = idr_pre_get(idp, GFP_ATOMIC);
	local_bh_enable();
	return ret;
}

/*
 *  Some Linux distributors have backported the skb macros in some releases
 *  so we can't rely on kernel version.
 *
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
 */
#if HAVE_SKB_MACROS == 0
static inline void skb_reset_network_header(struct sk_buff * const skb)
{
	skb->nh.raw = skb->data;
}


static inline void skb_reset_mac_header(struct sk_buff * const skb)
{
	skb->mac.raw = skb->data;
}


static inline unsigned char *skb_mac_header(const struct sk_buff * const skb)
{
	return skb->mac.raw;
}
#endif


/* Hold a lock during this call for synchronization. */
static inline void det_kcopy_ring(void * const dst,
				  void * const src,
				  const u32 src_head,
				  const u32 src_tail,
				  const u32 src_size,
				  const u32 count,
				  const size_t size)
{
	register u32 n;

	if (src_head < src_tail) {
		det_memcpy(dst, (u8*)src + (src_head * size), count * size);
	} else {
		n = min(count, src_size - src_head);
		det_memcpy(dst, (u8*)src + (src_head * size), n * size);
		if (n < count)
			det_memcpy((u8*)dst + (n * size), src, (count - n) * size);
	}
}


static inline void det_append_eqe(struct det_event * const event,
				  struct det_eqe * const eqe)
{
	event_lock_bh(&event->lock);
	list_add_tail(&eqe->entry, &event->event_queue);
	if (waitqueue_active(&event->wait_queue))
		wake_up(&event->wait_queue);
	event_unlock_bh(&event->lock);
}


/*
 * Reserve a completion queue entry.  Note that cq->lock remains
 * held upon successful completion of this call.  The client should
 * call det_append_cqe() after constructing the work completion.
 */
static inline int det_reserve_cqe(struct det_cq * const cq,
				  struct det_wc ** const wc)
{
	cq_lock_bh(&cq->lock);

	/* Check the CQ state. */
	if (unlikely(cq->attr.state != DET_CQ_READY)) {
		cq_unlock_bh(&cq->lock);
		return -EIO;
	}

	/* Check if the CQ is already full. */
	if (unlikely(atomic_read(&cq->depth) == cq->attr.size)) {
		cq->attr.state = DET_CQ_ERROR;
		cq_unlock_bh(&cq->lock);
		det_async_event(cq->nic, DET_AE_CQ_OVERRUN, DET_TYPE_CQ, cq);

		/*
		 * Return an error.  The QP affiliated with this CQ should
		 * also generate an event and transition to the error state.
		 */
		return -ENOSPC;
	}

	*wc = &cq->wc_array[cq->tail];

	return 0;
}


/*
 * Append a completion queue entry.  Note that this function assumes
 * that the cq->lock is currently held.  The client calls this function
 * after constructing the work completion returned by det_reserve_cqe().
 */
static inline void det_append_cqe(struct det_cq * const cq,
				  const struct det_wc * const wc)
{
	if ((wc->flags & DET_WC_SOLICITED) || (wc->status != DET_WS_SUCCESS))
		cq->solicited = 1;

	cq->tail = (cq->tail + 1) % cq->attr.size;
	atomic_inc(&cq->depth);

	cq_unlock_bh(&cq->lock);
}


static inline void det_notify_cq(struct det_cq * const cq)
{
	if (!cq->attr.arm || !atomic_read(&cq->depth))
		return;

	cq_lock_bh(&cq->lock);
	if ( (cq->attr.arm & DET_CQ_NEXT_SIGNALED)		      ||
	    ((cq->attr.arm & DET_CQ_NEXT_SOLICITED) && cq->solicited) ||
	    ((cq->attr.arm & DET_CQ_THRESHOLD)	    &&
	     (atomic_read(&cq->depth) >= cq->attr.threshold)) ) {
		cq->attr.arm = 0;	/* Disarm the CQ. */
		cq_unlock_bh(&cq->lock);
		cq->completion_cb(cq);
	} else
		cq_unlock_bh(&cq->lock);
}


/* This function assumes the WQ is protected by a lock. */
static inline struct det_wr *det_get_wr(const struct det_wq * const wq,
					const u32 index)
{
	/* Must calculate since WQ array elements are variable sized. */
	return (struct det_wr *)((u8 *)wq->array + (wq->entry_size * index));
}

static inline struct det_wr* det_wr_by_msg_id(struct det_wq * const wq,
					      const u32 msg_id)
{
	struct det_wr *wr;

	if (wq->size == 0)
		return NULL;

	wr = det_get_wr(wq, msg_id % wq->size);
	return (wr->msg_id == msg_id) ? wr : NULL;
}

/*
 * Reserve a inbound work queue entry.  Note that qp->iq.lock remains
 * held upon successful completion of this call.  The client should
 * call det_append_iq_wqe() after constructing the work request or
 * det_release_iq_wqe() to abort.
 */
static inline int det_reserve_iq_wqe(struct det_qp * const qp,
				     struct det_wr ** const wr)
{
	iq_lock_bh(&qp->iq.lock);

	/* Check if the QP state allows posting IQ WRs. */
	if (qp->attr.state != DET_QP_CONNECTED) {
		iq_unlock_bh(&qp->iq.lock);
		return -ENOTCONN;
	}

	/* Check if the IQ is already full. */
	if (unlikely(qp->iq.depth == qp->attr.max_ir)) {
		iq_unlock_bh(&qp->iq.lock);
		return -ENOSPC;
	}

	*wr = det_get_wr(&qp->iq, qp->iq.tail);

#ifdef	DET_TRIGGERED_WR
	(*wr)->trigger = 0;
	(*wr)->signal  = NULL;
#endif

	PERF_GET_HRC((*wr)->start);	
	return 0;
}


static inline void det_release_iq_wqe(struct det_qp * const qp)
{
	iq_unlock_bh(&qp->iq.lock);
}


/*
 * Append a inbound work queue entry.  Note that this function assumes
 * that the qp->iq.lock is currently held.  The client calls this function
 * after constructing the work request returned by det_reserve_iq_wqe().
 * Return queue depth including this entry.
 */
static inline int det_append_iq_wqe(struct det_qp * const qp)
{
	int iq_depth = ++qp->iq.depth;

	qp->iq.tail = (qp->iq.tail + 1) % qp->iq.size;
	qp->iq.next_msg_id++;
	iq_unlock_bh(&qp->iq.lock);

	return iq_depth;
}


/*
 * Reserve a send work queue entry.  Note that qp->sq.lock remains
 * held upon successful completion of this call.  The client should
 * call det_append_sq_wqe() after constructing the work request or
 * det_release_sq_wqe() to abort.
 */
static inline int det_reserve_sq_wqe(struct det_qp * const qp,
				     struct det_wr ** const wr)
{
	sq_lock_bh(&qp->sq.lock);

	/* Check if the QP state allows posting SQ WRs. */
	if (qp->attr.state != DET_QP_CONNECTED) {
		sq_unlock_bh(&qp->sq.lock);
		return -ENOTCONN;
	}

	/* Check if the SQ is already full. */
	if (unlikely(qp->sq.depth == qp->attr.sq_size)) {
		sq_unlock_bh(&qp->sq.lock);
		return -ENOSPC;
	}

	*wr = det_get_wr(&qp->sq, qp->sq.tail);

#ifdef	DET_TRIGGERED_WR
	(*wr)->trigger = 0;
	(*wr)->signal  = NULL;
#endif

	PERF_GET_HRC((*wr)->start);	
	return 0;
}


static inline void det_release_sq_wqe(struct det_qp * const qp)
{
	sq_unlock_bh(&qp->sq.lock);
}


/*
 * Append a send work queue entry.  Note that this function assumes that
 * the qp->sq.lock is currently held.  The client calls this function
 * after constructing the work request returned by det_reserve_sq_wqe().
 * Return queue depth including this entry.
 */
static inline int det_append_sq_wqe(struct det_qp * const qp)
{
	int sq_depth = ++qp->sq.depth;

	DET_STAT(wr_types[det_get_wr(&qp->sq,qp->sq.tail)->type]++);

	qp->sq.tail = (qp->sq.tail + 1) % qp->sq.size;
	qp->sq.next_msg_id++;
	sq_unlock_bh(&qp->sq.lock);

	return sq_depth;
}


/*
 * Reserve a receive work queue entry.  Note that qp->rq.lock remains
 * held upon successful completion of this call.  The client should
 * call det_append_rq_wqe() after constructing the work request or
 * det_release_rq_wqe() to abort.
 */
static inline int det_reserve_rq_wqe(struct det_qp * const qp,
				     struct det_wr ** const wr)
{
	rq_lock_bh(&qp->rq.lock);

	/* Check if the QP state allows posting RQ WRs. */
	if ((qp->attr.state != DET_QP_IDLE) &&
	    (qp->attr.state != DET_QP_CONNECTED)) {
		rq_unlock_bh(&qp->rq.lock);
		return -ENOTCONN;
	}

	/* Check if the RQ is already full. */
	if (unlikely(qp->rq.depth == qp->attr.rq_size)) {
		rq_unlock_bh(&qp->rq.lock);
		return -ENOSPC;
	}

	*wr = det_get_wr(&qp->rq, qp->rq.tail);

#ifdef	DET_TRIGGERED_WR
	(*wr)->trigger = 0;
	(*wr)->signal  = NULL;
#endif

	PERF_GET_HRC((*wr)->start);	
	return 0;
}


static inline void det_release_rq_wqe(struct det_qp * const qp)
{
	rq_unlock_bh(&qp->rq.lock);
}


/*
 * Append a receive work queue entry.  Note that this function assumes
 * that the qp->rq.lock is currently held.  The client calls this function
 * after constructing the work request returned by det_reserve_rq_wqe().
 */
static inline void det_append_rq_wqe(struct det_qp * const qp)
{
	DET_STAT(wr_types[DET_WR_RECV]++);

	qp->rq.tail = (qp->rq.tail + 1) % qp->rq.size;
	qp->rq.depth++;
	qp->rq.next_msg_id++;

	if (!qp_is_co_member(qp))
		rq_unlock_bh(&qp->rq.lock);
}


/*
 * NOTE: To avoid deadly embrace, do not hold CQ lock during this call.
 * The protocol layer holds WQ lock while processing a packet and acquires
 * the CQ lock (via det_reserve_cqe) to build a work completion.  Care has
 * been taken in the client det_poll_cq and det_poll_cq_ioctl routines to
 * avoid holding the CQ lock to retire WQEs removed by polling to prevent
 * a deadlock.
 */
static inline void det_retire_wqes(struct det_wq * const wq,
				   u32 count)
{
	/* Prevent retiring WQEs from QPs that have been destroyed. */
	if (!wq)
		return;

	wq_lock_bh(&wq->lock);
	wq->head = (wq->head + count) % wq->size;
	wq->depth -= count;
	wq->completion_cnt -= count;
	wq_unlock_bh(&wq->lock);
}


/* Clear a single ds MR reference. */
static inline void det_clear_ds_ref(struct det_ds * const ds)
{
	if (ds->in_use) {
		ds->in_use = 0;
		if (atomic_dec_and_test(&ds->mr->base.refcnt))
			complete(&ds->mr->base.done);
	}
}


/* Clear the specified number of ds MR references. */
static inline void det_clear_ds_refs(struct det_ds *ds,
				     u32 num_ds)
{
	while(num_ds--)
		det_clear_ds_ref(ds++);
}


/*
 * To work around MPI's assumptions that data is written atomically in
 * their header structures, we do our best to write the first 16 integers
 * of a transfer atomically.
 */
static inline int det_atomic_copy(u8 * const dst_addr,
				  u8 * const src_addr,
				  u32 copy_len,
				  int head_copied)
{
	volatile int *src_x = (int*)src_addr;
	volatile int *dst_x = (int*)dst_addr;
	volatile u8  *src_c;
	volatile u8  *dst_c;

	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (unlikely(!copy_len)) {
//		printk("det_atomic_copy length 0!\n");
		return head_copied;
	}

	if (det_do_atomic_copy &&
	    !head_copied &&
	    !((unsigned long)src_addr & (sizeof(int)-1)) &&
	    !((unsigned long)dst_addr & (sizeof(int)-1))) {

		switch (copy_len) {
		case sizeof(int):
			*dst_x = *src_x;
			goto done;
		case sizeof(int)*2:
			*dst_x++ = *src_x++;
			*dst_x = *src_x;
			goto done;
		case sizeof(int)*3:
			*dst_x++ = *src_x++;
			*dst_x++ = *src_x++;
			*dst_x = *src_x;
			goto done;
		default:
			if (copy_len >= (sizeof(int)*4)) {
				/* We have at least a whole header to copy. */
				head_copied = 1;
				copy_len -= sizeof(int)*4;

				*dst_x++ = *src_x++;
				*dst_x++ = *src_x++;
				*dst_x++ = *src_x++;

				if (copy_len == 0) {
					*dst_x = *src_x;
					goto done;
				}
				*dst_x++ = *src_x++;
			}
		}
	}

	/*
	 *  Header already copied, bad alignment, or atomic copy off.
	 *  Copy all but the last byte.
	 */
	if (--copy_len)
		det_memcpy((void*)dst_x, (void*)src_x, copy_len);

	src_c = ((volatile u8*) src_x) + copy_len;
	dst_c = ((volatile u8*) dst_x) + copy_len;
	*dst_c = *src_c;
done:
	PERF_RECORD(ATOMIC_COPY, start);
	return head_copied;
}


static inline void *det_kmap_src(struct page *page)
{
	return kmap_atomic(page, KM_SOFTIRQ0);
}


/*
 * struct page * passed for symmetry with det_kunmap_dst()
 */
static inline void det_kunmap_src(struct page *page, void *vaddr)
{
	if (vaddr)
		kunmap_atomic(vaddr, KM_SOFTIRQ0);
}


static inline void *det_kmap_dst(struct page *page)
{
	return kmap_atomic(page, KM_SOFTIRQ1);
}


static inline void det_kunmap_dst(struct page *page, void *vaddr)
{
	if (vaddr)
		kunmap_atomic(vaddr, KM_SOFTIRQ1);
	if (likely(page)) {
		flush_dcache_page(page);
		if (!PageReserved(page))
			set_page_dirty(page);
	}
}

static inline struct net_device* det_dev_get_by_name(const char *const ifname)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
	return dev_get_by_name(&init_net, ifname);
#else
	return dev_get_by_name(ifname);
#endif
}

#endif /* __DET_DRIVER_H__ */
