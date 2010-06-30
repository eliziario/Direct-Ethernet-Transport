/*
 * Intel(R) Direct Ethernet Transport (Intel(R) DET)
 * RDMA emulation protocol driver.
 * Copyright (c) 2008, Intel Corporation.
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This library is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
 * for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <fcntl.h>	/* for O_RDWR */
#include <sys/ioctl.h>  /* for IOCTL's */
#include <sys/socket.h> /* for sockaddr */
#include <stdio.h>      /* for fprintf etc */
#include <unistd.h>     /* for close */
#include <asm/types.h>  /* for __u64 etc */
#ifdef BITOPS
#include <asm/bitops.h>	/* for test_and_set etc */
#endif
#include <errno.h>	/* for errno */
#include <string.h>	/* for strncpy */
#include <time.h>	/* for nanosleep */

#include "det.h"

#ifdef	CONFIG_DET_DOORBELL

#define DET_IOCTL_DECL(type, var)
#include <stdlib.h>	/* for malloc */

static int page_size, page_mask, max_sges;

#else

#define DET_IOCTL_DECL(type, var)	struct type var

#endif

/***************************************/
//#define DET_PERF
#ifdef DET_PERF

enum det_timing {
	TM_SEND,
	TM_WRITE,
	TM_READ,
	TM_POLL_HIT,
	TM_POLL_MISS,
	TM_MAX_TIMINGS
};

#ifndef CONFIG_IA64

#define rdtscll(val) do { \
      unsigned int __a,__d; \
      asm volatile("rdtsc" : "=a" (__a), "=d" (__d)); \
      (val) = ((unsigned long)__a) | (((unsigned long)__d)<<32); \
} while(0)

/*
 *  We should be using a cycle_t for DET_CNTR but the kernel source erroneously
 *  defines a cycle_t as long long for x86_64 so we have to do it ourself.
 */
#define	DET_CNTR	unsigned long

struct clk_cnts {
	DET_CNTR	min;
	DET_CNTR	max;
	DET_CNTR	total;
	DET_CNTR	cnt;
};

struct clk_cnts timings[TM_MAX_TIMINGS];

static inline void clk_cnt_update(const int i,
				  const DET_CNTR start,
				  const DET_CNTR stop)
{
	DET_CNTR delta = stop > start ? stop-start : (~0-start)+stop;
	timings[i].cnt++;
	timings[i].total+=delta;
	timings[i].min > delta ? timings[i].min=delta : 0;
	timings[i].max < delta ? timings[i].max=delta : 0;
}

#define PERF_GET_HRC(x)		rdtscll(x)
#define PERF_DECL(var)		DET_CNTR var;
#define PERF_RECORD(i, start) \
	do {	\
		PERF_DECL(stop) \
		PERF_GET_HRC(stop); \
		clk_cnt_update(i, start, stop); \
	} while (0)

#define tm_avg( i ) \
	(timings[i].cnt ? timings[i].total / timings[i].cnt : 0)

void det_reset_stats(void)
{
	int i;
	memset(timings, 0, sizeof(timings));
	for (i = 0; i < TM_MAX_TIMINGS; i++)
		timings[i].min = -1;
}

void det_print_stats(void)
{
	printf( "                 min      max      avg      cnt\n"
		"DET Send:        % 8lld % 8lld % 8lld % 8lld\n"
		"DET Write:       % 8lld % 8lld % 8lld % 8lld\n"
		"DET Read:        % 8lld % 8lld % 8lld % 8lld\n"
		"DET Poll Hit:    % 8lld % 8lld % 8lld % 8lld\n"
		"DET Poll Miss:   % 8lld % 8lld % 8lld % 8lld\n",
		timings[TM_SEND].min,      timings[TM_SEND].max,      tm_avg(TM_SEND),      timings[TM_SEND].cnt,
		timings[TM_WRITE].min,     timings[TM_WRITE].max,     tm_avg(TM_WRITE),     timings[TM_WRITE].cnt,
		timings[TM_READ].min,      timings[TM_READ].max,      tm_avg(TM_READ),      timings[TM_READ].cnt,
		timings[TM_POLL_HIT].min,  timings[TM_POLL_HIT].max,  tm_avg(TM_POLL_HIT),  timings[TM_POLL_HIT].cnt,
		timings[TM_POLL_MISS].min, timings[TM_POLL_MISS].max, tm_avg(TM_POLL_MISS), timings[TM_POLL_MISS].cnt
		);
}

#else

#define DET_CNTR
#define PERF_GET_HRC(x)
#define PERF_DECL(var)
#define PERF_RECORD(i, start)
#define det_print_stats()
#define det_reset_stats()

#endif /* CONFIG_IA64 */
#else

#define DET_CNTR
#define PERF_GET_HRC(x)
#define PERF_DECL(var)
#define PERF_RECORD(i, start)
#define det_print_stats()
#define det_reset_stats()

#endif /* DET_PERF */
/***************************************/

#define set_ioc_ds(ioc_ds, verb_ds)		\
do {						\
	if (verb_ds)				\
		ioc_ds = *verb_ds;		\
	else					\
		ioc_ds.vaddr = 0;		\
} while(0)

#define det_doorbell_ptr2offset(doorbell, ptr) \
	(doorbell)->ptr = (void*)((void*)(doorbell)->ptr - (void*)(doorbell))

#define	det_atomic_init(a)	((a)->mutex = (a)->counter = 0)

#define	det_atomic_read(a)	((a)->counter)

#ifdef BITOPS
static inline void det_atomic_inc(struct det_atomic * const a)
{
	/* Acquire mutex. */
	while (test_and_set_bit(0, &a->mutex))
		;

	a->counter++;

	/*
	 * Release mutex.  This requires a memory barrier.
	 * Should use smp_mb__before_clear_bit() for this.
	 */
#ifdef CONFIG_IA64
	__asm__ __volatile__("mf" ::: "memory");
#else
	__asm__ __volatile__("" ::: "memory");
#endif
	clear_bit(0, &a->mutex);
}
#else
/*  we'll assume there are intrinsic atomics*/
static inline void det_atomic_inc(struct det_atomic * const a)
{
	(void)__sync_fetch_and_add(&a->counter, 1);
}
#endif


static inline int det_verb(int fd,
			   int cmd,
			   void *arg)
{
//#define DET_VERB_IOCTL
#ifdef	DET_VERB_IOCTL
	return ioctl(fd, cmd, arg);
#else
	struct det_verb verb;

	verb.cmd = cmd;
	verb.arg = (unsigned long)arg;

	return write(fd, &verb, sizeof(verb));
#endif
}


int det_open(struct det_device * const detdev)
{
	if (!detdev) {
		errno = EINVAL;
		return errno;
	}

	detdev->fd = open(DET_DEV, O_RDWR);
	if (detdev->fd == -1)
		return errno;

#ifdef	CONFIG_DET_DOORBELL
	page_size = getpagesize();
	page_mask = ~(page_size - 1);
	max_sges  =  (page_size - sizeof(struct det_doorbell)) /
				  sizeof(struct det_local_ds);
#endif

	return 0;
}


int det_query(struct det_device * const detdev,
	      struct det_attr * const attr)
{
	int err;

	if (!detdev) {
		errno = EINVAL;
		return errno;
	}

	err = det_verb(detdev->fd, DET_IOC_QUERY, attr);

	return (err) ? errno : 0;
}


int det_close(struct det_device * const detdev)
{
	int err;

	if (!detdev) {
		errno = EINVAL;
		return errno;
	}

	err = close(detdev->fd);

	return (err) ? errno : 0;
}


int det_create_event(struct det_device * const detdev,
		     const det_event_cb event_cb,
		     struct det_event * const event)
{
	int err;

	if (!detdev || !event) {
		errno = EINVAL;
		return errno;
	}

	event->fd	= detdev->fd;
	event->event_cb = event_cb;

	err = det_verb(detdev->fd, DET_IOC_CREATE_EVENT, &event->id);

	return (err) ? errno : 0;
}


int det_wait_on_event(struct det_event * const event,
		      const signed long timeout)
{
	struct det_ioc_event ioc_event;
	struct det_ioc_wait_on_event wait;
	int err;

	if (!event) {
		errno = EINVAL;
		return errno;
	}

	wait.event    = &ioc_event;
	wait.event_id = event->id;
	wait.timeout  = timeout;

	err = det_verb(event->fd, DET_IOC_WAIT_ON_EVENT, &wait);
	if (err)
		return errno;

	if (event->event_cb) {
		if (ioc_event.record.type != DET_TYPE_UNKNOWN)
			ioc_event.record.handle =
				(void*)(unsigned long)ioc_event.context;
		event->event_cb(event, &ioc_event.record);
	}

	switch (ioc_event.record.type) {
		case DET_TYPE_CO:
			det_atomic_inc(&((struct det_co *)
				(unsigned long)ioc_event.context)->nr_events);
			break;

		case DET_TYPE_CQ:
			det_atomic_inc(&((struct det_cq *)
				(unsigned long)ioc_event.context)->nr_events);
			break;

		case DET_TYPE_QP:
			det_atomic_inc(&((struct det_qp *)
				(unsigned long)ioc_event.context)->nr_events);
			break;

		case DET_TYPE_NIC:
			det_atomic_inc(&((struct det_nic *)
				(unsigned long)ioc_event.context)->nr_events);
			break;

		case DET_TYPE_UNKNOWN:
		default:
			break;
	}

	return 0;
}


int det_generate_event(struct det_event * const event,
		       void * const handle)
{
	struct det_ioc_generate_event generate;
	int err;

	if (!event) {
		errno = EINVAL;
		return errno;
	}

	generate.event_id = event->id;
	generate.handle	  = handle;

	err = det_verb(event->fd, DET_IOC_GENERATE_EVENT, &generate);

	return (err) ? errno : 0;
}


int det_destroy_event(struct det_event * const event)
{
	int err;

	if (!event) {
		errno = EINVAL;
		return errno;
	}

	err = det_verb(event->fd, DET_IOC_DESTROY_EVENT, &event->id);

	return (err) ? errno : 0;
}


int det_open_nic(struct det_device * const detdev,
		 const char * const ifname,
		 const struct det_event * event,
		 struct det_nic * const nic)
{
	struct det_ioc_open_nic open;
	int err;

	if (!detdev || !ifname || !event || !nic) {
		errno = EINVAL;
		return errno;
	}

	nic->fd = detdev->fd;
	det_atomic_init(&nic->nr_events);

	open.context  = (unsigned long)nic;
	open.nic_id   = &nic->id;
	strncpy(open.ifname, ifname, IFNAMSIZ);
	open.event_id = event->id;

	err = det_verb(detdev->fd, DET_IOC_OPEN_NIC, &open);

	return (err) ? errno : 0;
}


int det_query_nic(struct det_nic * const nic,
		  struct det_nic_attr * const nic_attr)
{
	struct det_ioc_query_nic query;
	int err;

	if (!nic) {
		errno = EINVAL;
		return errno;
	}

	query.attr   = nic_attr;
	query.nic_id = nic->id;

	err = det_verb(nic->fd, DET_IOC_QUERY_NIC, &query);

	return (err) ? errno : 0;
}


int det_close_nic(struct det_nic * const nic)
{
	struct det_ioc_close_nic close;
	struct timespec snooze;
	int nr_events, err;

	if (!nic) {
		errno = EINVAL;
		return errno;
	}

	close.nr_events = &nr_events;
	close.nic_id	= nic->id;

	err = det_verb(nic->fd, DET_IOC_CLOSE_NIC, &close);
	if (err)
		return errno;

	snooze.tv_sec  = 0;
	snooze.tv_nsec = 1000;	/* nanoseconds */

	while (det_atomic_read(&nic->nr_events) != nr_events)
		nanosleep(&snooze, NULL);

	return 0;
}


int det_alloc_pd(struct det_nic * const nic,
		 struct det_pd * const pd)
{
	struct det_ioc_alloc_pd alloc;
	int err;

	if (!nic || !pd) {
		errno = EINVAL;
		return errno;
	}

	pd->fd = nic->fd;

	alloc.pd_id  = &pd->id;
	alloc.nic_id = nic->id;

	err = det_verb(nic->fd, DET_IOC_ALLOC_PD, &alloc);

	return (err) ? errno : 0;
}


int det_dealloc_pd(struct det_pd * const pd)
{
	int err;

	if (!pd) {
		errno = EINVAL;
		return errno;
	}

	err = det_verb(pd->fd, DET_IOC_DEALLOC_PD, &pd->id);

	return (err) ? errno : 0;
}


int det_create_cq(struct det_nic * const nic,
		  const __u32 size,
		  struct det_event * const event,
		  struct det_cq_attr * const cq_attr,
		  struct det_cq * const cq)
{
	struct det_ioc_create_cq create;
	int err;

	if (!nic || !event || !cq) {
		errno = EINVAL;
		return errno;
	}

	cq->fd = nic->fd;
#ifdef CONFIG_DET_DOORBELL
	cq->qp = NULL;
	cq->co = NULL;
#endif
	det_atomic_init(&cq->nr_events);

	create.context	= (unsigned long)cq;
	create.cq_id	= &cq->id;
	create.size	= size;
	create.attr	= cq_attr;
	create.nic_id	= nic->id;
	create.event_id = event->id;

	err = det_verb(nic->fd, DET_IOC_CREATE_CQ, &create);

	return (err) ? errno : 0;
}


int det_query_cq(struct det_cq * const cq,
		 struct det_cq_attr * const cq_attr)
{
	struct det_ioc_query_cq query;
	int err;

	if (!cq) {
		errno = EINVAL;
		return errno;
	}

	query.attr  = cq_attr;
	query.cq_id = cq->id;

	err = det_verb(cq->fd, DET_IOC_QUERY_CQ, &query);

	return (err) ? errno : 0;
}


int det_resize_cq(struct det_cq * const cq,
		  const __u32 size,
		  struct det_cq_attr * const cq_attr)
{
	struct det_ioc_resize_cq resize;
	int err;

	if (!cq) {
		errno = EINVAL;
		return errno;
	}

	resize.size  = size;
	resize.attr  = cq_attr;
	resize.cq_id = cq->id;

	err = det_verb(cq->fd, DET_IOC_RESIZE_CQ, &resize);

	return (err) ? errno : 0;
}


int det_arm_cq(struct det_cq * const cq,
	       const enum det_cq_arm arm,
	       const __u32 threshold)
{
	struct det_ioc_arm_cq arm_cq;
	int err;

	if (!cq) {
		errno = EINVAL;
		return errno;
	}

	arm_cq.cq_id = cq->id;
	arm_cq.arm   = arm;
	if (arm & DET_CQ_THRESHOLD)
		arm_cq.threshold = threshold;

	err = det_verb(cq->fd, DET_IOC_ARM_CQ, &arm_cq);

	return (err) ? errno : 0;
}


int det_poll_cq(struct det_cq * const cq,
		__u32 * const num_wc,
		struct det_wc * const wc_array)
{
	struct det_ioc_poll_cq poll;
	int err;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (!cq) {
		errno = EINVAL;
		return errno;
	}

#ifdef CONFIG_DET_DOORBELL
	if (cq->co) {
		struct det_doorbell *db = cq->co->doorbell;
		
		if (*num_wc < 1) {
			errno = EINVAL;
			return errno;
		}
		if (db->co_last_wc_count == db->co_current_wc_count) {
			errno = EAGAIN;
			return errno;
		}

		*wc_array = db->co_wc;
		*num_wc = 1;
		db->co_last_wc_count = db->co_current_wc_count;

		return 0;
	}
#endif
	poll.wc_array = wc_array;
	poll.p_num_wc = num_wc;
	poll.num_wc   = *num_wc;
	poll.cq_id    = cq->id;

	err = det_verb(cq->fd, DET_IOC_POLL_CQ, &poll);

	PERF_RECORD(err==0 ? TM_POLL_HIT : TM_POLL_MISS, start);

	return (err) ? errno : 0;
}


int det_destroy_cq(struct det_cq * const cq)
{
	struct det_ioc_destroy_cq destroy;
	struct timespec snooze;
	int nr_events, err;

	if (!cq) {
		errno = EINVAL;
		return errno;
	}

	destroy.nr_events = &nr_events;
	destroy.cq_id	  = cq->id;

	err = det_verb(cq->fd, DET_IOC_DESTROY_CQ, &destroy);
	if (err)
		return errno;

	snooze.tv_sec  = 0;
	snooze.tv_nsec = 1000;	/* nanoseconds */

	while (det_atomic_read(&cq->nr_events) != nr_events)
		nanosleep(&snooze, NULL);

	return 0;
}


int det_create_qp(struct det_pd * const pd,
		  const struct det_qp_create * const qp_create,
		  struct det_qp_attr * const qp_attr,
		  struct det_qp * const qp)
{
	struct det_ioc_create_qp create;
	int err;

	if (!pd || !qp_create || !qp) {
		errno = EINVAL;
		return errno;
	}

	qp->fd	  = pd->fd;
	qp->pd	  = pd;
	qp->sq_cq = qp_create->sq_cq;
	qp->rq_cq = qp_create->rq_cq;
	det_atomic_init(&qp->nr_events);

	create.context	= (unsigned long)qp;
	create.qp_id	= &qp->id;
	create.create	= qp_create;
	create.attr	= qp_attr;
	create.pd_id	= pd->id;
	create.sq_cq_id = (qp_create->sq_cq) ? qp_create->sq_cq->id : 0;
	create.rq_cq_id = (qp_create->rq_cq) ? qp_create->rq_cq->id : 0;

#ifdef	CONFIG_DET_DOORBELL
	if ((qp->sq_cq && qp->sq_cq->co) || (qp->rq_cq && qp->rq_cq->co)) {
		errno = EINVAL;
		return errno;
	}

	qp->malloc = malloc(page_size);

	/* Must be page aligned for max_sges tests in data path operations. */
	if (!qp->malloc || ((unsigned long)qp->malloc & ~page_mask)) {
		qp->malloc = realloc(qp->malloc, page_size * 2);
		if (!qp->malloc) {
			errno = ENOMEM;
			return errno;
		}

		/* Align to a page boundary. */
		qp->doorbell = (void *)(((unsigned long)qp->malloc +
				page_size - 1) & page_mask);
	} else
		qp->doorbell = qp->malloc;

	create.doorbell = qp->doorbell;
#endif

	err = det_verb(pd->fd, DET_IOC_CREATE_QP, &create);
#ifdef	CONFIG_DET_DOORBELL
	if (err) {
		free(qp->malloc);
		return errno;
	}

	qp->sq_cq->qp = qp;
	qp->rq_cq->qp = qp;
#else
	if (err)
		return errno;
#endif

	if (qp_attr) {
		qp_attr->pd    = qp->pd;
		qp_attr->sq_cq = qp->sq_cq;
		qp_attr->rq_cq = qp->rq_cq;
	}

	return 0;
}


int det_query_qp(struct det_qp * const qp,
		 struct det_qp_attr * const qp_attr)
{
	struct det_ioc_query_qp query;
	int err;

	if (!qp) {
		errno = EINVAL;
		return errno;
	}

	query.attr  = qp_attr;
	query.qp_id = qp->id;

	err = det_verb(qp->fd, DET_IOC_QUERY_QP, &query);
	if (err)
		return errno;

	qp_attr->pd    = qp->pd;
	qp_attr->sq_cq = qp->sq_cq;
	qp_attr->rq_cq = qp->rq_cq;

	return 0;
}


int det_modify_qp(struct det_qp * const qp,
		  const struct det_qp_mod * const qp_mod,
		  struct det_qp_attr * const qp_attr)
{
	struct det_ioc_modify_qp modify;
	int err;

	if (!qp) {
		errno = EINVAL;
		return errno;
	}

	modify.mod   = qp_mod;
	modify.attr  = qp_attr;
	modify.qp_id = qp->id;

	err = det_verb(qp->fd, DET_IOC_MODIFY_QP, &modify);
	if (err)
		return errno;

	if (qp_attr) {
		qp_attr->pd    = qp->pd;
		qp_attr->sq_cq = qp->sq_cq;
		qp_attr->rq_cq = qp->rq_cq;
	}

	return 0;
}


int det_destroy_qp(struct det_qp * const qp)
{
	struct det_ioc_destroy_qp destroy;
	struct timespec snooze;
	int nr_events, err;

	if (!qp) {
		errno = EINVAL;
		return errno;
	}

	destroy.nr_events = &nr_events;
	destroy.qp_id	  = qp->id;

	err = det_verb(qp->fd, DET_IOC_DESTROY_QP, &destroy);
	if (err)
		return errno;

	snooze.tv_sec  = 0;
	snooze.tv_nsec = 1000;	/* nanoseconds */

	while (det_atomic_read(&qp->nr_events) != nr_events)
		nanosleep(&snooze, NULL);

#ifdef	CONFIG_DET_DOORBELL
	free(qp->malloc);
#endif

	return 0;
}


int det_reg_mr(struct det_pd * const pd,
	       const struct det_mr_reg * const mr_reg,
	       __u32 * const l_key,
	       net32_t * const r_key,
	       struct det_mr * const mr)
{
	struct det_ioc_reg_mr reg;
	int err;

	if (!pd || !mr_reg || !mr) {
		errno = EINVAL;
		return errno;
	}

	mr->fd = pd->fd;
	mr->pd = pd;

	reg.mr_id   = &mr->id;
	reg.l_key   = l_key;
	reg.r_key   = r_key;
	reg.mr_reg  = *mr_reg;
	reg.pd_id   = pd->id;

	err = det_verb(pd->fd, DET_IOC_REG_MR, &reg);
	if (err)
		return errno;

	return 0;
}


int det_query_mr(struct det_mr * const mr,
		 struct det_mr_attr * const mr_attr)
{
	struct det_ioc_query_mr query;
	int err;

	if (!mr) {
		errno = EINVAL;
		return errno;
	}

	query.attr  = mr_attr;
	query.mr_id = mr->id;

	err = det_verb(mr->fd, DET_IOC_QUERY_MR, &query);
	if (err)
		return errno;

	mr_attr->base.pd = mr->pd;

	return 0;
}


int det_modify_mr(struct det_mr * const mr,
		  const struct det_mr_mod * const mr_mod,
		  __u32 * const l_key,
		  net32_t * const r_key)
{
	struct det_ioc_modify_mr modify;
	int err;

	if (!mr || !mr_mod ||
	    ((mr_mod->flags & DET_MR_MOD_PD) && !mr_mod->pd)) {
		errno = EINVAL;
		return errno;
	}

	modify.mod   = mr_mod;
	modify.l_key = l_key;
	modify.r_key = r_key;
	modify.mr_id = mr->id;
	modify.pd_id = (mr_mod->flags & DET_MR_MOD_PD) ? mr_mod->pd->id : 0;

	err = det_verb(mr->fd, DET_IOC_MODIFY_MR, &modify);
	if (err)
		return errno;

	if (mr_mod->flags & DET_MR_MOD_PD)
		mr->pd = mr_mod->pd;

	return 0;
}


int det_reg_shared(struct det_mr * const mr,
		   const struct det_sh_reg * const sh_reg,
		   __u32 * const l_key,
		   net32_t * const r_key,
		   struct det_mr * const shared_mr)
{
	struct det_ioc_reg_shared reg;
	int err;

	if (!mr || !sh_reg || !sh_reg->pd || !shared_mr) {
		errno = EINVAL;
		return errno;
	}

	shared_mr->fd = mr->fd;
	shared_mr->pd = sh_reg->pd;

	reg.shared_id = &shared_mr->id;
	reg.l_key     = l_key;
	reg.r_key     = r_key;
	reg.access    = sh_reg->access;
	reg.pd_id     = sh_reg->pd->id;
	reg.mr_id     = mr->id;

	err = det_verb(mr->fd, DET_IOC_REG_SHARED, &reg);
	if (err)
		return errno;

	return 0;
}


int det_dereg_mr(struct det_mr * const mr)
{
	int err;

	if (!mr) {
		errno = EINVAL;
		return errno;
	}

	err = det_verb(mr->fd, DET_IOC_DEREG_MR, &mr->id);

	return (err) ? errno : 0;
}


int det_create_mw(struct det_pd * const pd,
		  struct det_mw * const mw)
{
	struct det_ioc_create_mw create;
	int err;

	if (!pd || !mw) {
		errno = EINVAL;
		return errno;
	}

	mw->fd = pd->fd;
	mw->pd = pd;

	create.mw_id = &mw->id;
	create.pd_id = pd->id;

	err = det_verb(pd->fd, DET_IOC_CREATE_MW, &create);

	return (err) ? errno : 0;
}


int det_query_mw(struct det_mw * const mw,
		 struct det_mw_attr * const mw_attr)
{
	struct det_ioc_query_mw query;
	int err;

	if (!mw) {
		errno = EINVAL;
		return errno;
	}

	query.attr  = mw_attr;
	query.mw_id = mw->id;

	err = det_verb(mw->fd, DET_IOC_QUERY_MW, &query);
	if (err)
		return errno;

	mw_attr->base.pd = mw->pd;

	return 0;
}


int det_destroy_mw(struct det_mw * const mw)
{
	int err;

	if (!mw) {
		errno = EINVAL;
		return errno;
	}

	err = det_verb(mw->fd, DET_IOC_DESTROY_MW, &mw->id);

	return (err) ? errno : 0;
}


int det_send(struct det_qp * const qp,
	     const __u64 id,
	     const struct det_local_ds * const ds_array,
	     const __u32 num_ds,
	     const enum det_wr_flags flags,
	     const __u32 immediate_data)
{
	DET_IOCTL_DECL(det_ioc_send, send);
	int err;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (!qp || (num_ds && !ds_array)) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	if (num_ds > max_sges) {
		errno = E2BIG;
		return errno;
	}

	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	qp->doorbell->send.wr_id	  = id;
	qp->doorbell->send.ds_array	  = qp->doorbell->send.local_ds;
	qp->doorbell->send.num_ds	  = num_ds;
	qp->doorbell->send.immediate_data = immediate_data;
	qp->doorbell->send.flags	  = flags;
	qp->doorbell->send.qp_id	  = qp->id;

	memcpy(qp->doorbell->send.local_ds, ds_array,
		sizeof(*ds_array) * num_ds);

	qp->doorbell->ioctl_cmd = DET_IOC_SEND;

	qp->doorbell->ring = 1;		/* Ding Dong */
	do err = qp->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	send.wr_id	    = id;
	send.ds_array	    = ds_array;
	send.num_ds	    = num_ds;
	send.immediate_data = immediate_data;
	send.flags	    = flags;
	send.qp_id	    = qp->id;

	if (num_ds && (num_ds <= MAX_IOC_NUM_DS))
		memcpy(send.local_ds, ds_array, sizeof(*ds_array) * num_ds);

	err = det_verb(qp->fd, DET_IOC_SEND, &send);
#endif

	PERF_RECORD(TM_SEND, start);
	return (err) ? errno : 0;
}


int det_recv(struct det_qp * const qp,
	     const __u64 id,
	     const struct det_local_ds * const ds_array,
	     const __u32 num_ds)
{
	DET_IOCTL_DECL(det_ioc_recv, recv);
	int err;

	if (!qp || (num_ds && !ds_array)) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	if (num_ds > max_sges) {
		errno = E2BIG;
		return errno;
	}

	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	qp->doorbell->recv.wr_id    = id;
	qp->doorbell->recv.ds_array = qp->doorbell->recv.local_ds;
	qp->doorbell->recv.num_ds   = num_ds;
	qp->doorbell->recv.qp_id    = qp->id;

	memcpy(qp->doorbell->recv.local_ds, ds_array,
		sizeof(*ds_array) * num_ds);

	qp->doorbell->ioctl_cmd = DET_IOC_RECV;

	qp->doorbell->ring = 1;		/* Ding Dong */
	do err = qp->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	recv.wr_id    = id;
	recv.ds_array = ds_array;
	recv.num_ds   = num_ds;
	recv.qp_id    = qp->id;

	if (num_ds && (num_ds <= MAX_IOC_NUM_DS))
		memcpy(recv.local_ds, ds_array, sizeof(*ds_array) * num_ds);

	err = det_verb(qp->fd, DET_IOC_RECV, &recv);
#endif

	return (err) ? errno : 0;
}


int det_read(struct det_qp * const qp,
	     const __u64 id,
	     const struct det_local_ds * const ds_array,
	     const __u32 num_ds,
	     const net64_t remote_address,
	     const net32_t remote_key,
	     const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_read, read);
	int err;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (!qp || !ds_array || !num_ds) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	if (num_ds > max_sges) {
		errno = E2BIG;
		return errno;
	}

	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	qp->doorbell->read.wr_id	  = id;
	qp->doorbell->read.ds_array	  = qp->doorbell->read.local_ds;
	qp->doorbell->read.num_ds	  = num_ds;
	qp->doorbell->read.remote_address = remote_address;
	qp->doorbell->read.remote_key	  = remote_key;
	qp->doorbell->read.flags	  = flags;
	qp->doorbell->read.qp_id	  = qp->id;

	memcpy(qp->doorbell->read.local_ds, ds_array,
		sizeof(*ds_array) * num_ds);

	qp->doorbell->ioctl_cmd = DET_IOC_READ;

	qp->doorbell->ring = 1;		/* Ding Dong */
	do err = qp->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	read.wr_id	    = id;
	read.ds_array	    = ds_array;
	read.num_ds	    = num_ds;
	read.remote_address = remote_address;
	read.remote_key	    = remote_key;
	read.flags	    = flags;
	read.qp_id	    = qp->id;

	if (num_ds && (num_ds <= MAX_IOC_NUM_DS))
		memcpy(read.local_ds, ds_array, sizeof(*ds_array) * num_ds);

	err = det_verb(qp->fd, DET_IOC_READ, &read);
#endif

	PERF_RECORD(TM_READ, start);
	return (err) ? errno : 0;
}


int det_write(struct det_qp * const qp,
	      const __u64 id,
	      const struct det_local_ds * const ds_array,
	      const __u32 num_ds,
	      const net64_t remote_address,
	      const net32_t remote_key,
	      const enum det_wr_flags flags,
	      const __u32 immediate_data)
{
	DET_IOCTL_DECL(det_ioc_write, write);
	int err;
	PERF_DECL(start)
	PERF_GET_HRC(start);

	if (!qp || (num_ds && !ds_array)) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	if (num_ds > max_sges) {
		errno = E2BIG;
		return errno;
	}

	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	qp->doorbell->write.wr_id	   = id;
	qp->doorbell->write.ds_array	   = qp->doorbell->write.local_ds;
	qp->doorbell->write.num_ds	   = num_ds;
	qp->doorbell->write.remote_address = remote_address;
	qp->doorbell->write.remote_key     = remote_key;
	qp->doorbell->write.immediate_data = immediate_data;
	qp->doorbell->write.flags	   = flags;
	qp->doorbell->write.qp_id	   = qp->id;

	memcpy(qp->doorbell->write.local_ds, ds_array,
		sizeof(*ds_array) * num_ds);

	qp->doorbell->ioctl_cmd = DET_IOC_WRITE;

	qp->doorbell->ring = 1;		/* Ding Dong */
	do err = qp->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	write.wr_id	     = id;
	write.ds_array	     = ds_array;
	write.num_ds	     = num_ds;
	write.remote_address = remote_address;
	write.remote_key     = remote_key;
	write.immediate_data = immediate_data;
	write.flags	     = flags;
	write.qp_id	     = qp->id;

	if (num_ds && (num_ds <= MAX_IOC_NUM_DS))
		memcpy(write.local_ds, ds_array, sizeof(*ds_array) * num_ds);

	err = det_verb(qp->fd, DET_IOC_WRITE, &write);
#endif

	PERF_RECORD(TM_WRITE, start);
	return (err) ? errno : 0;
}


int det_bind(struct det_qp * const qp,
	     const __u64 id,
	     struct det_mw * const mw,
	     struct det_mr * const mr,
	     net32_t * const r_key,
	     const __u64 vaddr,
	     const __u32 length,
	     const enum det_access_ctrl access,
	     const enum det_wr_flags flags)
{
	struct det_ioc_bind bind;
	int err;

	if (!qp || !mw || (length && !mr)) {
		errno = EINVAL;
		return errno;
	}

	bind.wr_id  = id;
	bind.qp_id  = qp->id;
	bind.mr_id  = (length) ? mr->id : 0;
	bind.mw_id  = mw->id;
	bind.r_key  = r_key;
	bind.vaddr  = vaddr;
	bind.length = length;
	bind.access = access;
	bind.flags  = flags;

	err = det_verb(qp->fd, DET_IOC_BIND, &bind);

	return (err) ? errno : 0;
}


int det_comp_exch(struct det_qp * const qp,
		  const __u64 id,
		  const __u64 comp_operand,
		  const __u64 exch_operand,
		  const struct det_local_ds * const local_ds,
		  const net64_t remote_address,
		  const net32_t remote_key,
		  const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_comp_exch, comp_exch);
	int err;

	if (!qp || !local_ds) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	qp->doorbell->comp_exch.wr_id	       = id;
	qp->doorbell->comp_exch.comp_operand   = comp_operand;
	qp->doorbell->comp_exch.exch_operand   = exch_operand;
	qp->doorbell->comp_exch.remote_address = remote_address;
	qp->doorbell->comp_exch.remote_key     = remote_key;
	qp->doorbell->comp_exch.local_ds       = *local_ds;
	qp->doorbell->comp_exch.flags	       = flags;
	qp->doorbell->comp_exch.qp_id	       = qp->id;

	qp->doorbell->ioctl_cmd = DET_IOC_COMP_EXCH;

	qp->doorbell->ring = 1;		/* Ding Dong */
	do err = qp->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	comp_exch.wr_id		 = id;
	comp_exch.comp_operand	 = comp_operand;
	comp_exch.exch_operand	 = exch_operand;
	comp_exch.remote_address = remote_address;
	comp_exch.remote_key	 = remote_key;
	comp_exch.local_ds	 = *local_ds;
	comp_exch.flags		 = flags;
	comp_exch.qp_id		 = qp->id;

	err = det_verb(qp->fd, DET_IOC_COMP_EXCH, &comp_exch);
#endif

	return (err) ? errno : 0;
}


int det_fetch_add(struct det_qp * const qp,
		  const __u64 id,
		  const __u64 add_operand,
		  const struct det_local_ds * const local_ds,
		  const net64_t remote_address,
		  const net32_t remote_key,
		  const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_fetch_add, fetch_add);
	int err;

	if (!qp || !local_ds) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	qp->doorbell->fetch_add.wr_id	       = id;
	qp->doorbell->fetch_add.add_operand    = add_operand;
	qp->doorbell->fetch_add.remote_address = remote_address;
	qp->doorbell->fetch_add.remote_key     = remote_key;
	qp->doorbell->fetch_add.local_ds       = *local_ds;
	qp->doorbell->fetch_add.flags	       = flags;
	qp->doorbell->fetch_add.qp_id	       = qp->id;

	qp->doorbell->ioctl_cmd = DET_IOC_FETCH_ADD;

	qp->doorbell->ring = 1;		/* Ding Dong */
	do err = qp->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	fetch_add.wr_id		 = id;
	fetch_add.add_operand	 = add_operand;
	fetch_add.remote_address = remote_address;
	fetch_add.remote_key	 = remote_key;
	fetch_add.local_ds	 = *local_ds;
	fetch_add.flags		 = flags;
	fetch_add.qp_id		 = qp->id;

	err = det_verb(qp->fd, DET_IOC_FETCH_ADD, &fetch_add);
#endif

	return (err) ? errno : 0;
}


int det_create_co(struct det_pd * const pd,
		  struct det_cq * const cq,
		  struct det_co * const co)
{
	struct det_ioc_create_co create;
	int err;

	if (!cq || !pd || !co
#ifdef CONFIG_DET_DOORBELL
			      || cq->qp
#endif
					) {
		errno = EINVAL;
		return errno;
	}

	co->fd = cq->fd;
	co->pd = pd;
	co->cq = cq;
	det_atomic_init(&co->nr_events);

	create.context = (unsigned long)co;
	create.co_id   = &co->id;
	create.pd_id   = pd->id;
	create.cq_id   = cq->id;

#ifdef	CONFIG_DET_DOORBELL
	co->malloc = malloc(page_size);

	/* Must be page aligned for max_sges tests in data path operations. */
	if (!co->malloc || ((unsigned long)co->malloc & ~page_mask)) {
		co->malloc = realloc(co->malloc, page_size * 2);
		if (!co->malloc) {
			errno = ENOMEM;
			return errno;
		}

		/* Align to a page boundary. */
		co->doorbell = (void *)(((unsigned long)co->malloc +
				page_size - 1) & page_mask);
	} else
		co->doorbell = co->malloc;

	create.doorbell = co->doorbell;
#endif

	err = det_verb(co->fd, DET_IOC_CREATE_CO, &create);
#ifdef	CONFIG_DET_DOORBELL
	if (err) {
		free(co->malloc);
		return errno;
	}
	cq->co = co;
#else
	if (err)
		return errno;
#endif
	return 0;
}


int det_join(struct det_co * const co,
	     const __u64 id,
	     const net64_t tag,
	     const int size,
	     const int rank,
	     const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_join, join);
	int err;

	if (!co || (size <= 1) || (rank >= size)) {
		errno = EINVAL;
		return errno;
	}

	co->size = size;

#ifdef	CONFIG_DET_DOORBELL
	if (size > max_sges) {
		errno = E2BIG;
		return errno;
	}

	co->doorbell->join.wr_id = id;
	co->doorbell->join.tag   = tag;
	co->doorbell->join.size  = size;
	co->doorbell->join.rank  = rank;
	co->doorbell->join.flags = flags;
	co->doorbell->join.co_id = co->id;

	co->doorbell->ioctl_cmd = DET_IOC_JOIN;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	join.wr_id = id;
	join.tag   = tag;
	join.size  = size;
	join.rank  = rank;
	join.flags = flags;
	join.co_id = co->id;

	err = det_verb(co->fd, DET_IOC_JOIN, &join);
#endif

	return (err) ? errno : 0;
}


int det_destroy_co(struct det_co * const co)
{
	struct det_ioc_destroy_co destroy;
	struct timespec snooze;
	int nr_events, err;

	if (!co) {
		errno = EINVAL;
		return errno;
	}

	destroy.nr_events = &nr_events;
	destroy.co_id = co->id;

	err = det_verb(co->fd, DET_IOC_DESTROY_CO, &destroy);
	if (err)
		return errno;

	snooze.tv_sec  = 0;
	snooze.tv_nsec = 1000;	/* nanoseconds */

	while (det_atomic_read(&co->nr_events) != nr_events)
		nanosleep(&snooze, NULL);

#ifdef	CONFIG_DET_DOORBELL
	free(co->malloc);
#endif

	return 0;
}


int det_barrier(struct det_co * const co,
		const __u64 id,
		const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_barrier, barrier);
	int err;

	if (!co) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	co->doorbell->barrier.wr_id = id;
	co->doorbell->barrier.flags = flags;
	co->doorbell->barrier.co_id = co->id;

	co->doorbell->ioctl_cmd = DET_IOC_BARRIER;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	barrier.wr_id = id;
	barrier.flags = flags;
	barrier.co_id = co->id;

	err = det_verb(co->fd, DET_IOC_BARRIER, &barrier);
#endif

	return (err) ? errno : 0;
}


int det_bcast(struct det_co * const co,
	      const __u64 id,
	      const int root,
	      const struct det_local_ds * const ds,
	      const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_bcast, bcast);
	int err;

	if (!co || !ds) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	co->doorbell->bcast.wr_id = id;
	co->doorbell->bcast.ds    = *ds;
	co->doorbell->bcast.root  = root;
	co->doorbell->bcast.flags = flags;
	co->doorbell->bcast.co_id = co->id;

	co->doorbell->ioctl_cmd = DET_IOC_BCAST;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	bcast.wr_id = id;
	bcast.ds    = *ds;
	bcast.root  = root;
	bcast.flags = flags;
	bcast.co_id = co->id;

	err = det_verb(co->fd, DET_IOC_BCAST, &bcast);
#endif

	return (err) ? errno : 0;
}


int det_scatter(struct det_co * const co,
		const __u64 id,
		const int root,
		const struct det_local_ds * const src_ds,
		const struct det_local_ds * const dst_ds,
		const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_scatter, scatter);
	int err;

	if (!co || (root < 0) || (root >= co->size) || (!src_ds && !dst_ds)) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	co->doorbell->scatter.wr_id  = id;
	set_ioc_ds(co->doorbell->scatter.src_ds, src_ds);
	set_ioc_ds(co->doorbell->scatter.dst_ds, dst_ds);
	co->doorbell->scatter.root   = root;
	co->doorbell->scatter.flags  = flags;
	co->doorbell->scatter.co_id  = co->id;

	co->doorbell->ioctl_cmd = DET_IOC_SCATTER;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	scatter.wr_id  = id;
	set_ioc_ds(scatter.src_ds, src_ds);
	set_ioc_ds(scatter.dst_ds, dst_ds);
	scatter.root   = root;
	scatter.flags  = flags;
	scatter.co_id  = co->id;

	err = det_verb(co->fd, DET_IOC_SCATTER, &scatter);
#endif

	return (err) ? errno : 0;
}


int det_scatterv(struct det_co * const co,
		 const __u64 id,
		 const int root,
		 const struct det_local_ds * const src_ds_array,
		 const struct det_local_ds * const dst_ds,
		 const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_scatterv, scatterv);
	int err;

	if (!co || (root < 0) || (root >= co->size) ||
	    (!src_ds_array && !dst_ds)) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	co->doorbell->scatterv.wr_id	    = id;
	co->doorbell->scatterv.src_ds_array = (src_ds_array) ?
		co->doorbell->scatterv.src_ds : NULL;
	set_ioc_ds(co->doorbell->scatterv.dst_ds, dst_ds);
	co->doorbell->scatterv.root	    = root;
	co->doorbell->scatterv.flags	    = flags;
	co->doorbell->scatterv.co_id	    = co->id;

	if (src_ds_array) {
		memcpy(co->doorbell->scatterv.src_ds, src_ds_array,
			sizeof(*src_ds_array) * co->size);
		det_doorbell_ptr2offset(co->doorbell, scatterv.src_ds_array);
	}

	co->doorbell->ioctl_cmd = DET_IOC_SCATTERV;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	scatterv.wr_id	      = id;
	scatterv.src_ds_array = src_ds_array;
	set_ioc_ds(scatterv.dst_ds, dst_ds);
	scatterv.root	      = root;
	scatterv.flags	      = flags;
	scatterv.co_id	      = co->id;

	if (src_ds_array && (co->size <= MAX_IOC_NUM_DS))
		memcpy(scatterv.src_ds, src_ds_array,
			sizeof(*src_ds_array) * co->size);

	err = det_verb(co->fd, DET_IOC_SCATTERV, &scatterv);
#endif

	return (err) ? errno : 0;
}


int det_gather(struct det_co * const co,
	       const __u64 id,
	       const int root,
	       const struct det_local_ds * const src_ds,
	       const struct det_local_ds * const dst_ds,
	       const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_gather, gather);
	int err;

	if (!co || (root < 0) || (root >= co->size) || (!src_ds && !dst_ds)) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	co->doorbell->gather.wr_id  = id;
	set_ioc_ds(co->doorbell->gather.src_ds, src_ds);
	set_ioc_ds(co->doorbell->gather.dst_ds, dst_ds);
	co->doorbell->gather.root   = root;
	co->doorbell->gather.flags  = flags;
	co->doorbell->gather.co_id  = co->id;

	co->doorbell->ioctl_cmd = DET_IOC_GATHER;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	gather.wr_id  = id;
	set_ioc_ds(gather.src_ds, src_ds);
	set_ioc_ds(gather.dst_ds, dst_ds);
	gather.root   = root;
	gather.flags  = flags;
	gather.co_id  = co->id;

	err = det_verb(co->fd, DET_IOC_GATHER, &gather);
#endif

	return (err) ? errno : 0;
}


int det_gatherv(struct det_co * const co,
		const __u64 id,
		const int root,
		const struct det_local_ds * const src_ds,
		const struct det_local_ds * const dst_ds_array,
		const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_gatherv, gatherv);
	int err;

	if (!co || (root < 0) || (root >= co->size) ||
	    (!src_ds && !dst_ds_array)) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	co->doorbell->gatherv.wr_id	   = id;
	set_ioc_ds(co->doorbell->gatherv.src_ds, src_ds);
	co->doorbell->gatherv.dst_ds_array = (dst_ds_array) ?
		co->doorbell->gatherv.dst_ds : NULL;
	co->doorbell->gatherv.root	   = root;
	co->doorbell->gatherv.flags	   = flags;
	co->doorbell->gatherv.co_id	   = co->id;

	if (dst_ds_array) {
		memcpy(co->doorbell->gatherv.dst_ds, dst_ds_array,
			sizeof(*dst_ds_array) * co->size);
		det_doorbell_ptr2offset(co->doorbell, gatherv.dst_ds_array);
	}

	co->doorbell->ioctl_cmd = DET_IOC_GATHERV;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	gatherv.wr_id	     = id;
	set_ioc_ds(gatherv.src_ds, src_ds);
	gatherv.dst_ds_array = dst_ds_array;
	gatherv.root	     = root;
	gatherv.flags	     = flags;
	gatherv.co_id	     = co->id;

	if (dst_ds_array && (co->size <= MAX_IOC_NUM_DS))
		memcpy(gatherv.dst_ds, dst_ds_array,
			sizeof(*dst_ds_array) * co->size);

	err = det_verb(co->fd, DET_IOC_GATHERV, &gatherv);
#endif

	return (err) ? errno : 0;
}


int det_allgather(struct det_co * const co,
		  const __u64 id,
		  const struct det_local_ds * const src_ds,
		  const struct det_local_ds * const dst_ds,
		  const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_allgather, allgather);
	int err;

	if (!co || !dst_ds) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	co->doorbell->allgather.wr_id  = id;
	set_ioc_ds(co->doorbell->allgather.src_ds, src_ds);
	co->doorbell->allgather.dst_ds = *dst_ds;
	co->doorbell->allgather.flags  = flags;
	co->doorbell->allgather.co_id  = co->id;

	co->doorbell->ioctl_cmd = DET_IOC_ALLGATHER;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	allgather.wr_id  = id;
	set_ioc_ds(allgather.src_ds, src_ds);
	allgather.dst_ds = *dst_ds;
	allgather.flags  = flags;
	allgather.co_id  = co->id;

	err = det_verb(co->fd, DET_IOC_ALLGATHER, &allgather);
#endif

	return (err) ? errno : 0;
}


int det_allgatherv(struct det_co * const co,
		   const __u64 id,
		   const struct det_local_ds * const src_ds,
		   const struct det_local_ds * const dst_ds_array,
		   const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_allgatherv, allgatherv);
	int err;

	if (!co || !dst_ds_array) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL

	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	co->doorbell->allgatherv.wr_id	      = id;
	set_ioc_ds(co->doorbell->allgatherv.src_ds, src_ds);
	co->doorbell->allgatherv.dst_ds_array = co->doorbell->allgatherv.dst_ds;
	co->doorbell->allgatherv.flags	      = flags;
	co->doorbell->allgatherv.co_id	      = co->id;

	memcpy((void*)co->doorbell->allgatherv.dst_ds_array, dst_ds_array,
		sizeof(*dst_ds_array) * co->size);
	det_doorbell_ptr2offset(co->doorbell, allgatherv.dst_ds_array);

	co->doorbell->ioctl_cmd = DET_IOC_ALLGATHERV;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	allgatherv.wr_id	= id;
	set_ioc_ds(allgatherv.src_ds, src_ds);
	allgatherv.dst_ds_array = dst_ds_array;
	allgatherv.flags	= flags;
	allgatherv.co_id	= co->id;

	if (co->size <= MAX_IOC_NUM_DS)
		memcpy(allgatherv.dst_ds, dst_ds_array,
			sizeof(*dst_ds_array) * co->size);

	err = det_verb(co->fd, DET_IOC_ALLGATHERV, &allgatherv);
#endif

	return (err) ? errno : 0;
}


int det_alltoall(struct det_co * const co,
		 const __u64 id,
		 const struct det_local_ds * const src_ds,
		 const struct det_local_ds * const dst_ds,
		 const enum det_wr_flags flags)
{
	DET_IOCTL_DECL(det_ioc_alltoall, alltoall);
	int err;

	if (!co || !src_ds || !dst_ds) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	co->doorbell->alltoall.wr_id  = id;
	co->doorbell->alltoall.src_ds = *src_ds;
	co->doorbell->alltoall.dst_ds = *dst_ds;
	co->doorbell->alltoall.flags  = flags;
	co->doorbell->alltoall.co_id  = co->id;

	co->doorbell->ioctl_cmd = DET_IOC_ALLTOALL;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	alltoall.wr_id  = id;
	alltoall.src_ds = *src_ds;
	alltoall.dst_ds = *dst_ds;
	alltoall.flags  = flags;
	alltoall.co_id  = co->id;

	err = det_verb(co->fd, DET_IOC_ALLTOALL, &alltoall);
#endif

	return (err) ? errno : 0;
}


int det_alltoallv(struct det_co * const co,
		  const __u64 id,
		  const struct det_local_ds * const src_ds_array,
		  const struct det_local_ds * const dst_ds_array,
		  const enum det_wr_flags flags)
{
	struct det_ioc_alltoallv alltoallv;
	int err;

	if (!co || !src_ds_array || !dst_ds_array) {
		errno = EINVAL;
		return errno;
	}

#ifdef	CONFIG_DET_DOORBELL
	/* AlltoAll has two ds_arrays - prevent doorbell overrun. */
	if (co->size > max_sges/2) {
		alltoallv.wr_id	       = id;
		alltoallv.src_ds_array = src_ds_array;
		alltoallv.dst_ds_array = dst_ds_array;
		alltoallv.flags	       = flags;
		alltoallv.co_id	       = co->id;

		if (co->size <= MAX_IOC_NUM_DS) {
			memcpy(alltoallv.src_ds, src_ds_array,
				sizeof(*src_ds_array) * co->size);
			memcpy(alltoallv.dst_ds, dst_ds_array,
				sizeof(*dst_ds_array) * co->size);
		}

		err = det_verb(co->fd, DET_IOC_ALLTOALLV, &alltoallv);

		return (err) ? errno : 0;
	}

	/*
	 * Note: Protection between concurrent QP operations to
	 * the doorbell page must be provided at a higher level.
	 */
	co->doorbell->alltoallv.wr_id	     = id;
	co->doorbell->alltoallv.src_ds_array = co->doorbell->alltoallv.src_ds;
	co->doorbell->alltoallv.dst_ds_array = &co->doorbell->alltoallv.src_ds[co->size];
	co->doorbell->alltoallv.flags	     = flags;
	co->doorbell->alltoallv.co_id	     = co->id;

	memcpy((void *)co->doorbell->alltoallv.src_ds_array, src_ds_array,
		sizeof(*src_ds_array) * co->size);

	memcpy((void *)co->doorbell->alltoallv.dst_ds_array, dst_ds_array,
		sizeof(*dst_ds_array) * co->size);

	det_doorbell_ptr2offset(co->doorbell, alltoallv.src_ds_array);
	det_doorbell_ptr2offset(co->doorbell, alltoallv.dst_ds_array);

	co->doorbell->ioctl_cmd = DET_IOC_ALLTOALLV;

	co->doorbell->ring = 1;		/* Ding Dong */
	do err = co->doorbell->ring;
	while (err == 1);		/* Wait for answer. */
	if (err)
		errno = -err;
#else
	alltoallv.wr_id	       = id;
	alltoallv.src_ds_array = src_ds_array;
	alltoallv.dst_ds_array = dst_ds_array;
	alltoallv.flags	       = flags;
	alltoallv.co_id	       = co->id;

	if (co->size <= MAX_IOC_NUM_DS) {
		memcpy(alltoallv.src_ds, src_ds_array,
			sizeof(*src_ds_array) * co->size);
		memcpy(alltoallv.dst_ds, dst_ds_array,
			sizeof(*dst_ds_array) * co->size);
	}

	err = det_verb(co->fd, DET_IOC_ALLTOALLV, &alltoallv);
#endif

	return (err) ? errno : 0;
}
