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

#ifndef __DET_H__
#define __DET_H__

//#define	CONFIG_DET_DOORBELL

#include <net/if.h>	/* for IFNAMESIZ (user-mode) */
#include "det_verbs.h"
#include "det_ioctl.h"


#define DET_DEV			"/dev/det"


struct det_atomic {
	volatile int		mutex;
	volatile int		counter;
};

struct det_device {
	int			fd;
};

struct det_event {
	int			fd;
	int			id;
	det_event_cb		event_cb;
};

struct det_nic {
	int			fd;
	int			id;
	struct det_atomic	nr_events;
};

struct det_pd {
	int			fd;
	int			id;
};

struct det_cq {
	int			fd;
	int			id;
#ifdef	CONFIG_DET_DOORBELL
	struct det_qp		*qp;
	struct det_co		*co;
#endif
	struct det_atomic	nr_events;
};

struct det_qp {
	int			fd;
	int			id;
	struct det_pd		*pd;
	struct det_cq		*sq_cq;
	struct det_cq		*rq_cq;
	struct det_atomic	nr_events;
#ifdef	CONFIG_DET_DOORBELL
	void			*malloc;
	struct det_doorbell	*doorbell;
#endif
};

struct det_mr {
	int			fd;
	int			id;
	struct det_pd		*pd;
};

struct det_mw {
	int			fd;
	int			id;
	struct det_pd		*pd;
};

struct det_co {
	int			fd;
	int			id;
	struct det_pd		*pd;
	struct det_cq		*cq;
	int			size;
	struct det_atomic	nr_events;
#ifdef	CONFIG_DET_DOORBELL
	void			*malloc;
	struct det_doorbell	*doorbell;
#endif
};

#endif /* __DET_H__ */

