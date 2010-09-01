/*
 * Copyright (c) 2005 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id: $
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/user.h>
#include <errno.h>

#include <det/det.h>

/* definitions */
#define SERVER_CONN_QUAL    45248
#define EVENT_TIMEOUT       (1000*1000*5)
#define CONN_TIMEOUT        (1000*1000*10)
#define RDMA_BUFFER_SIZE    64
#define MAX_RDMA_RD         4
#ifndef DET_DEVICE
#define DET_DEVICE          "eth2"
#endif


/* timers */
struct {
	double total;
	double dev_open;
	double nic_open;
	double modqp;
	double reg;
	double unreg;
	double pdc;
	double pdd;
	double eventc;
	double eventd;
	double cqc;
	double cqd;
	double qpc;
	double qpd;
	double rdma_wr;
	double rdma_rd_total;
	double one_way;
	double send_burst;
	double nic_close;
	double dev_close;
} time;

struct connect_info {
	struct det_qp_attr	qp_attr;
	void			*sbuf;
	net32_t			sbuf_rkey;
	void			*rbuf;
	net32_t			rbuf_rkey;
};

/* Global DET vars */
static struct det_device	detdev;
static struct det_nic		nic;
static struct det_pd		pd;
static struct det_event		send_event;
static struct det_event		recv_event;
static struct det_cq		send_cq;
static struct det_cq		recv_cq;
static struct det_qp		qp;
static struct det_nic_attr	nic_attr;
static struct det_cq_attr	cq_attr;
static struct det_qp_attr	qp_attr;
static struct det_mr		send_mr;
static struct det_mr		recv_mr;
static net32_t			send_lkey;
static net32_t			recv_lkey;
static net32_t			send_rkey;
static net32_t			recv_rkey;
static struct connect_info	remote_info;
static char			*rbuf = NULL;
static char			*sbuf = NULL;
static int			sock, sock_listen;

/* defaults */
static int burst = 1000;
static int server = 1;
static int bidirectional = 1;
static int verbose = 0;
static int polling = 0;
static int poll_cnt = 0;
static int snd_poll_cnt = 0;
static int wr_poll_cnt = 0;
static int rd_poll_cnt = 0;
static int buf_len = RDMA_BUFFER_SIZE;
static int recv_msg_index = 0;
static int burst_msg_index = 0;
static int pages = 0;
static char *interface = DET_DEVICE;
static char *init_string = "bla bla bla bla\n";
static char *hostname = NULL;

/* forward references */
int send_msg(void *data, __u32 size, __u32 lkey, __u64 id, int flags);
int register_rdma_memory(void);
int unregister_rdma_memory(void);
int destroy_events(void);
int do_burst_rdma_write(void);
int do_burst_rdma_read(void);
int do_ping_pong_msg(void);
int do_burst_send_msg(void);
void do_connect(char *host, struct det_qp *qp, struct det_qp_attr *attr);
void do_close(void);
void print_nic_attr(struct det_nic_attr*);
void print_usage(char *);

/* macros and inlines */
#define min(x, y)  ((x) > (y) ? (y) : (x))

#define LOGPRINTF(_format, _aa...) \
       if (verbose)               \
           printf(_format, ##_aa)

#define TIME(cnt, ret, func) \
	do { \
		double start = get_time(); \
		ret = func; \
		time.cnt += ((get_time() - start) * 1.0e6); \
	} while(0)

static inline double get_time()
{
	struct timeval tp;

	gettimeofday(&tp, NULL);
	return ((double) tp.tv_sec + (double) tp.tv_usec * 1e-6);
}

static inline int
collect_wc(struct det_cq *cq,
	      struct det_event *event,
	      struct det_wc *wc,
	      unsigned long timeout,
	      int *poll_count)
{
	struct timeval t, *tp = NULL;
	unsigned long expire;
	__u32 num_wc;
	int i, ret;

	if (polling) {
		/* do quick spin before messing with the overhead of time */
		for (i = 0; i < 50; i++) {
			num_wc = 1;
			if (!det_poll_cq(cq, &num_wc, wc))
				return 0;
			if (poll_count)
				(*poll_count)++;
		}

		if (timeout != DET_NO_TIMEOUT) {
			tp = &t;
			gettimeofday(&t, NULL);
			expire = (tp->tv_sec * 1000000) + tp->tv_usec + timeout;
		}

		do {
			for (i = 0; i < 5000; i++) {
				num_wc = 1;
				ret = det_poll_cq(cq, &num_wc, wc);
				if (!ret)
					break;
				if (poll_count)
					(*poll_count)++;
			}
			if (!tp)
				continue;

			gettimeofday(tp, NULL);
			if ((tp->tv_sec * 1000000) + tp->tv_usec > expire)
				ret = ETIME;

		} while (ret == EAGAIN);
		return ret;
	}

	/*
	 *  Since waiting is pretty heavy, a quality implementation would do
	 *  a pre-wait spin poll here.  But, we want to measure the cost of
	 *  of doing a wait, so we won't.
	 */
#ifdef QUALITY_WC_COLLECTION
	for (i = 0; i < 50; i++) {
		num_wc = 1;
		if (!det_poll_cq(cq, &num_wc, wc))
			return 0;
	}
#endif

	/*
	 *  It's important to understand that WQ events are only generated
	 *  at the time a WQ entry is added to the CQ *AND* the CQ is armed.
	 *  Arming the CQ when WQ entries are already present *WILL NOT*
	 *  generate an event for those entries.
	 *
	 *  To prevent races, arm the CQ then poll it to be sure there isn't
	 *  a completion already waiting.  If there is, cool.  If not, we are 
	 *  now guaranteed to wake when the next completion is added.  The side
	 *  effect of detecting the race is an event will be waiting on the
	 *  event queue which means we will immediately wake on the next wait
	 *  with nothing in CQ.  So, we just wait again.
	 */

	ret = det_arm_cq(cq, DET_CQ_THRESHOLD, 1);
	if (ret)
		return ret;

	num_wc = 1;
	ret = det_poll_cq(cq, &num_wc, wc);
	while ((ret == EAGAIN) || (ret == EINTR)) {
		ret = det_wait_on_event(event, timeout);
		if (ret)
			continue;
		num_wc = 1;
		ret = det_poll_cq(cq, &num_wc, wc);
		if (!ret)
			break;
		/*
		 *  Must re-arm before next wait.
		 *  Don't pollute ret - it worked coming in
		 *  so we'll assume it will work now
		 */
		(void)det_arm_cq(cq, DET_CQ_THRESHOLD, 1);
	}
	return ret;
}

/*
 *  It all begins here....
 */
main(int argc, char **argv)
{
	struct det_qp_create	qp_create;
	int ret, i, c;

	/* parse arguments */
	while ((c = getopt(argc, argv, "swpuvb:B:h:i:?")) != -1) {
		switch (c) {
		case 's':
			server = 1;
			break;
		case 'h':
			server = 0;
			hostname = optarg;
			break;
		case 'i':
			interface = optarg;
			break;
		case 'w':
			polling = 0;
			printf("Wait/block for event\n");
			break;
		case 'p':
			polling = 1;
			printf("Polling for events\n");
			break;
		case 'u':
			bidirectional = 0;
			break;
		case 'B':
			burst = strtol(optarg, NULL, 0);
			break;
		case 'b':
			buf_len = strtol(optarg, NULL, 0);
			break;
		case 'v':
			verbose = 1;
			printf("Verbose\n");
			break;
		case '?':
		default:
			print_usage(*argv);
			exit(1);
		}
	}

	printf("Running as %s on %s\n", server ? "server" : "client", interface);

	/* allocate send and receive buffers */
	if (((rbuf = malloc(buf_len * (burst+1))) == NULL) ||
	    ((sbuf = malloc(buf_len * (burst+1))) == NULL)) {
		perror("malloc");
		exit(1);
	}

	memset(&time, sizeof(time), 0);
	LOGPRINTF("Allocated RDMA buffers (r:%p,s:%p) len %d \n", rbuf,
		  sbuf, buf_len);

	/* open the general DET device */
	LOGPRINTF("Open DET\n");
	TIME( dev_open, ret,
	det_open(&detdev));
	if (ret) {
		perror("det_open");
		exit(1);
	}
	LOGPRINTF("DET Opened\n");

	/* create an send/receve events */
	LOGPRINTF("Create event\n");
	TIME( eventc, ret,
	det_create_event(&detdev, NULL, &send_event));
	if (ret) {
		perror("det_create_event send");
		exit(1);
	}
	ret = det_create_event(&detdev, NULL, &recv_event);
	if (ret) {
		perror("det_create_event recv");
		exit(1);
	}
	LOGPRINTF("Events created: send_event=%p recv_event=%p\n",
		  &send_event, &recv_event);

	/* open a nic interface */
	LOGPRINTF("Open NIC\n");
	TIME( nic_open, ret,
	det_open_nic(&detdev, interface, &send_event, &nic));
	if (ret) {
		perror("det_open_nic");
		exit(1);
	}
	LOGPRINTF("NIC Opened\n");

	/* get and display NIC attributes */
	if (verbose) {
		ret = det_query_nic(&nic, &nic_attr);
		if (ret) {
			perror("det_open_nic");
			exit(1);
		}
		print_nic_attr(&nic_attr);
	}

	/* create Protection Domain */
	LOGPRINTF("Create Protection Domain\n");
	TIME( pdc, ret,
	det_alloc_pd(&nic, &pd));
	if (ret) {
		perror("det_alloc_pd");
		exit(1);
	}
	LOGPRINTF("Protection Domain Created\n");

	/* create CQ */
	LOGPRINTF("Create CQs\n");
	TIME( cqc, ret,
	det_create_cq(&nic, burst + 1, &send_event, &cq_attr, &send_cq));
	if (ret) {
		perror("det_create_cq send");
		exit(1);
	}
	ret = det_create_cq(&nic, burst + 1, &recv_event, &cq_attr, &recv_cq);
	if (ret) {
		perror("det_create_cq receive");
		exit(1);
	}
	LOGPRINTF("CQs created: send_cq=%p recv_cq=%p\n", &send_cq, &recv_cq);

	/* create QP */
	qp_create.sq_cq	  = &send_cq;
	qp_create.rq_cq	  = &recv_cq;
	qp_create.sq_size = burst + 1;
	qp_create.rq_size = burst + 1;
	qp_create.sq_sges = 1;
	qp_create.rq_sges = 1;
	qp_create.max_or  = MAX_RDMA_RD;
	qp_create.max_ir  = MAX_RDMA_RD;

	LOGPRINTF("Create QP\n");
	TIME( qpc, ret,
	det_create_qp(&pd, &qp_create, &qp_attr, &qp));
	if (ret) {
		perror("det_create_qp");
		exit(1);
	}
	LOGPRINTF("QP created\n");

	/* Register memory */
	LOGPRINTF("Register RDMA memory\n");
	ret = register_rdma_memory();
	if (ret)
		exit(1);

	LOGPRINTF("Register RDMA memory done\n");
	/* Get connection information */
	LOGPRINTF("Waiting to connect\n");
	do_connect(hostname, &qp, &qp_attr);
	printf("CONNECTED\n");

       /*********** burst RDMA write data *************/
	if (server && !bidirectional) {
		printf("RDMA write skipped\n");
		goto skip_rdma_write;
	}
	printf("RDMA write start....  ");
	fflush(stdout);
	ret = do_burst_rdma_write();
	if (ret) {
		printf("ERROR %s\n", strerror(ret));
		exit(1);
	}
	printf("complete\n");

skip_rdma_write:
       /*********** burst RDMA read data *************/
	if (server && !bidirectional) {
		printf("RDMA read skipped\n");
		goto skip_rdma_read;
	}
	printf("RDMA Read start....   ");
	fflush(stdout);
	ret = do_burst_rdma_read();
	if (ret) {
		printf("ERROR %s\n", strerror(ret));
		exit(1);
	}
	printf("complete\n");

skip_rdma_read:
       /*********** PING PING messages ************/
	printf("Ping Pong start....   ");
	fflush(stdout);
	ret = do_ping_pong_msg();
	if (ret) {
		printf("ERROR %s\n", strerror(ret));
		exit(1);
	}
	printf("complete\n");

       /*********** burst Send messages - must run last ************/
	if (server && !bidirectional)
		printf("burst Send skip....   ");
	else	
		printf("Send start....        ");
	fflush(stdout);
	ret = do_burst_send_msg();
	if (ret) {
		printf("ERROR %s\n", strerror(ret));
		exit(1);
	}
	printf("complete\n");

	/* do graceful clean up */

	do_close();/* this acts like a barrier so we close at the same time */

	LOGPRINTF("Unregister memory\n");
	ret = unregister_rdma_memory();
	if (ret)
		exit(1);
	LOGPRINTF("Memory Unregistered\n");

	/* free QP */
	LOGPRINTF("Destroy QP\n");
	TIME( qpd, ret,
	det_destroy_qp(&qp));
	if (ret) {
		perror("det_destroy_qp");
		exit(1);
	}
	LOGPRINTF("QP Destroyed\n");

	/* free CQ */
	LOGPRINTF("destroy CQs\n");
	TIME( cqd, ret,
	det_destroy_cq(&recv_cq));
	if (ret) {
		perror("det_destroy_cq recv");
		exit(1);
	}
	ret = det_destroy_cq(&send_cq);
	if (ret) {
		perror("det_destroy_cq send");
		exit(1);
	}
	LOGPRINTF("CQs destroyed\n");


	/* Free protection domain */
	LOGPRINTF("Freeing PD\n");
	TIME( pdd, ret,
	det_dealloc_pd(&pd));
	if (ret) {
		perror("det_dealloc_pd");
		exit(1);
	}
	LOGPRINTF("PD Freed\n");

	/* close the NIC */
	LOGPRINTF("Close NIC Interface\n");
	TIME( nic_close, ret,
	det_close_nic(&nic));
	if (ret) {
		perror("det_close_nic");
		exit(1);
	}
	LOGPRINTF("NIC Closed\n");

	/* destroy event */
	LOGPRINTF("destroy events\n");
	TIME( eventd, ret,
	det_destroy_event(&send_event));
	if (ret) {
		perror("det_destroy_event");
		exit(1);
	}
	ret = det_destroy_event(&recv_event);
	if (ret) {
		perror("det_destroy_event");
		exit(1);
	}
	LOGPRINTF("Event Destroyed\n");

	/* close the DET device */
	LOGPRINTF("Closing DET device\n");
	TIME( dev_close, ret,
	det_close(&detdev));
	if (ret) {
		perror("det_close");
		exit(1);
	}
	LOGPRINTF("DET Closed\n");

	/*
	 *  Print the results
	 */
	printf("\nDET Test Complete %d iterations for buffer size %d\n\n",
	       burst, buf_len);
	printf
	    ("Ping Pong one way: %7.2lf usec per msg, %7.2lf MB/s, %7.2lf Mb/s, pc=%d (total %d)\n",
	     time.one_way / burst,
	     (burst * buf_len) / time.one_way,
	     ((burst * buf_len) / time.one_way) * 8,
	     poll_cnt / burst, poll_cnt);
	if (server && !bidirectional)
		goto skip_burst_stats;
	printf
	    ("Burst Send message:%7.2lf usec per msg, %7.2lf MB/s, %7.2lf Mb/s, pc=%d (total %d)\n",
	     time.send_burst / burst,
	     (burst * buf_len) / time.send_burst,
	     ((burst * buf_len) / time.send_burst) * 8,
	     snd_poll_cnt / burst, snd_poll_cnt);
	printf
	    ("Burst RDMA write:  %7.2lf usec per msg, %7.2lf MB/s, %7.2lf Mb/s, pc=%d (total %d)\n",
	     time.rdma_wr / burst,
	     (burst * buf_len) / time.rdma_wr,
	     ((burst * buf_len) / time.rdma_wr) * 8,
	     wr_poll_cnt / burst, wr_poll_cnt );
	printf
	    ("Burst RDMA read:   %7.2lf usec per msg, %7.2lf MB/s, %7.2lf Mb/s, pc=%d (total %d)\n",
	     time.rdma_rd_total/burst,
	     (burst * buf_len) / time.rdma_rd_total,
	     ((burst * buf_len) / time.rdma_rd_total) * 8,
	     rd_poll_cnt / burst, rd_poll_cnt);

skip_burst_stats:
	printf("dev open:    %10.2lf usec\n", time.dev_open);
	printf("dev close:   %10.2lf usec\n", time.dev_close);
	printf("nic open:    %10.2lf usec\n", time.nic_open);
	printf("nic close:   %10.2lf usec\n", time.nic_close);
	printf("PD create:   %10.2lf usec\n", time.pdc);
	printf("PD free:     %10.2lf usec\n", time.pdd);
	printf("MEM reg:     %10.2lf usec %d pages at%6.2lf per-page\n",
	       time.reg, pages, time.reg / pages);
	printf("MEM unreg:   %10.2lf usec %d pages at%6.2lf per-page\n",
		time.unreg, pages, time.unreg / pages);
	printf("Event create:%10.2lf usec\n", time.eventc);
	printf("Event free:  %10.2lf usec\n", time.eventd);
	printf("QP create:   %10.2lf usec\n", time.qpc);
	printf("QP free:     %10.2lf usec\n", time.qpd);
	printf("CQ create:   %10.2lf usec\n", time.cqc);
	printf("CQ free:     %10.2lf usec\n", time.cqd);
	printf("Mod QP:      %10.2lf usec\n", time.modqp);

	/* free rdma buffers */
	free(rbuf);
	free(sbuf);
}

int send_msg(void *data, __u32 size, __u32 lkey, __u64 id, int flags)
{
	struct det_local_ds ds;
	struct det_wc wc;
	int ret;

	ds.vaddr  = (unsigned long)data;
	ds.length = size;
	ds.l_key  = lkey;

	ret = det_send(&qp, id, &ds, 1, flags, 0);
	if (ret) {
		perror("det_send");
		return ret;
	}

	if (!(flags & DET_WR_SURPRESSED)) {
		ret = collect_wc(&send_cq, &send_event, &wc, EVENT_TIMEOUT, NULL);
		if (!verbose || ret)
			return (ret);

		if (wc.status != DET_WS_SUCCESS) {
			printf("Bad work completion status: %d\n", wc.status);
			return (-1);
		}
		if (wc.type != DET_WC_SEND) {
			printf("Unexpected completion type: %d\n", wc.type);
			return (-1);
		}
		if (wc.id != id) {
			printf("Unexpected completion id: exp %ld got %ld\n",
				id, wc.id);
			return (-1);
		}
	}

	return (ret); 
}


int do_burst_rdma_write()
{
	struct det_local_ds ds;
	struct det_wc wc;
	double start;
	int i, ret;

	if (server)
		strcpy((char *) sbuf, "server written data...");
	else
		strcpy((char *) sbuf, "client written data...");

	ds.vaddr = (unsigned long)sbuf;
	ds.length = buf_len;
	ds.l_key = send_lkey;

	start = get_time();
	for (i = 0; i < burst; i++) {
		ret = det_write(&qp,
				0x5555,
				&ds,
				1,
				(net64_t)remote_info.rbuf,
				remote_info.rbuf_rkey,
				i == burst - 1 ? 0 : DET_WR_SURPRESSED,
				0);
		if (ret) {
			perror("det_write");
			return (ret);
		}
	}

	/* last rdma write request will generate a completion - collect it */
	LOGPRINTF("waiting for RDMA write completion event\n");

	ret = collect_wc(&send_cq, &send_event, &wc, EVENT_TIMEOUT, &wr_poll_cnt);
	time.rdma_wr = ((get_time() - start) * 1.0e6);

	if (!ret)
		LOGPRINTF("RDMA write completion event generated\n");

	return (ret);
}

int do_burst_rdma_read()
{
	struct det_local_ds ds;
	struct det_wc wc;
	double start;
	int i, ret;

	/* setup rdma read buffer to initial string to be overwritten */
	strcpy((char *) sbuf, init_string);

	if (server)
		strcpy((char *) rbuf, "server read data...");
	else
		strcpy((char *) rbuf, "client read data...");

	ds.vaddr = (unsigned long)sbuf;
	ds.length = buf_len;
	ds.l_key = send_lkey;

	start = get_time();
	for (i = 0; i < burst; i++) {
		ret = det_read(&qp,
			       0x9999,
			       &ds,
			       1,
			       (net64_t)remote_info.rbuf, remote_info.rbuf_rkey,
			       i == burst - 1 ? 0 : DET_WR_SURPRESSED);
		if (ret) {
			perror("det_read");
			return (ret);
		}
	}

	LOGPRINTF("waiting for RDMA read completion event\n");

	ret = collect_wc(&send_cq, &send_event, &wc, EVENT_TIMEOUT, &rd_poll_cnt);
	time.rdma_rd_total = (get_time() - start) * 1.0e6;

	if (ret)
		return (ret);

	LOGPRINTF("RDMA read completion event generated\n");

	return (ret);
}

int do_ping_pong_msg()
{
	struct det_local_ds ds;
	struct det_wc wc;
	double start;
	char *snd_buf;
	char *rcv_buf;
	char expected;
	int i, ret;

	snd_buf = sbuf;
	rcv_buf = rbuf;

	/* pre-post all buffers */
	for (i = 0; i < burst + 1; i++) {
		ds.vaddr = (unsigned long)rcv_buf;
		ds.length = buf_len;
		ds.l_key = recv_lkey;

		ret = det_recv(&qp, i, &ds, 1);
		if (ret) {
			perror("ping pong det_recv");
			return (ret);
		}

		/* next buffer */
		rcv_buf += buf_len;
	}

	/* try to make sure the server is ready since it receives first */
	if (!server)
		sleep(2);

	/* Initialize recv_buf and index to beginning */
	rcv_buf = rbuf;
	burst_msg_index = 0;

	/* client ping 0x55, server pong 0xAA in first byte */
	start = get_time();
	for (i = 0; i < burst + 1; i++) {
		/* walk the send and recv buffers */
		if (!server) {
			*snd_buf = 0x55;
			ret = send_msg(snd_buf,
				       buf_len,
				       send_lkey,
				       i,
				       i == burst ? 0 : DET_WR_SURPRESSED);

			if (ret) {
				perror("ping_pong send_msg");
				return (ret);
			}
		}

		/* Wait for recv message */
		ret = collect_wc(&recv_cq, &recv_event, &wc, EVENT_TIMEOUT, &poll_cnt);
		if (ret)
			return (ret);

		/* validate event number and status */
		if (wc.status != DET_WS_SUCCESS) {
			fprintf(stderr,
				"Error unexpected status : %d\n",
				wc.status);
			return (wc.status);
		}
		if (wc.length != buf_len) {
			fprintf(stderr,
				"Error unexpected length : %d\n",
				wc.length);
			return (-1);
		}

		expected = server ? 0x55 : 0xaa;
		if (*rcv_buf != expected) {
			printf("ERROR: %s RCV buffer %p contains: 0x%x expected %d len=%d\n",
				server ? "SERVER:" : "CLIENT:",
				rcv_buf, (unsigned char)*rcv_buf,
				(unsigned char)expected, buf_len);
			return (-1);
		}

		burst_msg_index++;

		/* start timer after first message arrives on server */
		if (i == 0) {
			start = get_time();
		}

		/* If server, change data and send it back to client */
		if (server) {
			*snd_buf = 0xaa;
			ret = send_msg(snd_buf,
				       buf_len,
				       send_lkey,
				       i,
				       i == burst ? 0 : DET_WR_SURPRESSED);

			if (ret) {
				perror("ping pong send_msg");
				return (ret);
			}
		}

		/* next buffers */
		rcv_buf += buf_len;
		snd_buf += buf_len;
	}
	time.one_way = ((get_time() - start) * 1.0e6) / 2;

	return (ret);
}

int do_burst_send_msg()
{
	struct det_local_ds ds;
	struct det_wc wc;
	double start;
	char *snd_buf;
	char *rcv_buf;
	int i, ret;

	snd_buf = sbuf;
	rcv_buf = rbuf;

	/* pre-post all buffers */
	for (i = 0; i < burst; i++) {
		ds.vaddr = (unsigned long)rcv_buf;
		ds.length = buf_len;
		ds.l_key = recv_lkey;

		ret = det_recv(&qp, i, &ds, 1);
		if (ret) {
			perror("burst send det_recv");
			return (ret);
		}

		/* next buffer */
		rcv_buf += buf_len;
	}

	if (server && !bidirectional)
		goto collect_receives;

	/* try to make sure everyone gets here */
	sleep(2);

	/* send all messages */
	start = get_time();
	for (i = 0; i < burst; i++) {
		ret = send_msg(snd_buf,
			       buf_len,
			       send_lkey,
			       i,
			       i == burst - 1 ? 0 : DET_WR_SURPRESSED);

		if (ret) {
			perror("burst send send_msg");
			return (ret);
		}
		snd_buf += buf_len;
	}
	time.send_burst += ((get_time() - start) * 1.0e6);

	/* if we're not doing bidirectional test, receives won't be coming */
	if (!server && !bidirectional)
		return (0);

collect_receives:
	/* collect all the receives - could time out if server is passive */
	for (i = 0; i < burst; i++) {
		/* use wait to dequeue */
		ret = collect_wc(&recv_cq, &recv_event, &wc, EVENT_TIMEOUT, &snd_poll_cnt);
		if (ret)
			return (ret);

		/* validate event number and status */
		if (wc.status != DET_WS_SUCCESS) {
			fprintf(stderr,
				"Error unexpected status : %d\n",
				wc.status);
			return (wc.status);
		}
		if (wc.length != buf_len) {
			fprintf(stderr,
				"Error unexpected length : %d\n",
				wc.length);
			return (-1);
		}
	}

	return (ret);
}

/* Register RDMA Receive buffer */
int register_rdma_memory(void)
{
	struct det_mr_reg region;
	int ret;
	int total_len = buf_len * (burst + 1);

	/* Register RDMA Receive buffer */
	region.vaddr = (unsigned long)rbuf;
	region.length = total_len;
	region.access = DET_AC_LOCAL_READ  | DET_AC_LOCAL_WRITE |
			DET_AC_REMOTE_READ | DET_AC_REMOTE_WRITE;

	TIME( reg, ret,
	det_reg_mr(&pd, &region, &recv_lkey, &recv_rkey, &recv_mr));
	if (ret) {
		perror("det_reg_mr - recv");
		return (ret);
	}
	LOGPRINTF("Registered Receive RDMA Buffer %p\n", rbuf);

	pages += (total_len / PAGE_SIZE) + (total_len % PAGE_SIZE ? 1:0);

	/* Register RDMA Send buffer - same attributes as recive */
	region.vaddr = (unsigned long)sbuf;

	TIME( reg, ret,
	det_reg_mr(&pd, &region, &send_lkey, &send_rkey, &send_mr));
	if (ret) {
		perror("det_reg_mr - send");
		return (ret);
	}
	LOGPRINTF("Registered Send RDMA Buffer %p\n", sbuf);

	pages += (total_len / PAGE_SIZE) + (total_len % PAGE_SIZE ? 1:0);

	return ret;
}

/*
 * Unregister RDMA memory
 */
int unregister_rdma_memory(void)
{
	int ret;

	/* Unregister Recv Buffer */
	LOGPRINTF("Unregister Recv Buffer\n");
	TIME( unreg, ret,
	det_dereg_mr(&recv_mr));
	if (ret) {
		perror("det_dereg_mr - recv");
		return (ret);
	}
	LOGPRINTF("Recv Buffer Unregistered\n");

	/* Unregister Send Buffer */
	LOGPRINTF("Unregister Send Buffer\n");
	TIME( unreg, ret,
	det_dereg_mr(&send_mr));
	if (ret) {
		perror("det_dereg_mr - send");
		return (ret);
	}
	LOGPRINTF("Send Buffer Unregistered\n");

	return ret;
}

void do_connect(char *host, struct det_qp *qp, struct det_qp_attr *qp_attr)
{
	struct det_qp_mod	qp_mod;
	struct connect_info	local;
	struct sockaddr_in	addr;
	struct hostent		*hostent;
	char			barrier[4];
	int			ret, opt = 1;

	/*
	 *  Memory keys and addresses would normally be done through a
	 *  send/recv message exchange as opposed to in connect data, but
	 *  for this test, it's easier just to do it here.
	 */
	local.qp_attr   = *qp_attr;
	local.sbuf      = sbuf;
	local.sbuf_rkey = send_rkey;
	local.rbuf      = rbuf;
	local.rbuf_rkey = recv_rkey;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(1);
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		perror("setsockopt");
		exit(1);
	}
	memset(&addr, 0, sizeof(addr));
	if (server) {
		addr.sin_family = AF_INET;
		addr.sin_port   = htons(SERVER_CONN_QUAL);
		if (bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
			perror("bind");
			exit(1);
		}

		if (listen(sock, 1)) {
			perror("listen");
			exit(1);
		}
		sock_listen = sock;
		sock = accept(sock, NULL, 0);
		if (sock < 0) {
			perror("accept");
			exit(1);
		}
		if (send(sock, &local, sizeof(local), 0) <= 0) {
			perror("send");
			exit(1);
		}
		if (recv(sock, &remote_info, sizeof(local), 0) <= 0) {
			perror("recv");
			exit(1);
		}
	} else {
		hostent = gethostbyname(host);
		if (!hostent) {
			printf("invalid hostname: %s\n", host);
			exit(1);
		}
		memcpy(&addr.sin_addr.s_addr, hostent->h_addr, hostent->h_length);
		addr.sin_family = hostent->h_addrtype;
		addr.sin_port   = htons(SERVER_CONN_QUAL);

		if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
			perror("connect");
			exit(1);
		}
		if (recv(sock, &remote_info, sizeof(local), 0) <= 0) {
			perror("recv");
			exit(1);
		}
		if (send(sock, &local, sizeof(local), 0) <= 0) {
			perror("send");
			exit(1);
		}
	}

	if (verbose) {
		printf( "rem info: qp %d mac %02x:%02x:%02x:%02x:%02x:%02x "
			"sbuf_rkey %d rbuf_rkey %d sbuf %p rbuf %p\n",
			remote_info.qp_attr.local_qp_num,
			remote_info.qp_attr.local_mac.addr[0],
			remote_info.qp_attr.local_mac.addr[1],
			remote_info.qp_attr.local_mac.addr[2],
			remote_info.qp_attr.local_mac.addr[3],
			remote_info.qp_attr.local_mac.addr[4],
			remote_info.qp_attr.local_mac.addr[5],
			remote_info.sbuf_rkey,
			remote_info.rbuf_rkey,
			remote_info.sbuf,
			remote_info.rbuf);
		printf( "loc info: qp %d mac %02x:%02x:%02x:%02x:%02x:%02x "
			"sbuf_rkey %d rbuf_rkey %d sbuf %p rbuf %p\n",
			local.qp_attr.local_qp_num,
			local.qp_attr.local_mac.addr[0],
			local.qp_attr.local_mac.addr[1],
			local.qp_attr.local_mac.addr[2],
			local.qp_attr.local_mac.addr[3],
			local.qp_attr.local_mac.addr[4],
			local.qp_attr.local_mac.addr[5],
			local.sbuf_rkey,
			local.rbuf_rkey,
			local.sbuf,
			local.rbuf);
	}

	qp_mod.flags	     = DET_QP_MOD_STATE_FLAG | DET_QP_MOD_MAX_OR_FLAG;
	qp_mod.next_state    = DET_QP_CONNECTED;
	qp_mod.sq_size	     = 0;
	qp_mod.rq_size	     = 0;
	qp_mod.max_or	     = min(qp_attr->max_or, remote_info.qp_attr.max_ir);
	qp_mod.max_ir	     = 0;
	qp_mod.remote_qp_num = remote_info.qp_attr.local_qp_num;
	qp_mod.remote_mac    = remote_info.qp_attr.local_mac;

	LOGPRINTF("Modify QP\n");
	TIME( modqp, ret,
	det_modify_qp(qp, &qp_mod, qp_attr));
	if (ret) {
		perror("det_modify_qp");
		exit(1);
	}
	LOGPRINTF("QP modified\n");

	/*
	 *  We shouldn't start using the QP until we know the other side has
	 *  finished connecting.
	 */
	if (send(sock, barrier, sizeof(barrier), 0) <= 0) {
		perror("barrier send");
		exit(1);
	}
	if (recv(sock, &barrier, sizeof(barrier), 0) <= 0) {
		perror("barrier recv");
		exit(1);
	}
}

void do_close()
{
	char buf[4];

	printf("Waiting for close\n");
	if (send(sock, buf, sizeof(buf), 0) <= 0)
		perror("close send");
	else if (recv(sock, &buf, sizeof(buf), 0) <= 0) 
		perror("close receive");

	close(sock);
	if (server)
		close(sock_listen);
}

void print_nic_attr(struct det_nic_attr *attr)
{
	printf("DET NIC attributes:\n");
	printf("\tifname \"%s\"\n", attr->ifname);
	printf("\tvendor_id 0x%0x, device_id 0x%0x\n",
		attr->vendor_id, attr->device_id);
	printf("\thw_rev 0x%0x, fw_rev 0x%0x\n",
		attr->hw_rev, attr->fw_rev);
	printf("\tmin_pds 0x%0x, max_pds 0x%0x\n",
		attr->min_pds, attr->max_pds);
	printf("\tmin_mrs 0x%0x, max_mrs 0x%0x\n",
		attr->min_mrs, attr->max_mrs);
	printf("\tmin_mr_size 0x%0x, max_mr_size 0x%0x\n",
		attr->min_mr_size, attr->max_mr_size);
	printf("\tmin_mws 0x%0x, max_mws 0x%0x\n",
		attr->min_mws, attr->max_mws);
	printf("\tmin_cqs 0x%0x, max_cqs 0x%0x\n",
		attr->min_cqs, attr->max_cqs);
	printf("\tmin_cq_size 0x%0x, max_cq_size 0x%0x\n",
		attr->min_cq_size, attr->max_cq_size);
	printf("\tcqe_size 0x%0x\n",
		attr->cqe_size);
	printf("\tmin_qps 0x%0x, max_qps 0x%0x\n",
		attr->min_qps, attr->max_qps);
	printf("\tmin_sq_size 0x%0x, max_sq_size 0x%0x\n",
		attr->min_sq_size, attr->max_sq_size);
	printf("\tmin_rq_size 0x%0x, max_rq_size 0x%0x\n",
		attr->min_rq_size, attr->max_rq_size);
	printf("\twqe_size 0x%0x\n",
		attr->wqe_size);
	printf("\tmin_msg_size 0x%0x, max_msg_size 0x%0x\n",
		attr->min_msg_size, attr->max_msg_size);
	printf("\tmin_rdma_size 0x%0x, max_rdma_size 0x%0x\n",
		attr->min_rdma_size, attr->max_rdma_size);
	printf("\tmin_sges 0x%0x, max_sges 0x%0x\n",
		attr->min_sges, attr->max_sges);
	printf("\tsge_size 0x%0x\n",
		attr->sge_size);
	printf("\tmin_or 0x%0x, max_or 0x%0x\n",
		attr->min_or, attr->max_or);
	printf("\tmin_ir 0x%0x, max_ir 0x%0x\n",
		attr->min_ir, attr->max_ir);
	printf("\tmin_cos 0x%0x, max_cos 0x%0x\n",
		attr->min_cos, attr->max_cos);
	printf("\tpage_size 0x%0x\n", attr->page_size);
	printf("\n");
}

void print_usage(char *prog)
{
	printf
	    ("%s: <[-s] | -h servername> [-i interface] [-w] [-p] [-b len] [-B count] [-u] [-v]\n\n",
	     prog);
	printf("-s        run as server (default)\n");
	printf("-h host   server hostname\n");
	printf("-i        DET interface name (\"%s\" default)\n", interface);
	printf("-w        wait/block for event (default)\n");
	printf("-p        poll for event\n");
	printf("-b len    message buf length (%d default)\n", buf_len);
	printf("-B count  burst count, rdma and msgs (%d default)\n", burst);
	printf("-u        unidirectional burst mode (passive server)\n");
	printf("-v        verbose\n");
	printf("\n");
}
