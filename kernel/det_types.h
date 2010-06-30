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

#ifndef __DET_TYPES_H__
#define __DET_TYPES_H__

#include <linux/types.h>
#if !defined(__KERNEL__)
#include <limits.h>
#endif


/*
 * DET structures
 */
struct det_device;
struct det_event;
struct det_nic;
struct det_pd;
struct det_cq;
struct det_qp;
struct det_mr;
struct det_mw;
struct det_co;


/*
 * A shifty little bit macro.
 */
#ifndef	BIT
#define	BIT(x)			(1 << (x))
#endif


/*
 * Defines network byte ordered type values that traverse the wire.
 */
typedef __u16			net16_t;
typedef __u32			net32_t;
typedef __u64			net64_t;

/*
 * The Direct Ethernet Protocol is little-endian.
 */
#if !defined(__KERNEL__)
#if   (__BYTE_ORDER == __LITTLE_ENDIAN)
# define __constant_cpu_to_le16(x)	((__u16)(x))
# define __constant_le16_to_cpu(x)	((__u16)(x))
# define __constant_cpu_to_le32(x)	((__u32)(x))
# define __constant_le32_to_cpu(x)	((__u32)(x))
# define __constant_cpu_to_le64(x)	((__u64)(x))
# define __constant_le64_to_cpu(x)	((__u64)(x))
# define __cpu_to_le16(x)		((__u16)(x))
# define __le16_to_cpu(x)		((__u16)(x))
# define __cpu_to_le32(x)		((__u32)(x))
# define __le32_to_cpu(x)		((__u32)(x))
# define __cpu_to_le64(x)		((__u64)(x))
# define __le64_to_cpu(x)		((__u64)(x))
#elif (__BYTE_ORDER == __BIG_ENDIAN)
# define __constant_cpu_to_le16(x)	__bswap_16(x)
# define __constant_le16_to_cpu(x)	__bswap_16(x)
# define __constant_cpu_to_le32(x)	__bswap_32(x)
# define __constant_le32_to_cpu(x)	__bswap_32(x)
# define __constant_cpu_to_le64(x)	__bswap_64(x)
# define __constant_le64_to_cpu(x)	__bswap_64(x)
# define __cpu_to_le16(x)		__bswap_16(x)
# define __le16_to_cpu(x)		__bswap_16(x)
# define __cpu_to_le32(x)		__bswap_32(x)
# define __le32_to_cpu(x)		__bswap_32(x)
# define __cpu_to_le64(x)		__bswap_64(x)
# define __le64_to_cpu(x)		__bswap_64(x)
#else
# error __BYTE_ORDER is undefined in user mode build
#endif
#endif
#define	CONSTANT_HTON16(x)		__constant_cpu_to_le16(x)
#define	CONSTANT_NTOH16(x)		__constant_le16_to_cpu(x)
#define	CONSTANT_HTON32(x)		__constant_cpu_to_le32(x)
#define	CONSTANT_NTOH32(x)		__constant_le32_to_cpu(x)
#define	CONSTANT_HTON64(x)		__constant_cpu_to_le64(x)
#define	CONSTANT_NTOH64(x)		__constant_le64_to_cpu(x)
#define	HTON16(x)			__cpu_to_le16(x)
#define	NTOH16(x)			__le16_to_cpu(x)
#define	HTON32(x)			__cpu_to_le32(x)
#define	NTOH32(x)			__le32_to_cpu(x)
#define	HTON64(x)			__cpu_to_le64(x)
#define	NTOH64(x)			__le64_to_cpu(x)


/**
 * det_event_code
 * %DET_AE_USER_GENERATED	A user generated event.
 * %DET_AE_CQ_COMPLETION	A completion has occurred on the completion
 *				specified in the event record.  This event
 *				is only delivered to user-mode completion
 *				queues.  Users of kernel-mode completion
 *				queues are called back directly.
 * %DET_AE_NIC_FATAL		A fatal error occurred on the NIC.
 * %DET_AE_NIC_REMOVED		The NIC was disabled or removed from the
 *				system.
 * %DET_AE_DISCONNECT		A connected queue pair was disconnected
 *				normally.
 * %DET_AE_CQ_OVERRUN		The completion queue was overrun.
 * %DET_AE_CQ_FATAL		An error occurred while writing a completion
 *				to the completion queue.
 * %DET_AE_QP_SQ_ERROR		An error occurred while completing a send queue
 *				work request.
 * %DET_AE_QP_RQ_ERROR		An error occurred while completing a receive
 *				queue work request.
 * %DET_AE_QP_DESTROYED		A connected queue pair was disconnected
 *				because a queue pair was destroyed.
 * %DET_AE_QP_ERROR		A connected queue pair was disconnected
 *				because a queue pair entered the error state.
 * %DET_AE_QP_FATAL		Indicates an error occurred that prevents
 *				queue pair operations.
 * %DET_AE_CO_WR_ERROR		An error occurred while completing a collective
 *				work request.
 * %DET_AE_CO_DESTROYED		A collective group was destroyed.
 * %DET_AE_CO_ERROR		A collective group entered the error state.
 * %DET_AE_CO_FATAL		Indicates an error occurred that prevents
 *				collective operations.
 * %DET_AE_INVALID_OPCODE	An invalid protocol opcode was received.
 * %DET_AE_INVALID_LENGTH	The length in protocol header does not match
 *				the actual length received.
 * %DET_AE_INVALID_QP		A queue pair specified in the protocol header
 *				does not match a queue pair at the destination.
 * %DET_AE_INVALID_MSG_ID	The message ID in the protocol header was
 *				invalid.
 * %DET_AE_INVALID_L_KEY	A memory region or memory window key speciifed
 *				in a local data segment scatter-gather list
 *				was invalid.
 * %DET_AE_INVALID_RDMA_KEY	The memory region or memory window key
 *				speciifed in the RDMA operation was invalid.
 * %DET_AE_INVALID_RDMA_ID	The RDMA ID in the protocol header of an RDMA
 *				read response was invalid.
 * %DET_AE_INVALID_ATOMIC_KEY	The memory region or memory window key
 *				speciifed in the atomic operation was invalid.
 * %DET_AE_INVALID_ATOMIC_ID	The atomic ID in the protocol header of an
 *				atomic response was invalid.
 * %DET_AE_MAX_IR_EXCEEDED	The number of inbound RDMA read and atomic
 *				work requests exceeded the maximum currently
 *				allowed by the queue pair.
 * %DET_AE_ACK_TIMEOUT		A acknowledgement was not received from the
 *				remote queue pair within the connection retry
 *				timeout limits.
 * %DET_AE_PROTECTION_VIOLATION	A reference was made to a local memory region
 *				or window with a protection domain that does
 *				not match the protectin domain of the queue
 *				pair.
 * %DET_AE_BOUNDS_VIOLATION	The local scatter-gather list referenced an
 *				address beyond the limits specified for the
 *				memory region or window.  This includes length
 *				errors.  For a bind operation, the memory
 *				window was not wholly contained in the memory
 *				region.
 * %DET_AE_ACCESS_VIOLATION	An attempt was made to read or write a local
 *				memory region or window that did not provide
 *				appropriate access rights.  For a bind
 *				operation, the memory window access rights
 *				were not compatible with the memory region
 *				access rights.
 * %DET_AE_WRAP_ERROR		The length of the operation resulted in a wrap
 *				beyond the maximum machine-supported address.
 *
 * Description:
 *	Event codes indicating the reason an asynchronous event callback was
 *	generated.  Note that some asynchronous events are locally generated;
 *	connected queue pair events may originate either locally or from the
 *	remote queue pair as indicated by the %DET_AE_REMOTE flag.  The
 *	connection is lost when an event occurs on a connected queue pair.
 *
 * See Also:
 *	&struct det_record, det_event_was_local(), det_event_was_remote(),
 *	det_get_event_code()
 **/
enum det_event_code {

	/* Locally Generated Events */

		/* User Generated Event */
		DET_AE_USER_GENERATED	= 0,

		/* User-Mode CQ Completion Event */
		DET_AE_CQ_COMPLETION,

		/* NIC Errors */
		DET_AE_NIC_FATAL,
		DET_AE_NIC_REMOVED,

	/* Local or Remote Generated Events */

		/* Disconnect Event */
		DET_AE_DISCONNECT,

		/* CQ Errors */
		DET_AE_CQ_OVERRUN,
		DET_AE_CQ_FATAL,

		/* QP Errors */
		DET_AE_QP_SQ_ERROR,
		DET_AE_QP_RQ_ERROR,
		DET_AE_QP_DESTROYED,
		DET_AE_QP_ERROR,
		DET_AE_QP_FATAL,

		/* CO Errors - shared with QP, use det_type to differentiate */
		DET_AE_CO_WR_ERROR	= DET_AE_QP_SQ_ERROR,
		DET_AE_CO_DESTROYED	= DET_AE_QP_DESTROYED,
		DET_AE_CO_ERROR		= DET_AE_QP_ERROR,
		DET_AE_CO_FATAL		= DET_AE_QP_FATAL,

		/* Operation Errors */
		DET_AE_INVALID_OPCODE,
		DET_AE_INVALID_LENGTH,
		DET_AE_INVALID_QP,
		DET_AE_INVALID_MSG_ID,
		DET_AE_INVALID_L_KEY,
		DET_AE_INVALID_RDMA_KEY,
		DET_AE_INVALID_RDMA_ID,
		DET_AE_INVALID_ATOMIC_KEY,
		DET_AE_INVALID_ATOMIC_ID,
		DET_AE_MAX_IR_EXCEEDED,
		DET_AE_ACK_TIMEOUT,

		/* Protection Errors */
		DET_AE_PROTECTION_VIOLATION,
		DET_AE_BOUNDS_VIOLATION,
		DET_AE_ACCESS_VIOLATION,
		DET_AE_WRAP_ERROR
};

/**
 * DET_AE_REMOTE
 *
 * Description:
 *	A flag that indicates the connected queue pair event was
 *      generated by the remote queue pair.
 *
 * See Also:
 *	enum det_event_code
 **/
#define	DET_AE_REMOTE	 	BIT(31)

/**
 * DET_AE_MASK
 *
 * Description:
 *	A bit mask provided for clearing the DET_AE_REMOTE flag
 *	from event codes.
 *
 * See Also:
 *	enum det_event_code
 **/
#define	DET_AE_MASK	 	(~DET_AE_REMOTE)

/**
 * det_event_was_local
 * code:	A code that identifies the asynchronous event.
 *
 * Description:
 *	This boolean routine returns true if the event code indicates
 *	that it was generated locally, otherwise, zero is returned.
 *
 * Return Values:
 *	0
 *	The event was generated remotely.
 *
 *	!0
 *	The event was generated locally.
 *
 * See Also:
 *	&struct det_record
 **/
static inline int det_event_was_local(const enum det_event_code code)
{
	return !(code & DET_AE_REMOTE);
}

/**
 * det_event_was_remote
 * code:	A code that identifies the asynchronous event.
 *
 * Description:
 *	This boolean routine returns true if the event code indicates
 *	that it was generated remotely, otherwise, zero is returned.
 *
 * Return Values:
 *	0
 *	The event was generated locally.
 *
 *	!0
 *	The event was generated remotely.
 *
 * See Also:
 *	&struct det_record
 **/
static inline int det_event_was_remote(const enum det_event_code code)
{
	return !det_event_was_local(code);
}

/**
 * det_get_event_code
 * code:	A code that identifies the asynchronous event.
 *
 * Description:
 *	This routine returns the base asynchronous event code.
 *
 * Return Values:
 *	The base asynchronous event code.
 *
 * See Also:
 *	&struct det_record
 **/
static inline enum det_event_code
det_get_event_code(const enum det_event_code code)
{
	return code & DET_AE_MASK;
}


/**
 * det_type
 *
 * Description:
 *	DET resource types.
 *
 * See Also:
 *	&struct det_record
 **/
enum det_type {
	DET_TYPE_UNKNOWN,
	DET_TYPE_EVENT,
	DET_TYPE_NIC,
	DET_TYPE_PD,
	DET_TYPE_CQ,
	DET_TYPE_QP,
	DET_TYPE_MR,
	DET_TYPE_MW,
	DET_TYPE_CO
};


/**
 * det_record
 * @code:	A code that identifies the type of asynchronous event
 *		being reported.
 * @type:	Indicates the type of resource that experienced the
 *		asynchronous event.  This field is set to DET_TYPE_UNKNOWN
 *		for user generated events.
 * @handle:	A handle to the resource for which this event record was
 *		generated.  This handle will match the handle used
 *		during the creation of resource or, for user generated
 *		events, will be the context handle provided by the client
 *		when the event was generated.
 *
 * Description:
 *	Information returned when an asynchronous event occurs on an
 *	allocated resource.  This structure indicates the type of event,
 *	the source of the event.
 *
 * See Also:
 *	det_event_cb()
 **/
struct det_record {
	enum det_event_code		code;
	enum det_type			type;
	void				*handle;
} __attribute__((packed));


/**
 * DET_NO_TIMEOUT
 *
 * Description:
 *	A special value used with the det_wait_on_event() routine for
 *	the number of microseconds to wait for an event to occur.  If
 *	set to %DET_NO_TIMEOUT, the calling thread will block until an
 *	event or error occurs.
 *
 * See Also:
 *	det_wait_on_event()
 **/
#define DET_NO_TIMEOUT			LONG_MAX    /* MAX_SCHEDULE_TIMEOUT */


/**
 * det_attr
 * @timer_period:	The protocol retry timer interval in milliseconds.
 * @ack_timeout:	The maximum time to wait for a protocol acknowledgement
 *			in seconds.
 * @max_window:		The maximum number of outstanding unacknowledged
 *			transmit packets.
 * @max_memory:		The maximum percent of physical memory that may
 *			be pinned by the driver via memory registration,
 *			completion queue, and queue pair creation from all
 *			clients; this does not include the physical memory
 *			required by the driver itself.  The driver attempts
 *			to limit the number of physical memory pages pinned
 *			to this percentage.  In some cases, however, the
 *			actual number of pinned physical memory pages may
 *			be slightly greater than this limit.
 * @page_count:		The number of physical memory pages currently pinned
 *			by the driver via memory registration, completion
 *			queue, and queue pair creation from all clients; this
 *			does not include the physical memory required by the
 *			driver itself.
 *
 * Description:
 *	The attributes of DET.
 *
 * See Also:
 *	det_query()
 **/
struct det_attr {
	__u32				timer_period;
	__u32				ack_timeout;
	__u32				max_window;
	__u32				max_memory;
	__u32				page_count;
} __attribute__((packed));


/**
 * det_mac_addr
 * @addr:	The MAC address of a DET NIC
 * @pad:	Padding bytes for alignment.
 *
 * Description:
 *	This structure defines the MAC address of a DET NIC.
 *
 * See Also:
 *	det_open_nic(), &struct det_nic_attr, &struct det_qp_attr,
 *	&struct det_qp_mod
 **/
struct det_mac_addr {
#	define DET_MAC_ADDR_LEN		6
	__u8				addr[DET_MAC_ADDR_LEN];
	__u16				pad;
} __attribute__((packed));


/**
 * DET IDs and revisions
 *
 * Description:
 *	Intel Corporation vendor ID in IEEE format.
 *	DET device ID for a software emulated DET device.
 *	DET hardware revision for a software emulated DET device.
 *	DET firmware revision for a software emulated DET device.
 *
 * See Also:
 *	det_query_nic()
 **/
#define DET_VENDOR_ID			0x8086	/* Intel Corporation */
#define DET_DEVICE_ID			0
#define DET_HW_REV			0x0001	/* DET_MODULE_VERSION */
#define DET_FW_REV			DET_PROTOCOL_VER


/**
 * det_nic_attr
 * @ifname:		A null-terminated string identifying the NIC interface.
 * @vendor_id:		The device vendor ID in IEEE format.
 * @device_id:		A number assigned by the vendor to identify the
 *			device type.
 * @hw_rev:		A number assigned by the vendor to identify the
 *			device hardware revision.
 * @fw_rev:		A number assigned by the vendor to identify the
 *			device firmware revision.
 * @min_pds:		The minimum number of protection domains guaranteed
 *			to be supported by this NIC.
 * @max_pds:		The maximum number of protection domains that may be
 *			supported by this NIC.
 * @min_mrs:		The minimum number of memory regions guaranteed
 *			to be supported by this NIC.
 * @max_mrs:		The maximum number of memory regions that may be
 *			supported by this NIC.
 * @min_mr_size:	The smallest contiguous block of memory that may be
 *			registered, specified in bytes.
 * @max_mr_size:	The largest contiguous block of memory that may be
 *			registered, specified in bytes.
 * @min_mws:		The minimum number of memory windows guaranteed
 *			to be supported by this NIC.
 * @max_mws:		The maximum number of memory windows that may be
 *			supported by this NIC.
 * @min_cqs:		The minimum number of completion queues guaranteed
 *			to be supported by this NIC.
 * @max_cqs:		The maximum number of completion queues that may be
 *			supported by this NIC.
 * @min_cq_size:	The minimum number of entries in each completion
 *			queue guaranteed to be supported by this NIC.
 * @max_cq_size:	The maximum number of entries in each completion
 *			queue that may be supported by this NIC.
 * @cqe_size:		The size of each completion queue entry in bytes.
 * @min_qps:		The minimum number of queue pairs guaranteed to be
 *			supported by this NIC.
 * @max_qps:		The maximum number of queue pairs that may be
 *			supported by this NIC.
 * @min_sq_size:	The guaranteed minimum number work requests that
 *			may be outstanding on any send queue supported by
 *			this NIC.
 * @max_sq_size:	The maximum number of work requests that may be
 *			outstanding on any send queue supported by this NIC.
 * @min_rq_size:	The guaranteed minimum number work requests that
 *			may be outstanding on any receive queue supported
 *			by this NIC.
 * @max_rq_size:	The maximum number of work requests that may be
 *			outstanding on any receive queue supported by this
 *			NIC.
 * @wqe_size:		The size of each work queue entry in bytes.
 * @min_msg_size:	The minimum message size supported by this NIC
 *			in bytes.
 * @max_msg_size:	The maximum message size supported by this NIC
 *			in bytes.
 * @min_rdma_size:	The minimum RDMA transfer size supported by this NIC
 *			in bytes.
 * @max_rdma_size:	The maximum RDMA transfer size supported by this NIC
 *			in bytes.
 * @min_sges:		The minimum number of scatter/gather elements per
 *			work request guaranteed to be supported by this NIC.
 * @max_sges:		The maximum number of scatter/gather elements per
 *			work request that may supported by this NIC.
 * @sge_size:		The size of each scatter/gather entry in bytes.
 * @min_or:		The guaranteed minimum number of outbound RDMA read
 *			and atomic requests that may be outstanding per queue
 *			pair.
 * @max_or:		The maximum number of outbound RDMA read and atomic
 *			requests that may be outstanding per queue pair.
 * @min_ir:		The guaranteed minimum number of inbound RDMA read
 *			and atomic requests that may be outstanding per queue
 *			pair.
 * @max_ir:		The maximum number of inbound RDMA read and atomic
 *			requests that may be outstanding per queue pair.
 * @min_cos:		The minimum number of collective groups guaranteed
 *			to be supported by this NIC.
 * @max_cos:		The maximum number of collective groups that may be
 *			supported by this NIC.
 * @page_size:		The page size supported by the NIC.
 *
 * Description:
 *	The attributes of a DET NIC.
 *
 * See Also:
 *	det_query_nic()
 **/
struct det_nic_attr {
	char				ifname[IFNAMSIZ];
	__u32				vendor_id;
	__u16				device_id;
	__u16				hw_rev;
	__u64				fw_rev;
	__u32				min_pds;
	__u32				max_pds;
	__u32				min_mrs;
	__u32				max_mrs;
	__u32				min_mr_size;
	__u32				max_mr_size;
	__u32				min_mws;
	__u32				max_mws;
	__u32				min_cqs;
	__u32				max_cqs;
	__u32				min_cq_size;
	__u32				max_cq_size;
	__u32				cqe_size;
	__u32				min_qps;
	__u32				max_qps;
	__u32				min_sq_size;
	__u32				max_sq_size;
	__u32				min_rq_size;
	__u32				max_rq_size;
	__u32				wqe_size;
	__u32				min_msg_size;
	__u32				max_msg_size;
	__u32				min_rdma_size;
	__u32				max_rdma_size;
	__u32				min_sges;
	__u32				max_sges;
	__u32				sge_size;
	__u32				min_or;
	__u32				max_or;
	__u32				min_ir;
	__u32				max_ir;
	__u32				min_cos;
	__u32				max_cos;
	__u32				page_size;
} __attribute__((packed));


/**
 * det_cq_state
 * %DET_CQ_READY:	The ready state is the main operational state
 *			of a completion queue.  A completion queue is
 *			in the ready state following creation.  In
 *			this state work completions may be added to
 *			and polled from the completion queue.
 * %DET_CQ_ERROR:	The error state indication that the completion
 *			queue has experienced an error and has stopped
 *			accepting work completions.  Work completions
 *			on the completion queue at the time the error
 *			occurred can be retrieved by polling.
 *
 * Description:
 *	Indicates the state of a completion queue.
 *
 * See Also:
 *	&struct det_cq_attr
 **/
enum det_cq_state {
	DET_CQ_READY,
	DET_CQ_ERROR
};


/**
 * det_cq_arm
 * %DET_CQ_NEXT_SIGNALED:	Indicates that the completion queue should
 *				generate a notification event when the next
 *				completion entry is added to the queue.
 * %DET_CQ_NEXT_SOLICITED:	Indicates that the completion queue will
 *				generate a notification event only after
 *				a completion entry has been added to the
 *				queue with the solicited bit set or when
 *				an unsuccessful completion entry is added
 *				to the queue.
 * %DET_CQ_THRESHOLD:		Indicates that the completion queue will
 *				generate a notification event only after
 *				the number of completion entries in the
 *				queue reach a given threshold.
 *
 * Description:
 *	Indicates when a completion queue should generate the next
 *	notification event.  The client can specify any combination
 *	of flags when arming the completion queue.
 *
 * See Also:
 *	det_arm_cq()
 **/
enum det_cq_arm {
	DET_CQ_NEXT_SIGNALED		= BIT(0),
	DET_CQ_NEXT_SOLICITED		= BIT(1),
	DET_CQ_THRESHOLD		= BIT(2)
};


/**
 * det_cq_attr
 * @state:	Indicates the state of a completion queue.
 * @arm:	A set of flags indicating when the completion queue
 *		should generate the next notification event.
 * @size:	The actual size of the completion queue.
 * @threshold:	Specifies the number of entries that should be on the
 *		completion queue before generating an event.
 * @depth:	A snapshot of the number of entries currently on the
 *		completion queue.
 *
 * Description:
 *	Completion queue attributes.
 *
 * See Also:
 *	det_create_cq(), det_arm_cq()
 **/
struct det_cq_attr {
	enum det_cq_state		state;
	enum det_cq_arm			arm;
	__u32				size;
	__u32				threshold;
	__u32				depth;
} __attribute__((packed));


/**
 * det_qp_create
 * @sq_cq:	A handle to the completion queue used to report send
 *		work request completions.
 * @rq_cq:	A handle to the completion queue used to report receive
 *		work request completions.
 * @sq_size:	Indicates the requested maximum number of work requests
 *		that may be outstanding on the queue pair's send queue.
 *		This value must be less than or equal to the maximum
 *		reported by the NIC associated with the queue pair.
 * @rq_size:	Indicates the requested maximum number of work requests
 *		that may be outstanding on the queue pair's receive queue.
 *		This value must be less than or equal to the maximum
 *		reported by the NIC associated with the queue pair.
 * @sq_sges:	Indicates the requested maximum number of scatter/gather
 *		elements per work request submitted to the queue pair's
 *		send queue.
 * @rq_sges:	Indicates the requested maximum number of scatter/gather
 *		elements per work request submitted to the queue pair's
 *		receive queue.
 * @max_or:	Indicates the requested maximum number of RDMA read and
 *		atomic work requests that may be outstanding on the queue
 *		pair's send queue.  This value must be less than or equal
 *		to the maximum reported by the NIC associated with the queue
 *		pair.
 * @max_ir:	Indicates the requested maximum number of incoming RDMA read
 *		and atomic requests that may be outstanding on the queue pair.
 *		This value must be less than or equal to the maximum reported
 *		by the NIC associated with the queue pair.
 *
 * Description:
 *	Attributes used to initialize a queue pair at creation time.
 *
 * See Also:
 *	det_create_qp()
 **/
struct det_qp_create {
	struct det_cq			*sq_cq;
	struct det_cq			*rq_cq;
	__u32				sq_size;
	__u32				rq_size;
	__u32				sq_sges;
	__u32				rq_sges;
	__u32				max_or;
	__u32				max_ir;
} __attribute__((packed));


/**
 * det_qp_state
 * %DET_QP_IDLE:	A queue pair is in the idle state following
 *			creation or when moved to this state by modifying
 *			the queue pair.  In this state, receive work
 *			requests may be posted but are not processed
 *			and completion queue entries are not generated.
 * %DET_QP_CONNECTED:	The connected state is the main operational state
 *			of a queue pair.  All normal processing, both
 *			inbound and outbound, occurs in this state.  Prior
 *			to moving to this state, connection negotiation
 *			must be fully established.
 * %DET_QP_DISCONNECT:	The disconnect state is used to close a connection.
 *			This state may be entered manually via a modify
 *			queue pair operation or automatically by the remote
 *			queue pair or a locally detected error.  A disconnect
 *			without errors will cause the queue pair to transition
 *			to the %DET_QP_IDLE state, otherwise it will transition
 *			to the %DET_QP_ERROR state.  This state is transitory.
 * %DET_QP_ERROR:	The error state provides an indication that the
 *			queue pair has experienced an error (or a modify
 *			queue pair to error state) and has stopped
 *			operations.
 *
 * Description:
 *	Indicates or sets the state of a queue pair.
 *
 * See Also:
 *	det_modify_qp(), &struct det_qp_attr, &struct det_qp_mod
 **/
enum det_qp_state {
	DET_QP_IDLE,
	DET_QP_CONNECTED,
	DET_QP_DISCONNECT,
	DET_QP_ERROR
};


/**
 * det_qp_attr
 * @pd:			A pointer to the protection domain associated with
 *			the queue pair.
 * @sq_cq:		A pointer to the completion queue used to report
 *			send work request completions.
 * @rq_cq:		A pointer to the completion queue used to report
 *			receive	work request completions.
 * @state:		The current state of the queue pair.
 * @mtu_size:		The message transfer unit size in bytes for the
 *			underlying connection.  This field is only valid
 *			when the queue pair is in the %DET_QP_CONNECTED
 *			state.
 * @sq_size:		The maximum number of work requests that may be
 *			outstanding on the queue pair's send queue.
 * @rq_size:		The maximum number of work requests that may be
 *			outstanding on the queue pair's receive queue.
 * @sq_sges:		The maximum number of scatter/gather elements per
 *			work request submitted to the queue pair's send
 *			queue.
 * @rq_sges:		The maximum number of scatter/gather elements per
 *			work request submitted to the queue pair's receive
 *			queue.
 * @max_or:		The maximum number of RDMA read and atomic work
 *			requests that may be outstanding on the queue pair's
 *			send queue.
 * @max_ir:		The maximum number of incoming RDMA read and atomic
 *			requests that may be outstanding on the queue pair. 
 * @local_qp_num:	The number assigned to this local queue pair.
 * @remote_qp_num:	The number assigned to the remote queue pair to which
 *			this queue pair is connected.  This field is only
 *			valid when the queue pair is in the %DET_QP_CONNECTED
 *			state.
 * @local_mac:		The MAC address of the local NIC device associated
 *			with this queue pair.
 * @remote_mac:		The MAC address of the remote NIC device to which
 *			this queue pair is connected.  This field is only
 *			valid when the queue pair is in the %DET_QP_CONNECTED
 *			state.
 *
 * Description:
 *	Queue pair attributes.
 *
 * See Also:
 *	det_create_qp(), det_modify_qp(), &struct det_pd, &struct det_cq,
 *	&struct det_mac_addr
 **/
struct det_qp_attr {
	struct det_pd			*pd;
	struct det_cq			*sq_cq;
	struct det_cq			*rq_cq;
	enum det_qp_state		state;
	__u32				mtu_size;
	__u32				sq_size;
	__u32				rq_size;
	__u32				sq_sges;
	__u32				rq_sges;
	__u32				max_or;
	__u32				max_ir;
	__u32				local_qp_num;
	__u32				remote_qp_num;
	struct det_mac_addr		local_mac;
	struct det_mac_addr		remote_mac;
} __attribute__((packed));


/**
 * det_qp_mod_flag
 * %DET_QP_MOD_STATE_FLAG:	A flag that indicates that the state should
 *				be modified.  Note that when transitioning
 *				from the %DET_QP_IDLE to %DET_QP_CONNECTED
 *				state, the &remote_qp_num and &remote_mac
 *				are also modified.
 * %DET_QP_MOD_SQ_FLAG:		A flag that indicates that the %sq_size
 *				should be modified.
 * %DET_QP_MOD_RQ_FLAG:		A flag that indicates that the %rq_size
 *				should be modified.
 * %DET_QP_MOD_MAX_OR_FLAG:	A flag that indicates that the %max_or
 *				should be modified.
 * %DET_QP_MOD_MAX_IR_FLAG:	A flag that indicates that the %max_ir
 *				should be modified.
 *
 * Description:
 *	A set of flags used to set the capabilities of a queue pair.
 *
 * See Also:
 *	det_modify_qp()
 **/
enum det_qp_mod_flags {
	DET_QP_MOD_STATE_FLAG		= BIT(0),
	DET_QP_MOD_SQ_FLAG		= BIT(1),
	DET_QP_MOD_RQ_FLAG		= BIT(2),
	DET_QP_MOD_MAX_OR_FLAG		= BIT(3),
	DET_QP_MOD_MAX_IR_FLAG		= BIT(4)
};


/**
 * det_qp_mod
 * @flags:		A set of flags that indicates which queue pair
 *			attributes are being modified.
 * @next_state:		The next queue pair state.
 * @sq_size:		The maximum number of outstanding work requests
 *			the client expects to submit to the send queue
 *			of the queue pair.  This field is only valid for
 *			the following state transitions: %DET_QP_IDLE to
 *			%DET_QP_IDLE and %DET_QP_IDLE to %DET_QP_CONNECTED.
 * @rq_size:		The maximum number of outstanding work requests
 *			the client expects to submit to the receive queue
 *			of the queue pair.  This field is only valid for
 *			the following state transitions: %DET_QP_IDLE to
 *			%DET_QP_IDLE and %DET_QP_IDLE to %DET_QP_CONNECTED.
 * @max_or:		The requested number of outbound RDMA read and
 *			atomic requests the NIC can initiate from the send
 *			queue of the queue pair.  This field is only valid
 *			for the following state transitions: %DET_QP_IDLE
 *			to %DET_QP_IDLE and %DET_QP_IDLE to %DET_QP_CONNECTED.  
 * @max_ir:		The requested number of inbound outstanding RDMA
 *			read and atomic requests the queue pair can support.
 *			This field is only valid for the following state
 *			transitions: %DET_QP_IDLE to %DET_QP_IDLE and
 *			%DET_QP_IDLE to %DET_QP_CONNECTED.  
 * @remote_qp_num:	The number assigned to the remote queue pair to
 *			which this queue pair is connected.  This field
 *			is only valid when transitioning the queue pair
 *			from the %DET_QP_IDLE to the %DET_QP_CONNECTED
 *			state.
 * @remote_mac:		The MAC address of the remote NIC device to which
 *			this queue pair is connected.  This field is only
 *			valid when transitioning the queue pair from the
 *			%DET_QP_IDLE to the %DET_QP_CONNECTED state.
 *
 * Description:
 *	Information needed to change the state of a queue pair. When
 *	transitioning the state from %DET_QP_IDLE to %DET_QP_CONNECTED,
 *	the &remote_qp_num and &remote_mac_addr are also modified.
 *
 * See Also:
 *	det_modify_qp(), &struct det_mac_addr
 **/
struct det_qp_mod {
	enum det_qp_mod_flags		flags;
	enum det_qp_state		next_state;
	__u32				sq_size;
	__u32				rq_size;
	__u32				max_or;
	__u32				max_ir;
	__u32				remote_qp_num;
	struct det_mac_addr		remote_mac;
} __attribute__((packed));


/**
 * det_access_ctrl
 * %DET_AC_LOCAL_READ:		Enable local read access.
 * %DET_AC_REMOTE_READ:		Enable remote read access. Remote read
 *				access requires local read access to be
 *				enabled.
 * %DET_AC_LOCAL_WRITE:		Enable local write access.
 * %DET_AC_REMOTE_WRITE:	Enable remote write access.  Remote write 
 *				access requires local write access to be
 *				enabled.
 * %DET_AC_MW_BIND:		Enable memory window binding.
 *
 * Description:
 *	Indicates the type of access is permitted to a memory region.
 *	Clients may select any combination of access rights except as
 *	noted above.
 *
 * See Also:
 *	det_bind(), &struct det_mr_reg, &struct det_mr_attr,
 *	&struct det_mr_mod, &struct det_sh_reg, &struct det_mw_attr
 **/
enum det_access_ctrl {
	DET_AC_LOCAL_READ		= BIT(0),
	DET_AC_REMOTE_READ		= BIT(1),
/*	Reserved			= BIT(2), */
/*	Reserved			= BIT(3), */
	DET_AC_LOCAL_WRITE		= BIT(4),
	DET_AC_REMOTE_WRITE		= BIT(5),
/*	Reserved			= BIT(6), */
	DET_AC_MW_BIND			= BIT(7)
};


/**
 * det_mr_reg
 * @vaddr:	Specifies the virtual address to be assigned to the
 *		start of the registered memory region.
 * @length:	The length of the memory region to register in bytes.
 * @access:	Access rights of the registered memory region.
 *
 * Description:
 *	Information required to register a memory region.
 *
 * See Also:
 *	det_reg_mr()
 **/
struct det_mr_reg {
	__u64				vaddr;
	__u32				length;
	enum det_access_ctrl		access;
} __attribute__((packed));


/**
 * det_mem_attr
 * @pd:		Handle to the protection domain for this memory object.
 * @r_key:	The authorization key for the memory object used for
 *		remote access.
 * @length:	The length of the memory object in bytes.
 * @access:	Access rights for the specified memory object.
 *		This field is zero if the memory window object is unbound.
 *
 * Description:
 *	Base attributes of a memory object.
 *
 * See Also:
 *	det_reg_mr(), det_modify_mr(), det_reg_shared(), &struct det_pd
 *      &struct det_mr_attr, &struct det_mw_attr
 **/
struct det_mem_attr {
	struct det_pd			*pd;
	net32_t				r_key;
	__u32				length;
	enum det_access_ctrl		access;
} __attribute__((packed));


/**
 * det_mr_attr
 * @base:	Base attributes for this memory region.
 * @l_key:	The authorization key for the memory region used for
 *		local access.
 * Description:
 *	Attributes of a memory region.
 *
 * See Also:
 *	det_reg_mr(), det_modify_mr(), &struct det_mem_attr
 **/
struct det_mr_attr {
	struct det_mem_attr		base;
	__u32				l_key;
} __attribute__((packed));


/**
 * det_mr_mod_flags
 * %DET_MR_MOD_PD:	A flag that indicates that the protection domain
 *			of the memory region should be modified.
 * %DET_MR_MOD_ACCESS:	A flag that indicates that the access rights
 *			of the memory region should be modified.
 *
 * Description:
 *	A set of flags used to modify the attributes of a memory region.
 *
 * See Also:
 *	det_modify_mr()
 **/
enum det_mr_mod_flags {
	DET_MR_MOD_PD			= BIT(0),
	DET_MR_MOD_ACCESS		= BIT(1)
};


/**
 * det_mr_mod
 * @flags:	A set of flags that indicates which memory region
 *		attributes are being modified.
 * @pd:		The handle of the protection domain to be associated
 *		with the memory region.
 * @access:	Access rights of the registered memory region.
 *
 * Description:
 *	Information needed to modify a memory region.
 *
 * See Also:
 *	det_modify_mr(), &struct det_pd
 **/
struct det_mr_mod {
	enum det_mr_mod_flags		flags;
	struct det_pd			*pd;
	enum det_access_ctrl		access;
} __attribute__((packed));


/**
 * det_sh_reg
 * @pd:		A handle to an allocated protection domain associated
 *		with the shared memory region.
 * @vaddr:	Specifies the virtual address to be assigned to the
 *		start of the shared memory region.
 * @access:	Access rights of the shared memory region.
 *
 * Description:
 *	Information required to register a shared memory region.
 *
 * See Also:
 *	det_reg_shared(), &struct det_pd
 **/
struct det_sh_reg {
	struct det_pd			*pd;
	__u64				vaddr;
	enum det_access_ctrl		access;
} __attribute__((packed));


/**
 * det_mw_attr
 * @base:	Base attributes for this memory window.
 *
 * Description:
 *	Attributes of a memory window.
 *
 * See Also:
 *	det_reg_mr(), det_modify_mr(), det_reg_shared(), &struct det_mem_attr
 **/
struct det_mw_attr {
	struct det_mem_attr		base;
} __attribute__((packed));


/**
 * det_local_ds
 * @vaddr:	A virtual address within the memory region identified by the
 *		authorization key.
 * @length:	The length in bytes of the data segment.
 * @l_key:	The authorization key associated with the memory region used
 *		for local access.
 *
 * Description:
 *	A scatter/gather element referenced by work requests.  This is
 *	used to specify local data buffers used as part of a work request.
 *
 * See Also:
 *	det_send(), det_recv(), det_read(), det_write(), det_comp_exch(),
 *	det_fetch_add(), det_join(), det_bcast(), det_scatter(),
 *	det_scatterv(), det_gather(), det_gatherv(), det_allgather(),
 *	det_allgatherv(), det_alltoall(), det_alltoallv()
 **/
struct det_local_ds {
	__u64				vaddr;
	__u32				length;
	__u32				l_key;
} __attribute__((packed));


/**
 * det_wr_flags
 * %DET_WR_SURPRESSED:	A flag that when set indicates that successful
 *			completion of this work request will not generate
 *			a work completion on the associated completion
 *			queue associated with the local queue pair.
 * %DET_WR_SOLICITED:	A flag that when set indicates that a solicited
 *			event should be generated when a successful receive
 *			work completion is generated on the completion
 *			queue associated with the remote queue pair.
 * %DET_WR_FENCED:	A flag that when set indicates that all prior
 *			RDMA Read and Atomic work request operations
 *			have completed before the processing of this
 *			work request begins.
 * %DET_WR_IMMEDIATE:	A flag that when set indicates that immediate
 *			data is to be included in the out going operation.
 * %DET_WR_NO_TIMEOUT:  A flag to indicate the work request will not use 
 *                      network protocol timeouts.
 * %DET_WR_CO_RESERVED: A flag reserved for internal collective operations.
 *
 * Description:
 *	A set of flags used to control the operation of a work request.
 *
 * See Also:
 *	det_send(), det_read(), det_write(), det_comp_exch(), det_fetch_add(),
 *	det_join(), det_barrier(), det_bcast(), det_scatter(), det_scatterv(),
 *	det_gather(), det_gatherv(), det_allgather(), det_allgatherv(),
 *	det_alltoall(), det_alltoallv()
 **/
enum det_wr_flags {
	DET_WR_SURPRESSED		= BIT(0),
	DET_WR_SOLICITED		= BIT(1),
/*	Reserved			= BIT(2), */
	DET_WR_FENCED			= BIT(3),
	DET_WR_IMMEDIATE		= BIT(4),
	DET_WR_NO_TIMEOUT		= BIT(5),
	DET_WR_CO_RESERVED		= BIT(6)
};


/**
 * det_wc_type
 * %DET_WC_SEND			Indicates a send work completion type.
 * %DET_WC_RDMA_WRITE		Indicates an RDMA write work completion type.
 * %DET_WC_RDMA_READ		Indicates an RDMA read work completion type.
 * %DET_WC_ATOMIC_COMP_EXCH	Indicates an atomic compare/exchange work
 *				completion type.
 * %DET_WC_ATOMIC_FETCH_ADD	Indicates a atomic fetch/add work completion
 *				type.
 * %DET_WC_RECV			Indicates a receive work completion type.
 * %DET_WC_BIND			Indicates a memory window bind work completion
 *				type.
 *				** Collective Completion Types **
 * %DET_WC_JOIN			Indicates a join work completion type.
 * %DET_WC_BARRIER		Indicates a barrier work completion type.
 * %DET_WC_BCAST		Indicates a broadcast work completion type.
 * %DET_WC_SCATTER		Indicates a scatter work completion type.
 * %DET_WC_SCATTERV		Indicates a vector scatter work completion
 *				type.
 * %DET_WC_GATHER		Indicates a gather work completion type.
 * %DET_WC_GATHERV		Indicates a vector gather work completion type.
 * %DET_WC_ALLGATHER		Indicates a all-gather work completion type.
 * %DET_WC_ALLGATHERV		Indicates a vector all-gather work completion
 *				type.
 * %DET_WC_ALLTOALL		Indicates a all-to-all work completion type.
 * %DET_WC_ALLTOALLV		Indicates a vector all-to-all work completion
 *				type.
 *
 * Description:
 *	Indicates the type of work completion.
 **/
enum det_wc_type {
	DET_WC_SEND			= 1,
	DET_WC_RDMA_WRITE,
	DET_WC_RDMA_READ,
	DET_WC_ATOMIC_COMP_EXCH,
	DET_WC_ATOMIC_FETCH_ADD,
	DET_WC_RECV,
	DET_WC_BIND,

	/* Collectives */
	DET_WC_JOIN,
	DET_WC_BARRIER,
	DET_WC_BCAST,
	DET_WC_SCATTER,
	DET_WC_SCATTERV,
	DET_WC_GATHER,
	DET_WC_GATHERV,
	DET_WC_ALLGATHER,
	DET_WC_ALLGATHERV,
	DET_WC_ALLTOALL,
	DET_WC_ALLTOALLV
};


/**
 * det_wc_status
 * %DET_WS_SUCCESS		The work request completed successfully.
 * %DET_WS_FLUSHED		The work request was incomplete when the
 *				queue pair was disconnected or entered the
 *				error state.
 * %DET_WS_PROTECTION_ERR	A reference was made to a local memory region
 *				or window with a protection domain that does
 *				not match the protectin domain of the queue
 *				pair.
 * %DET_WS_BOUNDS_ERR		The local scatter-gather list referenced an
 *				address beyond the limits specified for the
 *				memory region or window.  This includes length
 *				errors.  For a bind operation, the memory
 *				window was not wholly contained in the memory
 *				region.
 * %DET_WS_ACCESS_ERR		An attempt was made to read or write a local
 *				memory region or window that did not provide
 *				appropriate access rights.  For a bind
 *				operation, the memory window access rights
 *				were not compatible with the memory region
 *				access rights.
 * %DET_WS_WRAP_ERR:		The length of the operation resulted in a wrap
 *				beyond the maximum machine-supported address.
 *
 * Description:
 *	Indicates the status of a completed work request.  These values
 *	are returned to the client when retrieving completions.  Note that
 *	success is identified as %DET_WS_SUCCESS, which is always zero.
 **/
enum det_wc_status {
	DET_WS_SUCCESS,
	DET_WS_FLUSHED,
	DET_WS_PROTECTION_ERR,
	DET_WS_BOUNDS_ERR,
	DET_WS_ACCESS_ERR,
	DET_WS_WRAP_ERR
};


/**
 * det_wc_flags
 * %DET_WC_SOLICITED:	A flag that when set indicates that a solicited
 *			event was generated with this work completion
 *			on the completion queue.  This flag is only valid
 *			for %DET_WC_RECV type work completions.
 * %DET_WC_IMMEDIATE:	A flag that when set indicates that the immediate
 *			data field is valid.  This flag is only valid for
 *			%DET_WC_RECV type work completions.
 *
 * Description:
 *	A set of flags used to indicate the completion a work request.
 *
 * See Also:
 *	&struct det_wc
 **/
enum det_wc_flags {
/*	Reserved			= BIT(0), */
	DET_WC_SOLICITED		= BIT(1),
/*	Reserved			= BIT(2), */
/*	Reserved			= BIT(3), */
	DET_WC_IMMEDIATE		= BIT(4)
};


/**
 * det_wc
 * @id:			The 64-bit work request identifier that was
 *			specified when posting the work request.
 * @status:		The result of the work request.
 * @type:		Indicates the type of work completion.
 * @flags:		Indicates optional flags as part of a work
 *			completion.
 * @length:		The number of bytes transferred by inbound sends
 *			and RDMA writes with immediate data or outbound
 *			RDMA read and atomic work requests.  This does
 *			not include the length of any immediate data.
 * @immediate_data:	A 32-bit field received as part of an inbound
 *			operation.  This field is only valid for
 *			%DET_WC_RECV type work completions if the
 *			@wc_flags %DET_WC_IMMEDIATE bit is set.
 * reap_cnt:		The number of work queue entries freed by
 *			polling this work completion.
 * reserved:		This field is reserved.
 *
 * Description:
 *	Work completion information.  When the work request completes
 *	in error, the only the @status and @id fields are valid.
 *
 * See Also:
 *	det_poll_cq()
 **/
struct det_wc {
	__u64				id;
	enum det_wc_status		status;
	enum det_wc_type		type;
	enum det_wc_flags		flags;
	__u32				length;
	__u32				immediate_data;
	__u32				reap_cnt;
	__u64				reserved;
} __attribute__((packed));


#endif /* __DET_TYPES_H__ */

