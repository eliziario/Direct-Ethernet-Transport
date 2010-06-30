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

#ifndef __DET_VERBS_H__
#define __DET_VERBS_H__

#include "det_types.h"


/*
 * General Notes:
 *	This file describes both the user-mode and kernel-mode APIs.
 *	Some APIs only apply to user mode, however, in most cases,
 *	the common APIs are identical.  Return error codes are
 *	negative within the kernel and positive in user-mode.  
 */


/**
 * det_open
 * @detdev:	Upon successful completion of this call, a pointer to
 *		an open instance of DET.
 *
 * Description:
 *	This function opens an instance of DET.  An opened instance of
 *	DET is required before allocating additional resources.
 *
 * Return Values:
 *	0
 *	DET was opened successfully.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to open DET.
 *
 * See Also:
 *	det_close(), &struct det_device
 **/
#ifndef	__KERNEL__
int det_open(struct det_device * const detdev);
#endif


/**
 * det_query
 * @detdev:	A pointer to an open instance of DET.
 * @attr:	Upon successful completion of this call, the structure
 *		referenced by this parameter contains the attributes of DET.
 *
 * Description:
 *	Queries the attributes of DET to determine the value of system limits,
 *	options, parameters, and statistics at runtime.
 *
 * Return Values:
 *	0
 *	The attributes were returned successfully.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.  This return value only applies
 *	to user-mode.
 *
 * See Also:
 * 	det_open(), &struct det_device, &struct det_attr
 **/
int det_query(struct det_device * const detdev,
	      struct det_attr * const attr);


/**
 * det_close
 * @detdev:	A pointer to an open instance of DET.
 *
 * Description:
 *	This call destroys an existing instance of DET.  Once closed, no
 *	further access is possible with the DET handle.
 *
 * Return Values:
 *	0
 *	DET was closed successfully.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_open(), &struct det_device
 **/
#ifndef	__KERNEL__
int det_close(struct det_device * const detdev);
#endif


/**
 * det_event_cb
 * @event:	A pointer to an existing event.
 * @record:	Information returned to the client indicating the type
 *		of event.
 *
 * Description:
 *	A client-specified callback that is invoked after an asynchronous
 *	event has occurred on an allocated resource.
 *
 *	For kernel-mode clients, this callback is invoked within a system
 *	thread context.
 *
 *	For user-mode clients, this callback is invoked by a client thread
 *	that called det_wait_on_event.
 *
 * See Also:
 *	det_open_nic(), det_create_event(), det_wait_on_event(),
 *	&struct det_event, &struct det_record
 **/
typedef void (*det_event_cb)(struct det_event * const event,
			     const struct det_record * const record);


/**
 * det_create_event
 * @detdev:	A pointer to an open instance of DET.
 * @event_cb:	A client-specified callback that is invoked after an
 *		asynchronous event or completion event has occurred.
 *		This parameter is optional.
 * @event:	A pointer to the newly created event.
 *
 * Description:
 *	This routine allocates an event.  If the event cannot be allocated,
 *	an error is returned.  The allocated event may be used by clients
 *	to wait for asynchronous events that occur a NIC, completion events,
 *	or client generated events.
 *
 * Return Values:
 *	0
 *	The event was successfully created.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to create the event.
 *
 * See Also:
 *	det_open(), det_destroy_event(), det_event_cb(), &struct det_event
 **/
#ifndef	__KERNEL__
int det_create_event(struct det_device * const detdev,
		     const det_event_cb event_cb,
		     struct det_event * const event);
#endif


/**
 * det_wait_on_event
 * @event:	A pointer to an existing event.
 * @timeout:	The number of microseconds to wait for an event to occur.
 *		If set to 0, the calling thread will check for and return
 *		any events that have occurred.  If set to %DET_NO_TIMEOUT,
 *		the calling thread will block until an event or a signal
 *		occurs.
 *
 * Description:
 *	This routine queues a request and blocks the calling thread waiting
 *	for an event.  When an event occurs, the client is notified through
 *	the event callback specified when the event was created.  Any thread
 *	waiting on the event queue may be used for notification.
 *
 * Return Values:
 *	0
 *	The event wait was successful.
 *
 *	EAGAIN
 *	No event was found on the event queue.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	EINTR
 *	A signal occurred while waiting on the event.
 *
 *	ETIME
 *	No events occurred before the specified wait time expired.
 *
 * See Also:
 *	det_create_event(), det_generate_event(), det_event_cb()
 **/
#ifndef	__KERNEL__
int det_wait_on_event(struct det_event * const event,
		      const signed long timeout);
#endif


/**
 * det_generate_event
 * @event:	A pointer to an existing event.
 * @handle:	A context handle provided by the client returned in the
 *		event record.
 *
 * Description:
 *	This routine queues an event signal on the specifed event handle.
 *	A client thread waiting on the event is notified through the event
 *	callback specified when the event handle was created.
 *
 * Return Values:
 *	0
 *	The event was successfully generated.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	EIO
 *	A fatal error occurred while generating the event.
 *
 * See Also:
 *	det_create_event(), det_wait_on_event(), det_event_cb()
 **/
#ifndef	__KERNEL__
int det_generate_event(struct det_event * const event,
		       void * const handle);
#endif


/**
 * det_destroy_event
 * @event:	A pointer to an existing event.
 *
 * Description:
 *	This call destroys an existing event.  Once destroyed, no further
 *	access to the event is possible.  This call will signal all threads
 *	waiting on the event to exit.  Therefore, call is synchronous and
 *	may block until all signalled threads are released from the event
 *	queue.
 *
 * Return Values:
 * 	0
 *	The event was successfully destoryed.
 *
 *	EBUSY
 *	The event is associated with one or more opened NICs or completion
 *	queues.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_create_event(), &struct det_event
 **/
#ifndef	__KERNEL__
int det_destroy_event(struct det_event * const event);
#endif


/**
 * det_open_nic
 * @detdev:	A pointer to an open instance of DET.
 * @ifname:	A null-terminated string containing the name of the NIC
 *		interface, limited to IFNAMSIZ bytes.
 * @event_cb:	A client-specified callback that is invoked after an
 *		asynchronous event has occurred on the NIC.  This parameter
 *		is optional and is only valid for kernel-mode clients.
 * @event:	A pointer to an event that is signaled after an asynchronous
 *		event has occurred on the NIC.  This parameter is only valid
 *		for user-mode clients.
 * @nic:	Upon successful completion of this call, a pointer to the
 *		opened NIC.
 *
 * Description:
 *	Opens a NIC for additional access.  A NIC must be opened before
 *	any additional resources can be consumed.  When successful, this
 *	routine returns a handle to an opened NIC.
 *
 *	For kernel-mode clients, when an asynchronous event occurs on a
 *	resource associated with this NIC instance the client-specified
 *	event callback will be invoked.  This callback is invoked through
 *	an asynchronous processing thread.
 *
 *	For user-mode applications, a client specifies an event that will
 *	be signaled when the NIC event occurs.  Any thread waiting on the
 *	event will be used to notify the client through the event callback
 *	specified when the event was created.  Use of the h_event parameter
 *	permits a client thread to block, waiting on NIC, completion queue,
 *	or user generated events.
 *
 * Return Values:
 *	0
 *	The operation was successful.
 *
 *	EINVAL
 *	An invalid parameter was provided.  This return value only applies
 *	to user-mode.
 *
 *	ENODEV
 *	No NIC was found in the system with the specified @ifname.
 *
 *	ENOMEM
 *	There was insufficient memory to open the NIC.
 *
 *	EPROTONOSUPPORT
 *	The features of the NIC device interface are not sufficient to
 *	support the DET protocol.
 *
 * See Also:
 *	det_query_nic(), det_close_nic(), det_event_cb(),
 *	det_create_event(), &struct det_device, &struct det_nic,
 *	&struct det_event
 **/
#ifdef	__KERNEL__
int det_open_nic(struct det_device * const detdev,
		 const char * const ifname,
		 const det_event_cb event_cb,
		 struct det_nic * const nic);
#else
int det_open_nic(struct det_device * const detdev,
		 const char * const ifname,
		 const struct det_event * event,
		 struct det_nic * const nic);
#endif


/**
 * det_query_nic
 * @nic:	A pointer to an opened NIC.
 * @nic_attr:	Upon successful completion of this call, the structure
 *		referenced by this parameter contains the attributes of
 *		the specified NIC.
 *
 * Description:
 *	Queries the attributes of an opened NIC.
 *
 * Return Values:
 *	0
 *	The attributes were returned successfully.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 * 	det_open_nic(), &struct det_nic, &struct det_nic_attr
 **/
int det_query_nic(struct det_nic * const nic,
		  struct det_nic_attr * const nic_attr);


/**
 * det_close_nic
 * @nic:	A pointer to an opened NIC.
 *
 * Description:
 *	Closes an opened NIC instance.  Once closed, no further access
 *	is possible with the NIC handle.  The client is responsible for
 *	freeing all associated resources, such as protection domains,
 *	queue pairs, completion queues, and registered memory.
 *
 * Return Values:
 * 	0
 *	The close was successful.
 *
 *	EBUSY
 *	The NIC handle has resources associated with it or is in use by
 *	another thread.  This return value only applies to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.  This return value only applies
 *	to user-mode.
 *
 * See Also:
 *	det_open_nic(), &struct det_nic
 **/
int det_close_nic(struct det_nic * const nic);


/**
 * det_alloc_pd
 * @nic:	A pointer to an opened NIC.
 * @pd:		Upon successful completion of this call, a pointer to
 *		the allocated protection domain.
 *
 * Description:
 *	Allocates a protection domain on the specified NIC.
 *
 * Return Values:
 *	0 
 *	The operation was successful.
 *
 *	EAGAIN
 *	There were insufficient resources currently available to allocate
 *	the protection domain.
 *
 *	EINVAL
 *	An invalid parameter was provided.  This return value only applies
 *	to user-mode.
 *
 *	ENOMEM
 *	There was insufficient memory to allocate the protection domain.
 *
 * See Also:
 *	det_open_nic(), det_dealloc_pd(), &struct det_nic, &struct det_pd
 **/
int det_alloc_pd(struct det_nic * const nic,
		 struct det_pd * const pd);


/**
 * det_dealloc_pd
 * @pd:		A pointer to an allocated protection domain.
 *
 * Description:
 *	Deallocates a protection domain.  The client is responsible for
 *	freeing all associated resources, such as queue pairs, completion
 *	queues, and registered memory.
 *
 * Return Values:
 *	0 
 *	The operation was successful.
 *
 *	EBUSY
 *	The protection domain handle has resources associated with it or
 *	is in use by another thread.  This return value only applies to
 *	user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.  This return value only applies
 *	to user-mode.
 *
 * See Also:
 *	det_open_nic(), det_alloc_pd(), &struct det_pd
 **/
int det_dealloc_pd(struct det_pd * const pd);


/**
 * det_completion_cb
 * @cq:		A pointer the completion queue on which the completion
 *		occurred.
 *
 * Description:
 *	Completion callback function provided by a client.  This function
 *	is invoked upon completion of a signaled work request on a queue
 *	pair associated with the completion queue.  This callback is
 *	usually invoked through a tasklet depending on the implementation
 *	of the underlying driver.
 *
 * See Also:
 *	det_create_cq, &struct det_cq
 **/
#ifdef	__KERNEL__
typedef void (*det_completion_cb)(struct det_cq * const cq);
#endif


/**
 * det_create_cq
 * @nic:		A pointer to an opened NIC.
 * @size:		The requested size of the completion queue.  If
 *			the creation call is successful, the actual size
 *			of the completion queue may be greater than the
 *			requested size.
 * @completion_cb:	A client-specified callback that is invoked
 *			whenever a signaled completion occurs on the
 *			completion queue.  This parameter is only valid
 *			for kernel-mode clients.
 * @event:		A pointer to an event that is signaled whenever
 *			a signaled completion occurs on the completion
 *			queue.  This parameter is only valid for user-mode
 *			clients.
 * @cq_attr:		Upon successful completion of this call, the
 *			structure referenced by this parameter contains
 *			the actual attributes created for the completion
 *			queue.  This parameter is optional.
 * @cq:			Upon successful completion of this call, a pointer
 *			to the newly created completion queue.
 *
 * Description:
 *	This routine creates a completion queue on the specified NIC.  If
 *	the completion queue cannot be allocated, an error is returned.
 *	Queue pairs associated with a given completion queue are required
 *	to use the same NIC.
 *
 *	Kernel-mode clients must specify a completion callback.  When a
 *	signaled completion occurs on the completion queue, the client
 *	will be notified through the callback.
 *
 *	User-mode clients must specify an event that will be signaled when
 *	a completion event occurs.
 *
 *	The client may optionally provide a reference to a structure to
 *	recieve the actual attributes created for the completion queue,
 *	which may be different from those requested.
 *
 * Return Values:
 *	0
 *	The completion queue was successfully created.
 *
 *	EAGAIN
 *	There were insufficient resources currently available to create
 *	the completion queue.
 *
 *	EDQUOT
 *	The requested commpletion queue attributes exceed the system pinned
 *	page quota.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to create the completion queue.
 *
 * See Also:
 *	det_open_nic(), det_destroy_cq(), det_create_event(),
 *	det_completion_cb(), &struct det_nic, &struct det_cq_attr,
 *	&struct det_cq
 **/
#ifdef	__KERNEL__
int det_create_cq(struct det_nic * const nic,
		  const __u32 size,
		  const det_completion_cb completion_cb,
		  struct det_cq_attr * const cq_attr,
		  struct det_cq * const cq);
#else
int det_create_cq(struct det_nic * const nic,
		  const __u32 size,
		  struct det_event * const event,
		  struct det_cq_attr * const cq_attr,
		  struct det_cq * const cq);
#endif


/**
 * det_query_cq
 * @cq:		A pointer to an existing completion queue.
 * @cq_attr:	Upon successful completion of this call, the structure
 *		referenced by this parameter contains the attributes
 *		of the completion queue.
 *
 * Description:
 *	This routine returns the current attributes of a completion queue.
 *
 * Return Values: 
 * 	0
 *	The completion queue attributes were returned successfully.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_create_cq(), &struct det_cq, &struct det_cq_attr
 **/
int det_query_cq(struct det_cq * const cq,
		 struct det_cq_attr * const cq_attr);


/**
 * det_resize_cq
 * @cq:		A pointer to an existing completion queue.
 * @size:	Specifies the new size of the completion queue.  If
 *		the resize call is successful, the actual size of the
 *		completion queue may be greater than the requested size.
 * @cq_attr:	Upon successful completion of this call, the structure
 *		referenced by this parameter contains the actual attributes
 *		created for the completion queue.  This parameter is optional.
 *
 * Description:
 *	This routine allows a client to modify the size of a completion
 *	queue.  If the new size is larger than what the associated NIC
 *	can support, an error is returned.  If the completion queue has
 *	valid completion entries on it and the requested size is smaller
 *	than the number of entries, a busy error is returned.
 *
 *	The client may optionaly provide a reference to a structure to
 *	recieve the actual attributes for the completion queue, which
 *	may be different from those requested.
 *
 * Return Values:
 *	0
 *	The size of the completion queue was successfully modified.
 *
 *	EAGAIN
 *	There were insufficient resources currently available to modify
 *	the size of the completion queue.
 *
 *	EBUSY
 *	The requested size of the completion queue was smaller than the
 *	number of work completions currently on the completion queue.
 *
 *	EDQUOT
 *	The requested commpletion queue attributes exceed the system pinned
 *	page quota.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to modify the size of the completion
 *	queue.
 *
 * See Also:
 *	det_create_cq(), &struct det_cq(), &struct det_cq_attr
 **/
int det_resize_cq(struct det_cq * const cq,
		  const __u32 size,
		  struct det_cq_attr * const cq_attr);


/**
 * det_arm_cq
 * @cq:		A pointer to an existing completion queue.
 * @arm:	A set of flags indicating when the completion queue
 *		should generate the next notification event.
 * @threshold:	The number of entries that should be on the completion
 *		queue before generating a notification event.  This
 *		parameter is only used if the %DET_CQ_THRESHOLD arm
 *		flag is set.  The threshold value must be greater
 *		than or equal to one.
 *
 * Description:
 *	This routine sets the completion queue to generate a notification
 *	event when the conditions specified by the arm flags are met.
 *
 *	When the %DET_CQ_THRESHOLD arm flag is set, a notification event
 *	will be generated when the number of work completions on the
 *	completion queue reach the given threshold value.  The event
 *	may be generated immediately if current depth of the completion
 *	queue meets or exceeds the given threshold value.
 *
 *	When the %DET_CQ_NEXT_SOLICITED arm flag is set, the completion
 *	queue will generate a notification event when the next work
 *	completion is added to the queue with the %DET_WC_SOLICITED
 *	bit set or when the next unsuccessful work completion is added
 *	to the completion queue.
 *
 *	When the %DET_CQ_NEXT_SIGNALED arm flag is set, the completion
 *	queue will generate a notification event when the next work
 *	completion is added to the queue.  Thus, the %DET_CQ_NEXT_SIGNALED
 *	arm flag has priority over all other arm types.
 *
 *	Once armed, a completion queue cannot be disarmed.  Calling this
 *	routine multiple times before a notification event is generated
 *	has the effect of OR-ing the arm flag settings together; in this
 *	case, the last threshold value specified will be used.  Only one
 *	notification event will be generated even though multiple calls
 *	were made prior to the notification event for the specified
 *	completion queue.  Once the notification event is generated,
 *	another request to arm the completion queue must be registered
 *	before the next notification event is generated for the specified
 *	completion queue.
 *
 * Return Values:
 * 	0
 *	The completion queue arm request was registered successfully.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_create_cq(), det_poll_cq(), &struct det_cq
 **/
int det_arm_cq(struct det_cq * const cq,
	       const enum det_cq_arm arm,
	       const __u32 threshold);


/**
 * det_poll_cq
 * @cq:		A pointer to an existing completion queue.
 * @num_wc:	On input, the number of structures in the work completion
 *		array.  Upon successful completion of this call, the number
 *		of work completions removed from the completion queue.
 * @wc_array:	On input, a reference to an array of work completion
 *		structures used provided by the client.  Upon successful
 *		completion of this call, this array contains completed
 *		work requests.
 *
 * Description:
 *	This routine retrieves completed work requests from the specified
 *	completion queue.  This call will retrieve all completed requests,
 *	up to to the number of work completion structures specified by the
 *	num_wc parameter.
 *
 * Return Values:
 *	0
 *	The poll operation completed successfully.
 *
 *	EAGAIN
 *	No completed work requests were removed from the completion queue.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.  This return value only applies
 *	to user-mode.
 *
 * See Also:
 *	det_create_cq(), det_send(), det_recv(), &struct det_cq,
 *	&struct det_wc
 **/
int det_poll_cq(struct det_cq * const cq,
		__u32 * const num_wc,
		struct det_wc * const wc_array);


/**
 * det_destroy_cq
 * @cq:		A pointer to an existing completion queue.
 *
 * Description
 *	Destroys a completion queue.  Once destroyed, no further access
 *	to the completion queue is possible.  If there are still queue
 *	pairs associated with the completion queue when this function
 *	is invoked, the destroy operation will fail with %EBUSY status.
 *
 * Return Values:
 * 	0
 *	The completion queue was successfully destroyed.
 *
 *	EBUSY
 *	One or more queue pairs are associated with the completion queue.
 *
 *	EINVAL
 *	An invalid parameter was provided.  This return value only applies
 *	to user-mode.
 *
 * See Also:
 *	det_create_cq(), &struct det_cq
 **/
int det_destroy_cq(struct det_cq * const cq);


/**
 * det_create_qp
 * @pd:		A pointer to an allocated protection domain.
 * @qp_create:	Attributes necessary to allocate and initialize the
 *		queue pair.
 * @qp_attr:	Upon successful completion of this call, the structure
 *		referenced by this parameter contains the actual attributes
 *		created for the queue pair. This parameter is optional.
 * @qp:		Upon successful completion of this call, a pointer to the
 *		newly created queue pair.
 *
 * Description:
 *	This routine allocates a queue pair with the specified attributes.
 *	If the queue pair cannot be allocated, an error is returned.
 *
 *	The client may optionally provide a reference to a structure to
 *	recieve the actual attributes created for the queue pair, which
 *	may be different from those requested.
 *
 * Return Values:
 *	0
 *	The queue pair was created successfully.
 *
 *	EAGAIN
 *	There were insufficient resources currently available to create
 *	the queue pair.
 *
 *	EDQUOT
 *	The requested queue pair attributes exceed the system pinned
 *	page quota.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to create the queue pair.
 *
 * See Also:
 *	det_alloc_pd(), det_destroy_qp(), &struct det_pd,
 *	&struct det_qp_create, &struct det_qp_attr, &struct det_qp
 **/
int det_create_qp(struct det_pd * const pd,
		  const struct det_qp_create * const qp_create,
		  struct det_qp_attr * const qp_attr,
		  struct det_qp * const qp);


/**
 * det_query_qp
 * @qp:		A pointer to an existing queue pair.
 * @qp_attr:	Upon successful completion of this call, the structure
 *		referenced by this parameter contains the attributes
 *		for the queue pair.
 *
 * Description:
 *	This routine returns the current attributes of a queue pair.
 *
 * Return Values: 
 * 	0
 *	The queue pair attributes were returned successfully.
 *
 *	EAGAIN
 *	The queue pair attributes are being modified by another thread.
 *	This return value only applies to kernel-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_create_qp(), &struct det_qp, &struct det_qp_attr
 **/
int det_query_qp(struct det_qp * const qp,
		 struct det_qp_attr * const qp_attr);


/**
 * det_modify_qp
 * @qp:		A pointer to an existing queue pair.
 * @qp_mod:	The new attributes to use when modifying the queue pair.
 * @qp_attr:	Upon successful completion of this call, the structure
 *		referenced by this parameter contains the actual attributes
 *		for the queue pair.  This parameter is optional.
 *
 * Description:
 *	This routine modifies the attributes of an existing queue pair
 *	and transitions it to a new state.  The new state and attributes
 *	are specified through the @qp_mod parameter.  Upon successful
 *	completion, the queue pair is in the requested state.  The client
 *	may optionally provide a reference to a structure to recieve the
 *	actual attributes of the queue pair, which may be different from
 *	those requested.
 *
 * Return Values: 
 * 	0
 *	The queue pair was modified successfully.
 *
 *	EAGAIN
 *	The queue pair attributes are being modified by another thread.
 *	This return value only applies to kernel-mode.
 *
 *	EBUSY
 *	The requested send or receive queue size was smaller than the
 *	number of work requests currently on the queue.
 *
 *	EDQUOT
 *	The requested queue pair attributes exceed the system pinned
 *	page quota.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to modify the queue pair.
 *
 *	EPERM
 *	The requested queue pair state transition is not permitted.
 *
 * See Also:
 *	det_create_qp(), &struct det_qp, &struct det_qp_mod,
 *	&struct det_qp_attr
 **/
int det_modify_qp(struct det_qp * const qp,
		  const struct det_qp_mod * const qp_mod,
		  struct det_qp_attr * const qp_attr);


/**
 * det_destroy_qp
 * @qp:		A pointer to an existing queue pair.
 *
 * Description:
 *	Destroy a queue pair.  Once destroyed, no further access to this
 *	queue pair is possible.  This call is synchronous and may block
 *	until all references from the underlying NIC are released.
 *
 * Return Values:
 * 	0
 *	The queue pair was successfully destroyed.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_open_nic(), det_create_qp(), &struct det_qp
 **/
int det_destroy_qp(struct det_qp * const qp);


/**
 * det_reg_mr
 * @pd:		A pointer to an allocated protection domain.
 * @mr_reg:	Information describing the memory region to register.
 * @l_key:	Upon successful completion of this call, this references
 *		an authorization key used for local access.
 * @r_key:	Upon successful completion of this call, this references
 *		an authorization key used for remote access.  This field
 *		is optional and valid only when remote access is requested.
 * @mr:		Upon successful completion of this call, a pointer to the
 *		newly created memory region.
 *
 * Description:
 *	This routine registers a memory region with a NIC.  Memory must be
 *	registered before being used in a data transfer operation.
 *
 *	Kernel-mode clients are responsible for initializing the number
 *	of pages and allocating / initializing the page list array at the
 *	end of the det_mr structure.  The initialization of the page list
 *	array contents may depend on the method used to allocate the memory
 *	region, e.g., kmalloc, vmalloc, __get_free_pages, etc.
 *
 * Return Values: 
 * 	0
 *	The memory region was registered successfully.
 *
 *	E2BIG
 *	The size of the physical buffer list exceeds the maximum supported
 *	by the hardware.
 *
 *	EAGAIN
 *	There were insufficient resources currently available to register
 *	the memory region.
 *
 *	EDQUOT
 *	The memory region attributes exceed the system pinned page quota.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to register the memory region.
 *
 *	ERANGE
 *	The specified virtual address and length result in a wrap beyond
 *	the maximum machine-supported address.
 *
 * See Also:
 *	det_alloc_pd(), det_query_mr(), det_dereg_mr(), &struct det_pd,
 *	&struct det_mr_reg, &struct det_mr
 **/
int det_reg_mr(struct det_pd * const pd,
	       const struct det_mr_reg * const mr_reg,
	       __u32 * const l_key,
	       net32_t * const r_key,
	       struct det_mr * const mr);


/**
 * det_query_mr
 * @mr:		A pointer to a memory region.
 * @mr_attr:	Upon successful completion of this call, the structure
 *		referenced by this parameter contains the attributes
 *		of the memory region.
 *
 * Description:
 *	This routine returns the current attributes of a memory region.
 *
 * Return Values: 
 * 	0
 *	The memory region attributes were returned successfully.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_reg_mr(), &struct det_mr, &struct det_mr_attr
 **/
int det_query_mr(struct det_mr * const mr,
		 struct det_mr_attr * const mr_attr);


/**
 * det_modify_mr
 * @mr:		A pointer to an existing memory region that will be
 *		modified.
 * @mr_mod:	The new attributes to use when modifying the memory
 *		region.
 * @l_key:	Upon successful completion of this call, this references
 *		the new authorization key used for local access.
 * @r_key:	Upon successful completion of this call, this references
 *		the new authorization key used for remote access.  This
 *		field is optional and valid only when remote access is
 *		requested.
 *
 * Description:
 *	This routine modifies the attributes of the specified memory region
 *	and may be used to change the access rights and/or protection domain
 *	of a memory region.
 *
 * Return Values: 
 * 	0
 *	The memory region was modified successfully.
 *
 *	EBUSY
 *	One or more memory windows is bound to the memory region.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to modify the memory region.
 *
 * See Also:
 *	det_reg_mr(), det_query_mr(), det_reg_shared(), &struct det_mr,
 *	&struct det_mr_mod
 **/
int det_modify_mr(struct det_mr * const mr,
		  const struct det_mr_mod * const mr_mod,
		  __u32 * const l_key,
		  net32_t * const r_key);


/**
 * det_reg_shared
 * @mr:		A pointer to the existing memory region being shared.
 * @sh_reg:	Information describing the shared memory region to
 *		register.
 * @l_key:	Upon successful completion of this call, this references
 *		the authorization key used for local access.
 * @r_key:	Upon successful completion of this call, this references
 *		the authorization key used for remote access.  This field
  *		is optional and valid only when remote access is requested.
* @shared_mr:	Upon successful completion of this call, a pointer to the
 *		shared memory region.
 *
 * Description:
 *	This routine registers a memory region that shares the same physical
 *	pages as an previously registered memory region.
 *
 * Return Values: 
 * 	0
 *	The shared memory region was successfully registered.
 *
 *	EAGAIN
 *	There were insufficient resources currently available to register
 *	the shared memory region.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to register the shared memory region.
 *
 * See Also:
 *	det_reg_mr(), det_query_mr(), &struct det_mr, &struct det_sh_reg
 **/
int det_reg_shared(struct det_mr * const mr,
		   const struct det_sh_reg * const sh_reg,
		   __u32 * const l_key,
		   net32_t * const r_key,
		   struct det_mr * const shared_mr);


/**
 * det_dereg_mr
 * @mr:		A pointer to a registered memory region that will be
 *		unregistered.
 *
 * Description:
 *	This routine deregisters a registered memory region.  The region
 *	may be deregistered only if there are no memory windows bound to
 *	the region.  Once this operation is complete, future accesses
 *	using the memory region authorization keys will fail.  This call
 *	is synchronous and may block until all references from the
 *	underlying NIC are released.
 *
 * Return Values:
 *	0
 *	The memory region was successfully deregistered.
 *
 *	EBUSY
 *	The memory region has memory windows bound to it.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_reg_mr(), &struct det_mr
 **/
int det_dereg_mr(struct det_mr * const mr);


/**
 * det_create_mw
 * @pd:		A pointer to an allocated protection domain.
 * @mw:		Upon successful completion of this call, a pointer to the
 *		unbound memory window.
 *
 * Description:
 *	This routine creates a memory window associated with a specified
 *	protection domain.  Newly created windows are not bound to any
 *	specific memory region.  The memory window cannot be used for
 *	data transfer operations until it is bound to a registered
 *	memory region.
 *
 * Return Values:
 * 	0
 *	The memory window was allocated successfully.
 *
 *	EAGAIN
 *	There were insufficient resources currently available to create
 *	the memory window.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to create the memory window.
 *
 * See Also:
 *	det_alloc_pd(), &struct det_pd, &struct det_mr_attr, &struct det_mw
 **/
int det_create_mw(struct det_pd * const pd,
		  struct det_mw * const mw);


/**
 * det_query_mw
 * @mw:		A pointer to a memory window.
 * @mw_attr:	Upon successful completion of this call, the structure
 *		referenced by this parameter contains the attributes
 *		of the memory window.
 *
 * Description:
 *	This routine returns the current attributes of a memory window.
 *
 * Return Values:
 * 	0
 *	The memory window attributes were returned successfully.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_create_mw(), &struct det_mw, &struct det_mw_attr
 **/
int det_query_mw(struct det_mw * const mw,
		 struct det_mw_attr * const mw_attr);


/**
 * det_destroy_mw
 * @mw:		A pointer to a memory window that will be destroyed.
 *
 * Description:
 *	Destroy a memory window.
 *
 * NOTES
 *	This routine deallocates a memory window.  Once this operation
 *	is complete, future accesses to the memory window will fail.
 *
 * Return Values:
 *	0
 *	The memory window was successfully destroyed.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_create_mw(), &struct det_mw
 **/
int det_destroy_mw(struct det_mw * const mw);


/**
 * det_send
 * @qp:			A pointer to the queue pair to which this work
 *			request is being submitted.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @ds_array:		A reference to an array of local data segments
 *			used by the send operation.
 * @num_ds:		Number of local data segments specified by this
 *			work request.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 * @immediate_data:	A 32-bit field sent as part of the send operation.
 *			This field is only valid if the @flags
 *			%DET_WR_IMMEDIATE bit is set.
 *
 * Description:
 *	This routine posts a send work request to the send queue of a
 *	queue pair.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	E2BIG
 *	The number of work request scatter gather elements exceed the
 *	queue pair configuration.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read access.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOTCONN
 *	The current queue pair state does not allow posting work requests.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the send queue of the queue pair.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The queue pair and local data segment do not belong to the same
 *	protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_create_qp(), det_recv(), &struct det_qp, &struct det_local_ds
 **/
int det_send(struct det_qp * const qp,
	     const __u64 id,
	     const struct det_local_ds * const ds_array,
	     const __u32 num_ds,
	     const enum det_wr_flags flags,
	     const __u32 immediate_data);


/**
 * det_recv
 * @qp:			A pointer to the queue pair to which this work
 *			request is being submitted.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @ds_array:		A reference to an array of local data segments
 *			used by the receive operation.
 * @num_ds:		Number of local data segments specified by this
 *			work request.
 *
 * Description:
 *	This routine posts a receive work request to the receive queue of
 *	a queue pair.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	E2BIG
 *	The number of work request scatter gather elements exceed the
 *	queue pair configuration.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	write access.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOTCONN
 *	The current queue pair state does not allow posting work requests.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the receive queue of the queue pair.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The queue pair and local data segment do not belong to the same
 *	protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_create_qp(), det_send(), &struct det_qp, &struct det_local_ds
 **/
int det_recv(struct det_qp * const qp,
	     const __u64 id,
	     const struct det_local_ds * const ds_array,
	     const __u32 num_ds);


/**
 * det_read
 * @qp:			A pointer to the queue pair to which this work
 *			request is being submitted.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @ds_array:		A reference to an array of local data segments
 *			used by the read operation.
 * @num_ds:		Number of local data segments specified by this
 *			work request.
 * @remote_address:	An address within the remote memory region
 *			identified by the authorization key.
 * @remote_key:		The authorization key provided for the remote
 *			memory region.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts an RDMA read work request to the send queue
 *	of a queue pair.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	E2BIG
 *	The number of work request scatter gather elements exceed the
 *	queue pair configuration.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	write access.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOBUFS
 *	The queue pair max_or attribute does not allow outstanding RDMA
 *	read work requests on the send queue.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOTCONN
 *	The current queue pair state does not allow posting work requests.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the send queue of the queue pair.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The queue pair and local data segment do not belong to the same
 *	protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_create_qp(), &struct det_qp, &struct det_local_ds
 **/
int det_read(struct det_qp * const qp,
	     const __u64 id,
	     const struct det_local_ds * const ds_array,
	     const __u32 num_ds,
	     const net64_t remote_address,
	     const net32_t remote_key,
	     const enum det_wr_flags flags);


/**
 * det_write
 * @qp:			A pointer to the queue pair to which this work
 *			request is being submitted.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @ds_array:		A reference to an array of local data segments
 *			used by the write operation.
 * @num_ds:		Number of local data segments specified by this
 *			work request.
 * @remote_address:	An address within the remote memory region
 *			identified by the authorization key.
 * @remote_key:		The authorization key provided for the remote
 *			memory region.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 * @immediate_data:	A 32-bit field sent as part of the write operation.
 *			This field is only valid if the @flags
 *			%DET_WR_IMMEDIATE bit is set.
 *
 * Description:
 *	This routine posts an RDMA write work request to the send
 *	queue of a queue pair.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	E2BIG
 *	The number of work request scatter gather elements exceed the
 *	queue pair configuration.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read access.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOTCONN
 *	The current queue pair state does not allow posting work requests.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the send queue of the queue pair.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The queue pair and local data segment do not belong to the same
 *	protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_create_qp(), &struct det_qp, &struct det_local_ds
 **/
int det_write(struct det_qp * const qp,
	      const __u64 id,
	      const struct det_local_ds * const ds_array,
	      const __u32 num_ds,
	      const net64_t remote_address,
	      const net32_t remote_key,
	      const enum det_wr_flags flags,
	      const __u32 immediate_data);


/**
 * det_bind
 * @qp:			A pointer to the queue pair to which this work
 *			request is being submitted.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @mw:			A pointer to the memory window to which is being
 *			bound.
 * @mr:			A pointer to the memory region to which this memory
 *			window is being bound.  This field is ignored if
 *			length is zero.
 * @r_key:		Upon successful completion of this call, this
 *			references an authorization key used for remote
 *			access to the memory window.
 * @vaddr:		A virtual address within the memory region to the
 *			first byte of the bound memory window.  This field
 *			is ignored if length is zero.
 * @length:		The size of the memory window in bytes.
 * @access:		A set of flags used to control the access rights
 *			of the bound memory window.  This field is ignored
 *			if length is zero.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts a request to bind a memory window to a
 *	registered memory region.  The bind operation occurs on the
 *	specified queue pair, but the bound region is usable across
 *	all queue pairs within the same protection domain.  A bind
 *	operation will automatically fence all subsequent work
 *	requests submitted to the send queue of the queue pair until
 *	the bind operation is complete.  A previously bound memory
 *	window can be bound to a new virtual address range in the
 *	same or a different memory region, causing the previous
 *	binding to be invalidated.  Binding a memory window to
 *	a zero-length virtual address range will invalidate any
 *	previous binding and return an r_key that is unbound.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	EACCES
 *	The memory region access rights do not allow memory window binding.
 *
 *	EFAULT
 *	An invalid address was provided.  This return value only applies
 *	to user-mode.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOTCONN
 *	The current queue pair state does not allow posting work requests.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the send queue of the queue pair.
 *
 *	EPERM
 *	The queue pair, memory window, and memory region do not belong to
 *	the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of the memory window
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_create_qp(), &struct det_qp, &struct det_bind_wr
 **/
int det_bind(struct det_qp * const qp,
	     const __u64 id,
	     struct det_mw * const mw,
	     struct det_mr * const mr,
	     net32_t * const r_key,
	     const __u64 vaddr,
	     const __u32 length,
	     const enum det_access_ctrl access,
	     const enum det_wr_flags flags);


/**
 * det_comp_exch
 * @qp:			A pointer to the queue pair to which this work
 *			request is being submitted.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @comp_operand:	The comparison data used with the atomic
 *			compare/exchange operation.
 * @exch_operand:	The exchange data used with the atomic
 *			compare/exchange operation.
 * @local_ds:		A reference to a local data segment where a copy
 *			of the original contents of the remote memory
 *			operation will be deposited after the
 *			compare/exchange operation is completed at the
 *			remote endnode.
 * @remote_address:	The address of a remote memory region for the atomic
 *			compare/exchange operation.  This address must be
 *			aligned on 64-bit boundary.
 * @remote_key:		The authorization key provided for the remote
 *			memory region.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts an atomic compare/exchange work request to the
 *	send queue of a queue pair.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	EACCES
 *	The access rights of the local data segment do not allow local
 *	write access.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOBUFS
 *	The queue pair max_or attribute does not allow outstanding atomic
 *	work requests on the send queue.
 *
 *	ENOTCONN
 *	The current queue pair state does not allow posting work requests.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the send queue of the queue pair.
 *
 *	ENXIO
 *	The local authorization key of the data segment is invalid.
 *
 *	EOVERFLOW
 *	The data segment length is too small to perform a 64-bit atomic
 *	operation.
 *
 *	EPERM
 *	The queue pair and local data segment buffer do not belong to
 *	the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of the data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_create_qp(), &struct det_qp, &struct det_comp_exch_wr
 **/
int det_comp_exch(struct det_qp * const qp,
		  const __u64 id,
		  const __u64 comp_operand,
		  const __u64 exch_operand,
		  const struct det_local_ds * const local_ds,
		  const net64_t remote_address,
		  const net32_t remote_key,
		  const enum det_wr_flags flags);


/**
 * det_fetch_add
 * @qp:			A pointer to the queue pair to which this work
 *			request is being submitted.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @add_operand:	The data used with the atomic fetch/add operation.
 * @local_ds:		A reference to a local data segment where a copy
 *			of the original contents of the remote memory
 *			operation will be deposited after the fetch/add
 *			operation is completed at the remote endnode.
 * @remote_address:	The address of a remote memory region for the atomic
 *			fetch/add operation.  This address must be aligned
 *			on 64-bit boundary.
 * @remote_key:		The authorization key provided for the remote
 *			memory region.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts an atomic fetch/add work request to the send
 *	queue of a queue pair.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	EACCES
 *	The access rights of the local data segment do not allow local
 *	write access.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOBUFS
 *	The queue pair max_or attribute does not allow outstanding atomic
 *	work requests on the send queue.
 *
 *	ENOTCONN
 *	The current queue pair state does not allow posting work requests.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the send queue of the queue pair.
 *
 *	ENXIO
 *	The local authorization key of the data segment is invalid.
 *
 *	EOVERFLOW
 *	The data segment length is too small to perform a 64-bit atomic
 *	operation.
 *
 *	EPERM
 *	The queue pair and local data segment buffer do not belong to
 *	the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of the data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_create_qp(), &struct det_qp, &struct det_fetch_add_wr
 **/
int det_fetch_add(struct det_qp * const qp,
		  const __u64 id,
		  const __u64 add_operand,
		  const struct det_local_ds * const local_ds,
		  const net64_t remote_address,
		  const net32_t remote_key,
		  const enum det_wr_flags flags);


/*******************************
 *
 *      Collective Verbs
 *
 ******************************/


/**
 * det_create_co
 * @pd:			A pointer to an allocated protection domain.
 * @cq:			A pointer to an existing completion queue.
 * @co:			Upon successful completion of this call, a
 *			pointer to the newly created collective group.
 *
 * Description:
 *	This routine allocates a collective group associated with the
 *	specified protection domain and completion queue.  If the
 *	collective group cannot be allocated, an error is returned.
 *	Once created, each process must join the collective to become
 *	a member of the group.
 *
 * Return Values:
 *	0
 *	The collective group was created successfully.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to create the collective group.
 *
 * See Also:
 *	det_alloc_pd(), det_create_cq(), det_destroy_co(), &struct det_pd,
 *	&struct det_cq, &struct det_co
 **/
int det_create_co(struct det_pd * const pd,
		  struct det_cq * const cq,
		  struct det_co * const co);


/**
 * det_join
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @tag:		A group tag provided by the client.
 * @size:		The number of members in group.
 * @rank:		Rank of this process within the group.
 * @flags:		A set of flags used to control the operation
 *			of the work request.
 *
 * Description:
 *	This routine posts a work request to join a collective group.
 *	The size of the group is determined by size.  The membership
 *	rank for this process within the group is specifed by rank.
 *	The tag provided by the client identifies the group and must
 *	be unique among all participating processes.  To become members
 *	of the group, each process must join using the same tag value.
 *
 * Return Values:
 *	0
 *	The work request was successfully posted.
 *
 *	E2BIG
 *	The size of the collective group exceeds the maximum supported
 *	by the hardware.
 *
 *	EBUSY
 *	A collective group has already been joined.
 *
 *	EEXIST
 *	The collective group tag value already exists.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_create_co(), &struct det_co
 **/
int det_join(struct det_co * const co,
	     const __u64 id,
	     const net64_t tag,
	     const int size,
	     const int rank,
	     const enum det_wr_flags flags);


/**
 * det_destroy_co
 * @co:			A pointer to an existing collective group.
 *
 * Description:
 *	This routine destroys an existing collective group.  Once destroyed,
 *	no further access to the group is possible.  This call is synchronous
 *	and may block until all outstanding operations are complete.
 *
 * Return Values:
 * 	0
 *	The collective group was successfully destoryed.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 * See Also:
 *	det_create_co(), &struct det_co
 **/
int det_destroy_co(struct det_co * const co);


/**
 * det_barrier
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @flags:		A set of flags used to control the operation
 *			of the work request.
 *
 * Description:
 *	This routine posts a collective work request to synchronize with
 *	all members of the group.  A successful work completion will be
 *	generated when all members of the group have entered the barrier.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the send queue of the collective group queue pairs.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 * See Also:
 *	det_join(), &struct det_co
 **/
int det_barrier(struct det_co * const co,
		const __u64 id,
		const enum det_wr_flags flags);


/**
 * det_bcast
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @root:		The rank of the broadcast root.
 * @ds:			A reference to a local data segment.  If the root
 *			is the calling node, the ds identifies the transmit
 *			data, otherwise it specifes the receive buffer of
 *			the broadcast.
 * @flags:		A set of flags used to control the operation
 *			of the work request.
 *
 * Description:
 *	This routine posts a collective work request to perform a broadcast
 *	from the root process to all other members.  The root parameter
 *	specifies the member providing the data.  All other members will
 *	receive the data.  The data segment describes either the local
 *	send or receive buffer as determined by the root parameter.  The
 *	data buffer must have read and write access rights.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	EACCES
 *	The access rights of the local data segment do not allow local
 *	read and write access as required.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the collective group.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 *	ENXIO
 *	The local authorization key of the data segment is invalid.
 *
 *	EPERM
 *	The collective group and local data segment do not belong to
 *	the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of the data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_join(), &struct det_co, &struct det_local_ds
 **/
int det_bcast(struct det_co * const co,
	      const __u64 id,
	      const int root,
	      const struct det_local_ds * const ds,
	      const enum det_wr_flags flags);


/**
 * det_scatter
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @root:		The rank of the member providing the data.
 * @src_ds:		A reference to a local data segment describing
 *			the source buffer.  This parameter is only used
 *			at the root.
 * @dst_ds:		A reference to a local data segment describing
 *			the destination buffer.  This parameter may be
 *			NULL at the root to prevent local data movement.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts a collective work request to scatter data to
 *	all members.  The root parameter specifies the member providing
 *	the data.  The data segments describe the local send and receive
 *	buffers.  The transfer is divided by the size of the group and
 *	data is equally portioned to each member in ascending rank order.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read or write access as required.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	EIO
 *	The local data segments do not describe memory that can be
 *	evenly divided by the size of the collective group.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the collective group.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The collective group and local data segment do not belong to
 *	the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_join(), &struct det_co, &struct det_local_ds
 **/
int det_scatter(struct det_co * const co,
		const __u64 id,
		const int root,
		const struct det_local_ds * const src_ds,
		const struct det_local_ds * const dst_ds,
		const enum det_wr_flags flags);


/**
 * det_scatterv
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @root:		The rank of the member providing the data.
 * @src_ds_array:	A reference to an array of local data segments
 *			describing the source buffer for each member.
 *			This parameter is only used at the root.
 * @dst_ds:		A reference to a local data segment describing the
 *			destination buffer.  This parameter may be NULL at
 *			the root to prevent local data movement.
 * @flags:		A set of flags used to control the operation
 *			of the work request.
 *
 * Description:
 *	This routine posts a collective work request to scatter data to
 *	all members.  The root parameter specifies the member providing
 *	the data.  The data segments describes the local send and receive
 *	buffers.  Entries in the src_ds_array specify the source data buffer
 *	for each member.  Data is disbursed among members in ascending rank
 *	order.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	E2BIG
 *	The number of work request scatter gather elements exceed the
 *	collective group configuration.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read or write access as required.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the collective group.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The collective group and local data segment do not belong to
 *	the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_join(), &struct det_co, &struct det_local_ds
 **/
int det_scatterv(struct det_co * const co,
		 const __u64 id,
		 const int root,
		 const struct det_local_ds * const src_ds_array,
		 const struct det_local_ds * const dst_ds,
		 const enum det_wr_flags flags);


/**
 * det_gather
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @root:		The rank of the member receiving the data.
 * @src_ds:		A reference to a local data segment describing
 *			the source buffer.  This parameter may be NULL
 *			at the root to prevent local data movement.
 * @dst_ds:		A reference to a local data segment describing
 *			the destination buffer.  This parameter is only
 *			used at the root.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts a collective work request to gather data
 *	from all members.  The root parameter specifies the member
 *	collecting the data.  The data segments describe the local
 *	send or receive buffers.  The transfer is divided by the size
 *	of the group and data is combined equally from each member in
 *	ascending rank order.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read or write access as required.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	EIO
 *	The local data segments do not describe memory that can be
 *	evenly divided by the size of the collective group.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the collective group.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The collective group and local data segment do not belong to
 *	belong to the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_join(), &struct det_co, &struct det_local_ds
 **/
int det_gather(struct det_co * const co,
	       const __u64 id,
	       const int root,
	       const struct det_local_ds * const src_ds,
	       const struct det_local_ds * const dst_ds,
	       const enum det_wr_flags flags);


/**
 * det_gatherv
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @root:		The rank of the member receiving the data.
 * @src_ds:		A reference to a local data segment describing the
 *			source buffer.  This parameter may be NULL at the
 *			root to prevent local data movement.
 * @dst_ds_array:	A reference to an array of local data segments
 *			describing the destination buffer for each member.
 *			This parameter is only used at the root.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts a collective work request to gather data from
 *	all members.  The root parameter specifies the member collecting
 *	the data.  The data segments describe the local send and/or receive
 *	buffers.  Entries in the dst_ds_array specify the placement of data
 *	received from each member.  Data is combined from each member in
 *	ascending rank order.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	E2BIG
 *	The number of work request scatter gather elements exceed the
 *	collective group configuration.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read or write access as required.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the collective group.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The collective group and local data segment do not belong to
 *	belong to the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_join(), &struct det_co, &struct det_local_ds
 **/
int det_gatherv(struct det_co * const co,
		const __u64 id,
		const int root,
		const struct det_local_ds * const src_ds,
		const struct det_local_ds * const dst_ds_array,
		const enum det_wr_flags flags);


/**
 * det_allgather
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @src_ds:		A reference to a local data segment describing
 *			the source buffer.  This parameter may be NULL
 *			to prevent local data movement.
 * @dst_ds:		A reference to a local data segment describing
 *			the destination buffer.
 * @flags:		A set of flags used to control the operation
 *			of the work request.
 *
 * Description:
 *	This routine posts a collective work request to gather data from
 *	and deliver the result to all members.  The data segments describe
 *	the local send and receive buffers.  The destination buffer must
 *	have read and write access rights.  The transfer is divided by
 *	the size of the group and data is combined equally from members
 *	in ascending rank order.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read or write access as required.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	EIO
 *	The local data segments do not describe memory that can be
 *	evenly divided by the size of the collective group.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the collective group.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The collective group and local data segment do not belong to
 *	belong to the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_join(), &struct det_co, &struct det_local_ds
 **/
int det_allgather(struct det_co * const co,
		  const __u64 id,
		  const struct det_local_ds * const src_ds,
		  const struct det_local_ds * const dst_ds,
		  const enum det_wr_flags flags);


/**
 * det_allgatherv
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @src_ds:		A reference to a local data segment describing the
 *			source buffer.  This parameter may be NULL
 *			to prevent local data movement.
 * @dst_ds_array:	A reference to an array of local data segments
 *			describing the destination buffer for each member.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts a collective work request to gather data from
 *	and deliver the result to all member.  The data segments describe
 *	the local send or receive buffers.  Entries in the dst_ds_array
 *	specify the placement of data recevived from each member.  The
 *	destination data buffers must have read and write access rights.
 *	Data is combined from each member in ascending rank order.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	E2BIG
 *	The number of work request scatter gather elements exceed the
 *	collective group configuration.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read or write access as required.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the collective group.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The collective group and local data segment do not belong to
 *	belong to the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_join(), &struct det_co, &struct det_local_ds
 **/
int det_allgatherv(struct det_co * const co,
		   const __u64 id,
		   const struct det_local_ds * const src_ds,
		   const struct det_local_ds * const dst_ds_array,
		   const enum det_wr_flags flags);


/**
 * det_alltoall
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @src_ds:		A reference to a local data segment describing
 *			the source buffer.
 * @dst_ds:		A reference to a local data segment describing
 *			the destination buffer.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts a collective work request to exchange data with
 *	all group members.  The data segments describe the local send or
 *	receive buffers.  The destination buffer must have read and write
 *	access rights.  The transfer is divided by the size of the group.
 *	Data is equally portioned to and combined from members in ascending
 *	rank order.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read or write access as required.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	EIO
 *	The local data segments do not describe memory that can be
 *	evenly divided by the size of the collective group.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the collective group.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The collective group and local data segment do not belong to
 *	belong to the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_join(), &struct det_co, &struct det_local_ds
 **/
int det_alltoall(struct det_co * const co,
		 const __u64 id,
		 const struct det_local_ds * const src_ds,
		 const struct det_local_ds * const dst_ds,
		 const enum det_wr_flags flags);


/**
 * det_alltoallv
 * @co:			A pointer to an existing collective group.
 * @id:			A 64-bit work request identifier that is returned
 *			to the client as part of the work completion.
 * @src_ds_array:	A reference to an array of local data segments
 *			describing the source buffer for each member.
 * @dst_ds_array:	A reference to an array of local data segments
 *			describing the destination buffer for each member.
 * @flags:		A set of flags used to control the operation of
 *			the work request.
 *
 * Description:
 *	This routine posts a collective work request to exchange data
 *	with all group members.  The data segments describe the local
 *	send and receive buffers.  Entries in the arrays specify the
 *	number of local data segments exchanged with each member.  The
 *	destination data buffers must have read and write access rights.
 *	Data is combined from group members in ascending rank order.
 *
 * Return Values:
 * 	0
 *	The work request was successfully posted.
 *
 *	E2BIG
 *	The number of work request scatter gather elements exceed the
 *	collective group configuration.
 *
 *	EACCES
 *	The access rights of a local data segment do not allow local
 *	read or write access as required.
 *
 *	EINVAL
 *	An invalid parameter was provided.
 *
 *	ENOMEM
 *	There was insufficient memory to post the work request.
 *
 *	ENOSPC
 *	The number of posted work requests exceed the current depth
 *	available on the collective group.
 *
 *	ENOTCONN
 *	The collective group state does not allow posting work requests.
 *
 *	ENXIO
 *	The local authorization key of a data segment is invalid.
 *
 *	EPERM
 *	The collective group and local data segment do not belong to
 *	belong to the same protection domain.
 *
 *	ERANGE
 *	The specified virtual address and/or length of a data segment
 *	exceed the memory region boundaries.
 *
 * See Also:
 *	det_join(), &struct det_co, &struct det_local_ds
 **/
int det_alltoallv(struct det_co * const co,
		  const __u64 id,
		  const struct det_local_ds * const src_ds_array,
		  const struct det_local_ds * const dst_ds_array,
		  const enum det_wr_flags flags);


#endif /* __DET_VERBS_H__ */
