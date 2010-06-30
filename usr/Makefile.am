# $Id: $

OSFLAGS = -DOS_RELEASE=$(shell expr `uname -r | cut -f1 -d.` \* 65536 + `uname -r | cut -f2 -d.`)
# Check for RedHat, needed for ia64 udapl atomic operations (IA64_FETCHADD syntax)
# and built-in atomics for RedHat EL5
if HAVE_BITOPS
OSFLAGS += -DBITOPS
endif

DBGFLAGS = -g

detlibdir = $(libdir)
detlib_LTLIBRARIES = libdet.la
libdet_la_CFLAGS = -fPIC -Wall -Werror $(DBGFLAGS) -D_GNU_SOURCE $(OSFLAGS) -I$(srcdir)

if HAVE_LD_VERSION_SCRIPT
    det_version_script = -Wl,--version-script=$(srcdir)/libdet.map
else
    det_version_script = 
endif
				
libdet_la_SOURCES = det_verbs.c 

libdet_la_LDFLAGS = -version-info 1:1:0 $(det_version_script)

libdetincludedir = $(includedir)/det

libdetinclude_HEADERS = det.h \
                        det_ioctl.h \
                        det_types.h \
                        det_verbs.h 

man3_MANS =	man/det_allgather.3 \
		man/det_allgatherv.3 \
		man/det_alloc_pd.3 \
		man/det_alltoall.3 \
		man/det_alltoallv.3 \
		man/det_arm_cq.3 \
		man/det_barrier.3 \
		man/det_bcast.3 \
		man/det_bind.3 \
		man/det_close.3 \
		man/det_close_nic.3 \
		man/det_comp_exch.3 \
		man/det_create_co.3 \
		man/det_create_cq.3 \
		man/det_create_event.3 \
		man/det_create_mw.3 \
		man/det_create_qp.3 \
		man/det_dealloc_pd.3 \
		man/det_dereg_mr.3 \
		man/det_destroy_co.3 \
		man/det_destroy_cq.3 \
		man/det_destroy_event.3 \
		man/det_destroy_mw.3 \
		man/det_destroy_qp.3 \
		man/det_event_cb.3 \
		man/det_fetch_add.3 \
		man/det_gather.3 \
		man/det_gatherv.3 \
		man/det_generate_event.3 \
		man/det_join.3 \
		man/det_modify_mr.3 \
		man/det_modify_qp.3 \
		man/det_open.3 \
		man/det_open_nic.3 \
		man/det_poll_cq.3 \
		man/det_query.3 \
		man/det_query_cq.3 \
		man/det_query_mr.3 \
		man/det_query_mw.3 \
		man/det_query_nic.3 \
		man/det_query_qp.3 \
		man/det_read.3 \
		man/det_recv.3 \
		man/det_reg_mr.3 \
		man/det_reg_shared.3 \
		man/det_resize_cq.3 \
		man/det_scatter.3 \
		man/det_scatterv.3 \
		man/det_send.3 \
		man/det_wait_on_event.3 \
		man/det_write.3

EXTRA_DIST = libdet.map \
             det \
	     $(man3_MANS) \
	     ../LICENSE-DET-Library.txt
