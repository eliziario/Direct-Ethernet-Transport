#*******************************************************************************/
#
#  Copyright(c) 1999 - 2005 Intel Corporation. All rights reserved.
#  
#  This program is free software; you can redistribute it and/or modify it 
#  under the terms of the GNU General Public License as published by the Free 
#  Software Foundation; either version 2 of the License, or (at your option) 
#  any later version.
#  
#  This program is distributed in the hope that it will be useful, but WITHOUT 
#  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or 
#  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for 
#  more details.
#  
#  You should have received a copy of the GNU General Public License along with
#  this program; if not, write to the Free Software Foundation, Inc., 59 
#  Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#  
#  The full GNU General Public License is included in this distribution in the
#  file called LICENSE.
#  
#  Contact Information:
#  http://whatif.intel.com
#  Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
#
#*******************************************************************************/
# $Id: $

EXTRA_DIST = det_co.c \
             det_cq.c \
             det_datapath.c \
             det_debug.h \
             det_driver.h \
             det_event.c \
             det.h \
             det_ioctl32.c \
             det_ioctl32.h \
             det_ioctl.c \
             det_ioctl.h \
             det_loopback.c \
             det_main.c \
             det_memops.c \
             det_memops.h \
             det_mr.c \
             det_mw.c \
             det_nic.c \
             det_pd.c \
             det_perf.h \
             det_procfs.c \
             det_protocol.c \
             det_protocol.h \
             det_qp.c \
             det_types32.h \
             det_types.h \
             det_verbs.h \
             Makefile-module \
             ../LICENSE-DET-Driver.txt

all: det.ko

det.ko:
	mv Makefile Makefile~
	cp $(srcdir)/Makefile-module Makefile
	chmod 0644 Makefile
	make SUBDIRS=$(srcdir)
	mv Makefile~ Makefile

clean:
	make -f Makefile-module clean

