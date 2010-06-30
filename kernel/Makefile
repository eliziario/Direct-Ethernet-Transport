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

#
# Makefile for the Direct Ethernet Driver
#

ifdef CONFIG_DET_PROFILING
EXTRA_CFLAGS += -g -O0 
endif

ifdef SUBDIRS
PWD := $(shell pwd)/$(SUBDIRS)
else
PWD := $(shell pwd)
endif

CONFIG_DET = m

obj-$(CONFIG_DET)	+= det.o

ver := $(shell uname -r)
KDIR := /lib/modules/$(ver)/build

# hack to detect Linux distributor backports of skb macros
SKB_MACROS := $(shell if [ -e $(KDIR)/include/linux/skbuff.h ]; then grep -c skb_mac_header $(KDIR)/include/linux/skbuff.h; else echo 0; fi)

EXTRA_CFLAGS += -DCONFIG_DET_DEBUG=1 -DHAVE_SKB_MACROS=$(SKB_MACROS)

det-objs		:= det_main.o		\
			   det_ioctl.o		\
			   det_ioctl32.o	\
			   det_event.o		\
			   det_nic.o		\
			   det_pd.o		\
			   det_cq.o		\
			   det_qp.o		\
			   det_mr.o		\
			   det_mw.o		\
			   det_co.o		\
			   det_datapath.o	\
			   det_protocol.o	\
			   det_loopback.o	\
			   det_procfs.o		\
			   det_memops.o

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	rm -rf $(det-objs) det.o det.ko det.mod.o det.mod.c .det*.cmd .tmp_versions

