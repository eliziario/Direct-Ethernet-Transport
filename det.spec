# DET driver and user-mode library 1.1 Registry RPM SPEC file
#
# $Id: $

%{!?KVERSION: %define KVERSION %(uname -r)}
%{!?LIB_MOD_DIR: %define LIB_MOD_DIR /lib/modules/%{KVERSION}/updates}
%define LIB_MOD_DIR_NET %{LIB_MOD_DIR}/kernel/drivers/net

Name: det
Version: 1.1.0
Release: 1%{?dist}
Summary: An Ethernet RDMA kernel driver an user-mode verbs library

Group: System Environment/Libraries
License: Dual GPL/LGPL
Url: http://whatif.intel.com
Source: %{name}-%{version}.tar.gz
BuildRoot: %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%define debug_package %{nil}

%description
Package contains the kernel driver and user-mode verbs library for the
DET RDMA transport.

%package devel
Summary: Development files for libdet
Group: System Environment/Libraries
Requires: det

%description devel
Header files for the libdet library.

%package devel-static
Summary: Static development files for the libdet library.
Group: System Environment/Libraries
Requires: det-devel
 
%description devel-static
Static libraries for the libdet library.

%prep
%setup -q

%build
%configure 
make

%install
rm -rf %{buildroot}
make DESTDIR=%{buildroot} install
# remove unpackaged files from the buildroot
rm -f %{buildroot}%{_libdir}/*.la

install -d $RPM_BUILD_ROOT%{LIB_MOD_DIR_NET}/det
install -m 0744 $RPM_BUILD_DIR/%{name}-%{version}/kernel/det.ko $RPM_BUILD_ROOT%{LIB_MOD_DIR_NET}/det
install -d $RPM_BUILD_ROOT/etc/init.d
install -m 0755 $RPM_BUILD_DIR/%{name}-%{version}/usr/det $RPM_BUILD_ROOT/etc/init.d

%clean
rm -rf %{buildroot}
rm -rf $RPM_BUILD_DIR/%{name}-%{version}

%post
/sbin/ldconfig
/sbin/depmod -r -ae %{KVERSION}

###########################################################################
#  Update modprobe.conf to get low latency for the adapters we know about
###########################################################################
modconf=/etc/modprobe.conf
config_e1000=n
config_ixgb=n
config_ixgbe=n
for iface in `ls /sys/class/net`
do
    if [ -e /sys/class/net/$iface/device/subsystem_vendor ]; then
        vendor=`cat /sys/class/net/$iface/device/subsystem_vendor`
        if [ "$vendor" == "0x8086" ]; then
            if [ -e /sys/class/net/$iface/driver ]; then
		driver_dir=/sys/class/net/$iface/driver
            elif [ -e /sys/class/net/$iface/device/driver ]; then
		driver_dir=/sys/class/net/$iface/device/driver
            else
                continue
            fi
            
            for pci in `ls $driver_dir`; do
                driver=`find /sys/bus/pci/drivers -name $pci | sed -e "s/\/sys\/bus\/pci\/drivers\///" -e "s/\/.*//"`
                if [ "x`grep "options $driver" $modconf`" == "x" ]; then
                    case $driver in
                        e1000) config_e1000=y ;;
                         ixgb) config_ixgb=y  ;;
                        ixgbe) config_ixgbe=y ;;
                            *)                ;;
                    esac
                fi
                if [ "x`grep "alias $iface" $modconf`" == "x" ]; then
                    echo "alias $iface  $driver" >> $modconf
                fi
                break
            done
        fi
    fi
done
if [ $config_e1000 == y ]; then
    echo "options e1000 InterruptThrottleRate=0,0,0,0 RxIntDelay=0,0,0,0 TxIntDelay=0,0,0,0 RxAbsIntDelay=0,0,0,0 TxAbsIntDelay=0,0,0,0" >> $modconf
fi
if [ $config_ixgb == y ]; then
    echo "options ixgb RxIntDelay=0,0,0,0 TxIntDelay=0,0,0,0 IntDelayEnable=0,0,0,0" >> $modconf
fi
if [ $config_ixgbe == y ]; then
    echo "options ixgbe InterruptThrottleRate=0,0,0,0 RxBufferMode=0,0,0,0" >> $modconf
fi

########################################################
#  Setup driver initialization script for approprite O/S
########################################################
if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then        
    perl -i -ne 'if (m@^#!/bin/sh@) {
    print q@#!/bin/sh
#
# Bring up/down det
#
# chkconfig: 2345 15 85
# description: Activates/Deactivates DET Driver to \
#              start at boot time.
#
### BEGIN INIT INFO
# Provides:       det
### END INIT INFO
@;
                 } else {
                     print;
                 }' /etc/init.d/det

    if ! ( /sbin/chkconfig --del det > /dev/null 2>&1 ); then
        true
    fi
    if ! ( /sbin/chkconfig --add det > /dev/null 2>&1 ); then
        true
    fi
fi

if [ -f /etc/SuSE-release ]; then
    perl -i -ne 'if (m@^#!/bin/sh@) {
    print q@#!/bin/sh
### BEGIN INIT INFO
# Provides:       det
# Required-Start: $local_fs $network
# Required-Stop: 
# Default-Start:  2 3 5
# Default-Stop: 0 1 2 6
# Description:    Activates/Deactivates DET Driver to \
#                 start at boot time.
### END INIT INFO
@;
             } else {
                 print;
             }' /etc/init.d/det

    if ! ( /sbin/insserv det > /dev/null 2>&1 ); then
        true
    fi
fi

/etc/init.d/det start

%preun
/etc/init.d/det stop

###########################################################
#  Deactive driver initialization script for approprite O/S
###########################################################
if [ $1 = 0 ]; then  # 1 : Erase, not upgrade
    if [[ -f /etc/redhat-release || -f /etc/rocks-release ]]; then
        if ! ( /sbin/chkconfig --del det  > /dev/null 2>&1 ); then
            true
        fi
    fi
    if [ -f /etc/SuSE-release ]; then
        if ! ( /sbin/insserv -r det > /dev/null 2>&1 ); then
            true
        fi
    fi
fi

%postun -p /sbin/ldconfig

%files
%defattr(-,root,root,-)
%{_libdir}/libdet*.so.*
%dir %{LIB_MOD_DIR_NET}/det
%{LIB_MOD_DIR_NET}/det/det.ko
/etc/init.d/det

%files devel
%defattr(-,root,root,-)
%{_libdir}/*.so
%dir %{_includedir}/det
%{_includedir}/det/*
%dir %{_mandir}/man3
%{_mandir}/man3/*.3*

%files devel-static
%defattr(-,root,root,-)
%{_libdir}/*.a

%changelog
