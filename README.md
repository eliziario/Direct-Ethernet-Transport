Direct Ethernet Transport
====================

Use at your own risk.
---------------------

This is a adaptation of ttp://software.intel.com/en-us/articles/intel-direct-ethernet-transport/ to account for some slight changes in proc_fs on kernel since it was first published and a lot of other small quirks.

Right now I still have some Oops on the kernel driver mostly related to sleeping problems. I am working on it and will commit a fix as soon as get around having some time to do it.

To compile and install the kernel driver, take a look at the spec file and use rpmbuild, rpm is needed to install the kernel driver, but not the user-mode library

