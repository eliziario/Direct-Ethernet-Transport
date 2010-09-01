This directory contains examples for using Intel(R) Direct Ethernet Transport
(Intel(R) DET) verbs APIs.  The following RPM packages must be installed to
successfully compile and run these examples:

det-1.1.0-1
det-devel-1.1.0-1

All example programs can be built buy invoking make(1) without arguments.
There is currently only one example program.

Example Descriptions
--------------------
det_perf: This example utilizes all of the primary DET interfaces to construct
          a client/server performance test.  It performs a ping pong test to
          measure one-way latency as well as burst tests to measure packet
          rate for send, RDMA write, and RDMA read.

          DET verbs do not define a method for discovering the QP/MAC address
          information needed to transition a queue pair to the connected
          state.  This example uses TCP/IP as the method to exchange QP/MAC
          information.

          Use the -? option for a list of options.  In its most simplest form,
          run the server without arguments and -h <server_name> on the client.
          The default Ethernet interface is eth0.
