SimpleRPL
=========

SimpleRPL is Linux-based implementation of the Routing Protocol for Low-Power and Lossy
Networks (RPL) as defined in [RFC 6550](https://tools.ietf.org/html/rfc6550).
It aims to complete the Linux Wireless Sensor Network ecosystem by bringing a
(hopefully) fully-compliant RPL implementation.

What is implemented? What are the implementations choices?
----------------------------------------------------------

* storing mode of operation with no multicast support (MOP value 2)
* act as a DODAG root or as a RPL router
* implement Objective function zero (RFC 6552). However, the rank increase is
  always a same fixed value.  This is because there is no feedback from the
  layer 2 or the layer 3 (yet), meaning that there can be no indication on the
  link quality.
* store unbounded number of DIO parents
* store one DAO parent at time
* support multiple interfaces (i.e. node can act as a bridge between two link-layer technology)

What is not implemented?
------------------------

* Routing metrics (as defined in RFC 6551) are not implemented, that is because
  there is currently no way to retrieve link quality information from IEEE 802.15.4
  links
* no support for floating DODAG
* no support for security (hence, if it is required, it should be implemented
  at the Link-Layer)
* no support for leaf function
* no Path Control support in DAO messages

Known limitations
-----------------

* only one DODAG root can exists in the network at once: if two root exists for the same DODAG, they will compete forever
* only one DODAG can be joined at once

Installation
------------

### List of dependencies

SimpleRPL is written in Python 2.x and requires the following libraries to be installed:

* [libnl3](http://www.infradead.org/~tgr/libnl/): a netlink library
* [pyzmq](http://pypi.python.org/pypi/pyzmq): python bindings for the famous ZeroMQ library
* [Routing](http://github.com/tcheneau/Routing/): a python wrapper around libnl3 that can manage routes, addresses and link layer addresses
* [RplIcmp](http://github.com/tcheneau/RplIcmp/): a python module that simplify operations through ICMP sockets in Python.
* [python-zmq](http://www.zeromq.org/bindings:python): Pythong binding for the Zero Message Queue (0mq) library
* [python-argparse](https://pypi.python.org/pypi/argparse): a python argument parser module (only needed if your Python version is < 2.7)


### Sytem-wide installation

From the root directory:

    $ python setup.py install


### Bulding up RPMs

You might prefer to build a package (so that you can easily deploy, upgrade or
remove SimpleRPL). All you need to do, from the root directory, is:

    $ python setup.py bdist_rpm

How to use
----------

### General information

SimpleRPL has been designed to be configured only through command line arguments.

Here is a list of arguments recognized by simpleRPL:

    $ simpleRPL.py --help
    usage: simpleRPL.py [-h] [-d DODAGID] [-i IFACE] [-R] [-v] [-p PREFIX]
    
    A simplistic RPL implementation
    
    optional arguments:
      -h, --help            show this help message and exit
      -d DODAGID, --dodagID DODAGID
                            RPL DODAG Identifier, has to be an IPv6 address that
                            is assigned on the node (optional)
      -i IFACE, --iface IFACE
                            network interfaces that RPL will listen on
      -R, --root            indicates if the nodes is the DODAG Root
      -v, --verbose         verbose output
      -p PREFIX, --prefix PREFIX
                            Routable prefix(es) that this node advertise (only for
                            DODAG root, optional)

Please note that due to its functioning SimpleRPL requires root access in the system.

### Running a RPL Router

If you want to start a RPL Router that listen on all interfaces:

     $ simpleRPL.py

In this case the node will join the first DODAG it receives a DIO from.

If you want a more verbose output: turn on debugging with "-v" argument (can be repeated up to five times for a even more verbose output ("-vvvvv")).

### Running a DODAG Root

A DODAG Root needs a global IPv6 address that is assigned on one of its interfaces as a DODAG ID 
Here is an example of a DODAG whose DODAG ID is 2001:aaaa::0202:0007:0001
(assigned on any of the interfaces) that advertised the 2001:aaaa::/64 prefix.

    $ simpleRPL.py -vvvvv -R -d 2001:aaaa::0202:0007:0001 -p 2001:aaaa::

### Getting information on a running instance

SimpleRPL comes with a companion tool that can talk to a running instance in
order to retrieve internal values or to trigger some administration function
(local repair, global repair, etc). This tool is name _cliRPL.py_. 

When SimpleRPL is started, it binds an IPC socket to the current directory. This
involves that _cliRPL.py_ needs to be invoked in the same directory.

Getting the list of available commands:

    $ cliRPL.py help
    show-preferred-parent: List the currently preferred (DIO) parent
    list-parents-verbose: List the (DIO) parents and their corresponding DODAG
    list-downward-routes: List the downward routes for the currently active DODAG
    local-repair: Trigger a local repair on the DODAG
    list-routes: List the routes assigned by the RPL implementation
    list-parents: List the (DIO) parents
    show-current-dodag: Show the currently active DODAG
    show-dao-parent: Show the DAO parent (for the currently active DODAG)
    subdodag-dao-update: Trigger the DODAG to increase its DTSN so that the sub-dodag will send a DAO message
    global-repair: Trigger a global repair on the DODAG (only valid for DODAG root)
    list-dodag-cache: List the content of the DODAG cache
    list-neighbors: List the neighbors
    help: List this help
    list-neighbors-verbose: List the neighbors and their corresponding DODAG

For example, if you want to trigger a global repair from the DODAG root:

    $ cliRPL.py global-repair
    global repair triggered, bumping new version for DODAG:
    DODAGID: 2001:aaaa::202:7:1; new version: 241


Interoperability with other implementations
-------------------------------------------

No interoperability test has been performed for the moment. This is because the
6LoWPAN stack that ships with the Linux kernel currently suffers from some
limitation. Once basic interoperability is achieved with other operating
systems, such as Contiki, interoperability test will become the topmost
priority.

A word on security
------------------

SimpleRPL is expected to be run on a secure environment (either completely
isolated, or using link-layer security). This is because we use it as a
prototype implementation. There is a lot of case where the implementation will
(purposely) stop working (because a function is not implemented yet). This
means that someone with evil intents could craft packets designed to shut down
the implementation.

Authors
-------

* Tony Cheneau (tony.cheneau@nist.gov or tony.cheneau@amnesiak.org)

Acknowledgment
--------------

This work was supported by the Secure Smart Grid project at the Advanced
Networking Technologies Division, NIST.

Conditions Of Use
-----------------

<em>This software was developed by employees of the National Institute of
Standards and Technology (NIST), and others.
This software has been contributed to the public domain.
Pursuant to title 15 Untied States Code Section 105, works of NIST
employees are not subject to copyright protection in the United States
and are considered to be in the public domain.
As a result, a formal license is not needed to use this software.

This software is provided "AS IS."
NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED
OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
AND DATA ACCURACY.  NIST does not warrant or make any representations
regarding the use of the software or the results thereof, including but
not limited to the correctness, accuracy, reliability or usefulness of
this software.</em>
