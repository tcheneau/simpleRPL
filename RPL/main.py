# Conditions Of Use
#
# This software was developed by employees of the National Institute of
# Standards and Technology (NIST), and others.
# This software has been contributed to the public domain.
# Pursuant to title 15 Untied States Code Section 105, works of NIST
# employees are not subject to copyright protection in the United States
# and are considered to be in the public domain.
# As a result, a formal license is not needed to use this software.
#
# This software is provided "AS IS."
# NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED
# OR STATUTORY, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT
# AND DATA ACCURACY.  NIST does not warrant or make any representations
# regarding the use of the software or the results thereof, including but
# not limited to the correctness, accuracy, reliability or usefulness of
# this software.

import argparse
import os
import signal
import logging
import socket
import sys
from signal import SIGKILL

import RPL.global_variables as gv
from RPL.core import process_loop, register_interfaces, iface_listener, stop_processing
from RPL.route_cache import RouteCache
from RPL.address_cache import AddressCache
from RPL.dodag import DODAG, DODAG_cache
from RPL.neighbor_cache import NeighborCache
from RPL.lollipop import DEFAULT_SEQUENCE_VAL
from Routing import Link


# from http://code.activestate.com/recipes/65287-automatically-start-the-debugger-on-an-exception/
def info(type, value, tb):
   if hasattr(sys, 'ps1') or not sys.stderr.isatty():
      # we are in interactive mode or we don't have a tty-like
      # device, so we call the default hook
      sys.__excepthook__(type, value, tb)
   else:
      import traceback, pdb
      # we are NOT in interactive mode, print the exception...
      traceback.print_exception(type, value, tb)
      print
      # ...then start the debugger in post-mortem mode.
      pdb.pm()

sys.excepthook = info

def main(args):
    # read the arguments
    parser = argparse.ArgumentParser(description="A simplistic RPL implementation")

    parser.add_argument("-d", "--dodagID", type=str, action="append", default=[],
            help="RPL DODAG Identifier, has to be an IPv6 address that is assigned on the node (optional)")
    parser.add_argument("-i", "--iface", default=None, action="append",
            help="network interfaces that RPL will listen on")
    parser.add_argument("-R", "--root", default=False, action="store_true",
            help="indicates if the nodes is the DODAG Root")
    parser.add_argument("-v", "--verbose", default=False, action="count",
            help="verbose output")
    parser.add_argument("-p", "--prefix", action="append", default=[],
            help="Routable prefix(es) that this node advertise (only for DODAG root, optional)")
    args = parser.parse_args()

    if args.verbose == 0:
        level = logging.FATAL
    elif args.verbose == 1:
        level = logging.ERROR
    elif args.verbose == 2:
        level = logging.WARNING
    else:
        level = logging.DEBUG

    # set the logger
    logging.basicConfig(level=level, format='%(asctime)s|%(module)s:%(lineno)d|%(funcName)s|%(message)s')
    logger = logging.getLogger("RPL")

    # register all interfaces
    interfaces = register_interfaces(args.iface)

    # start the listener for all interfaces
    listener_processes = []
    for (iface, sock) in interfaces.iteritems():
        pid = os.fork()
        if pid == 0:
            os.close(0)  # close stdin
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            iface_listener(iface, sock)
            sys.exit(0)
        else:
            listener_processes.append(pid)

    # start routing cache (in order to clean up new routes upon exit)
    logger.warning("registering routing cache")
    gv.route_cache = RouteCache()

    logger.warning("registering RPL neighbor cache")
    gv.neigh_cache = NeighborCache()

    #populate address cache (in order to clean up new addresses upon exit)
    logger.warning("registering address cache")
    gv.address_cache = AddressCache()

    # register Netlink Link Cache facility
    logger.warning("registering Netlink link cache")
    gv.link_cache = Link()

    gv.dodag_cache = DODAG_cache()

    if args.root:
        if args.dodagID == []:
            raise NotImplementedError()
        else:
            # convert the "printable" prefixes into "network" format
            prefixes = [socket.inet_pton(socket.AF_INET6, prefix) for prefix in args.prefix]
            for dodag in args.dodagID:
                gv.dodag_cache.add(DODAG(instanceID=0,
                                         version=DEFAULT_SEQUENCE_VAL,
                                         G=1,
                                         MOP=2,
                                         Prf=0,
                                         DTSN=DEFAULT_SEQUENCE_VAL,
                                         dodagID=dodag,
                                         advertised_prefixes=prefixes,
                                         interfaces=interfaces,
                                         active=True,
                                         is_root=True))

    # start the process loop that listen for all interfaces
    try:
        process_loop(interfaces)

    finally: # things need to be cleaned up before exiting
        logger.warning("main loop interrupted, program is exiting")
        stop_processing()

        # performs some cleanup
        for pid in listener_processes:
            os.kill(pid, SIGKILL)

        # poison every DODAG the node is attached to
        gv.dodag_cache.poison_all()

        # clean up the resources allocated to the DODAGs
        gv.dodag_cache.cleanup()

        gv.route_cache.empty_cache()
        gv.address_cache.emptyCache()

        logging.shutdown()
