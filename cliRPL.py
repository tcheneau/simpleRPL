#!/bin/env python

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

"""
A very simple command line interface for simpleRPL
"""

import zmq
import sys

def usage():
    """Print usage"""
    usage = "%s command\n" % sys.argv[0]
    usage += "type 'help' as a command for more information"
    return usage

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print usage()
        sys.exit(-1)

    context = zmq.Context()
    cli_sock = context.socket(zmq.REQ)
    cli_sock.connect("ipc://RPL_CLI")

    try:
        cli_sock.send(sys.argv[1], zmq.DONTWAIT)
    except zmq.ZMQError, err:
        print "unable to communicate with the simpleRPL daemon: %s" % err
        sys.exit(-1)
    print cli_sock.recv()
