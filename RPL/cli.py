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
Command line interfaces
"""

import logging
import global_variables as gv
from address import Address

logger = logging.getLogger("RPL")

COMMANDS = \
        {"show-current-dodag": "Show the currently active DODAG",
         "list-dodag-cache": "List the content of the DODAG cache",
         "list-neighbors": "List the neighbors",
         "list-neighbors-verbose": "List the neighbors and their corresponding DODAG",
         "show-preferred-parent": "List the currently preferred (DIO) parent",
         "list-parents": "List the (DIO) parents",
         "list-parents-verbose": "List the (DIO) parents and their corresponding DODAG",
         "show-dao-parent": "Show the DAO parent (for the currently active DODAG)",
         "global-repair": "Trigger a global repair on the DODAG (only valid for DODAG root)",
         "local-repair": "Trigger a local repair on the DODAG",
         "subdodag-dao-update" : "Trigger the DODAG to increase its DTSN so that the sub-dodag will send a DAO message",
         "list-routes" : "List the routes assigned by the RPL implementation",
         "list-downward-routes": "List the downward routes for the currently active DODAG",
         "help": "List this help",
         }

def parse(cli_sock, command):
    """
    Parse a command from the CLI
    """
    resp = "unrecognized command, try 'help'"

    logger.debug("processing command %s", command)

    if command == "help":
        resp = "\n".join(["%s: %s" % (command, desc) for (command, desc) in COMMANDS.iteritems()])
    elif command == "show-current-dodag":
        dodag = gv.dodag_cache.get_active_dodag()
        if dodag:
            resp = str(dodag)
        else:
            resp = "This node has not joined any DODAG yet"
    elif command == "list-dodag-cache":
        dodags = gv.dodag_cache.get_dodag()
        resp = "\n".join([str(dodag) for dodag in dodags])
    elif command =="list-neighbors":
        neighbors = gv.neigh_cache.get_neighbor_list()
        resp = "\n".join([str(neigh) for neigh in neighbors])
    elif command == "list-neighbors-verbose":
        neighbors = gv.neigh_cache.get_neighbor_list()
        resp = "\n".join([str(neigh)+'\n'+str(neigh.dodag) for neigh in neighbors])
    elif command == "show-preferred-parent":
        resp = str(gv.neigh_cache.get_preferred())
    elif command == "show-dao-parent":
        dodag = gv.dodag_cache.get_active_dodag()
        if dodag:
            resp = str(dodag.preferred_parent)
        else:
            resp = "This node has not joined any DODAG yet"
    elif command == "list-parents":
        parents = gv.neigh_cache.get_parent_list()
        resp = "\n".join([str(parent) for parent in parents])
    elif command == "list-parents-verbose":
        parents = gv.neigh_cache.get_parent_list()
        resp = "\n".join([str(parent)+'\n'+str(parent.dodag) for parent in parents])
    elif command == "global-repair":
        dodags = gv.dodag_cache.get_dodag(is_root=True)
        resp = "global repair triggered, bumping new version for DODAG:\n"
        for dodag in dodags:
            dodag.version += 1
            dodag.DIOtimer.hear_inconsistent()
            resp += "DODAGID: %s; new version: %d" % (repr(Address(dodag.dodagID)), dodag.version.get_val())
    elif command == "local-repair":
        dodags = gv.dodag_cache.get_dodag()
        resp = "local repair triggers on the following DODAG:\n"
        for dodag in dodags:
            dodag.DIOtimer.hear_inconsistent()
            resp += "DODAGID: %s; version: %d" % (repr(Address(dodag.dodagID)), dodag.version.get_val())
    elif command == "subdodag-dao-update":
        dodags = gv.dodag_cache.get_dodag()
        resp = "incrementing DTSN field for the following DODAG:\n"
        for dodag in dodags:
            dodag.DTSN += 1
            dodag.DIOtimer.hear_inconsistent()
            resp += "DODAGID: %s; version: %d; new DTSN: %d\n" % (repr(Address(dodag.dodagID)), dodag.version.get_val(), dodag.DTSN.get_val())
    elif command == "list-routes":
        resp = "list of routes assigned on the node:\n"
        resp += "\n".join([str(route) for route in gv.route_cache.route_cache])
    elif command == "list-downward-routes":
        dodag = gv.dodag_cache.get_active_dodag()
        if dodag:
            resp = "list of downward routes on the current DODAG %s" % dodag.dodagID
            resp += "\n".join([str(route) for route in dodag.downward_routes_get()])
        else:
            resp = "This node has not joined any DODAG yet"

    else:
        logger.debug("command %s not recognized" % command)

    cli_sock.send(resp)
