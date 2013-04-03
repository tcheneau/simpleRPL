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

from tools import list_valid_interfaces, broadcast
from RplIcmp import RplSocket
from cPickle import dumps, loads
from copy import deepcopy
from message import Message
from address import Address, derive_address
from dodag import DODAG
from route_cache import Route
from icmp import ICMPv6, RPL_Header_map, DIS, DIO, \
                 DAO, DAO_ACK, \
                 RPL_Option_Solicited_Information, \
                 RPL_Option_DODAG_Configuration, \
                 RPL_Option_DAG_Metric_Container, \
                 RPL_Option_Prefix_Information, \
                 RPL_Option_RPL_Target, \
                 RPL_Option_Transit_Information, \
                 findOption, getAllOption
from rpl_constants import INFINITE_RANK, \
                          DEFAULT_INTERVAL_BETWEEN_DIS
from threading import Timer
from time import time
import cli
import global_variables as gv
import zmq
import sys

# logging facility
import logging
logger = logging.getLogger("RPL")

#
# Global variables for this module
#

dis_timer = None

#
# Functions
#

def process_loop(interfaces):
    context = zmq.Context()
    receiver = context.socket(zmq.PULL)
    cli_sock = context.socket(zmq.REP)
    receiver.bind("ipc://RPL_listeners")
    cli_sock.bind("ipc://RPL_CLI")

    poller = zmq.Poller()
    poller.register(receiver, zmq.POLLIN)
    poller.register(cli_sock, zmq.POLLIN)
    try:
        logger.info("starting message processing loop")

        # no need to send DIS message when the node is a DODAG Root
        # Note that it might not always make sense
        if gv.dodag_cache.is_empty():
            broadcast_dis(interfaces)

        while True:
            socks = dict(poller.poll())

            if receiver in socks and socks[receiver] == zmq.POLLIN:
                message = receiver.recv()
                message = loads(message)
                # this is not a self message
                if not gv.address_cache.is_assigned(message.src):
                    # do some real processing on message
                    handleMessage(interfaces, message)

                del message

            if cli_sock in socks and socks[cli_sock] == zmq.POLLIN:
                command = cli_sock.recv()
                cli.parse(cli_sock, command)

                del command

    except KeyboardInterrupt:
        global dis_timer

        try:
            dis_timer.cancel()
        except AttributeError:
            pass

def stop_processing():
    global handleMessage
    handleMessage = lambda a,b: None


def broadcast_dis(interfaces, options=""):
    """Broadcast a DIS message on all interfaces"""
    global dis_timer
    logger.debug("checking if a DIS broadcast is required")
    if gv.dodag_cache.is_empty():
        logger.debug("broadcasting DIS")
        broadcast(interfaces, str(DIS()) + str(options))
    else:
        logger.debug("no DIS is required")
    dis_timer = Timer(DEFAULT_INTERVAL_BETWEEN_DIS, broadcast_dis, kwargs= {'interfaces':interfaces})
    dis_timer.daemon = True
    dis_timer.start()

def handleMessage(interfaces, message):
    """Dispatch a message to the correct handler"""
    try:
        icmp_hdr = ICMPv6()
        icmp_hdr.parse(message.msg)
    except:
        logger.debug("unable to parse ICMPv6 header")

    if icmp_hdr.code in RPL_Header_map:
        message_name = RPL_Header_map[icmp_hdr.code].__name__
        logger.debug("received a %s message from %s" % (message_name, message.src))

        if not Address(message.src).is_linklocal():
            logger.debug("message source is not a Link-Local address, dropping message")
            return

        env = globals()
        try:
            handler = env["handle%s" % message_name]
        except KeyError:
            raise NotImplementedError("handler for %s messages not implemented yet" % message_name)
        handler(interfaces, message)


def handleDIO(interfaces, message):
    """Handler for DIO messages"""
    dio = DIO()
    payload = dio.parse(message.msg)
    consistent = True

    # attach to the very first RPL Instance we see
    if gv.global_instanceID == 0:
        gv.global_instanceID = dio.instanceID

    if dio.instanceID != gv.global_instanceID:
        logger.debug("ignoring DIO message address targeting a different RPL instance")
        return (None, None)

    try:
        dodag = gv.dodag_cache.get_dodag(dio.DODAGID, dio.version, dio.instanceID)[0]
    except IndexError:
        dodag = None

    if dodag and dodag.is_dodagRoot:
        logger.debug("This node is the DODAG Root for this DODAG, dropping DIO")
        return  # we should not process this DIO message any further
    elif dodag:  # this is a DIO, from the same RPL Instance, DODAG ID, Version
        logger.debug("Updating information on an existing DODAG")

        dodag.last_dio = time()

        if dio.MOP != dodag.MOP:
            raise NotImplementedError("Change MOP on an existing DODAG is not implemented")

        if dio.Prf != dodag.Prf:
            dodag.Prf = dio.Prf
            consistent = False

        # if the rank is INFINITE_RANK, remove the source node from the parent
        # list (and from the neighbor set)
        node = gv.neigh_cache.get_node(message.iface, message.src, dodag)
        if dio.rank == INFINITE_RANK and node:
            logger.debug("Node %s advertises a DIO message with infinite rank" % repr(Address(message.src)))
            updated = gv.neigh_cache.remove_node_by_address(dodag, message.src)
            if updated: consistent = False
            node = None

        # check if the node is a DIO parent and request its sub-DODAG to send DAO messages
        if node and node.dtsn < dio.DTSN and node in gv.neigh_cache.get_parent_list():
            logger.info("Parent %s has increased its DTSN field, scheduling a DAO message" % repr(Address(message.src)))
            dodag.downward_routes_reset()
            dodag.setDAOtimer()
            consistent = False

        dodag.DTSN.set_val(dio.DTSN)
    else:
        # we might have multiple older or newer versions of this DODAG still in
        # our cache
        old_dodags = gv.dodag_cache.get_dodag(dio.DODAGID, instanceID=dio.instanceID)

        try:
            if old_dodags[0].is_dodagRoot:
                logger.debug("This node is the DODAG Root for this DODAG, dropping DIO")
                return  # we should not process this DIO message any further

            least_recent = old_dodags[0].version
            most_recent = old_dodags[0].version
            least_recent_dodag = old_dodags[0]
            most_recent_dodag = old_dodags[0]
            for old_dodag in old_dodags:
                dodag_version = old_dodag.version
                if dodag_version < least_recent:
                    least_recent = dodag_version
                    least_recent_dodag = old_dodag
                if dodag_version > most_recent:
                    most_recent = dodag_version
                    most_recent_dodag = old_dodag

            if dio.version > most_recent:
                logger.debug("Receiving a DIO from a new version of the DODAG %s," \
                             " version %d < version %d" % (repr(Address(most_recent_dodag.dodagID)), most_recent_dodag.version.get_val(), dio.version ))
                # this should trigger global repair downward
                consistent = False

            if dio.version < least_recent:
                logger.debug("Receiving a DIO from an old version of the DODAG %s," \
                             " version %d < version %d" % (repr(Address(least_recent_dodag.dodagID)), dio.version, least_recent_dodag.version.get_val()))
                logger.debug("DIO dropped")
                return
        except IndexError:  # there was not older version of this DODAG
            pass

        # this is the first time we receive a DIO from this DODAG version
        # make sure that the DODAG is grounded, and that we support this
        # mode of operation.
        if dio.rank != INFINITE_RANK and dio.G == 1 and dio.MOP == 2:
            logger.info("Receiving a DIO from a new DODAG, adding it to our cache")
            dodag = DODAG(instanceID=dio.instanceID, version=dio.version,
                        G=dio.G, MOP=dio.MOP, Prf=dio.Prf, DTSN=dio.DTSN,
                        dodagID=dio.DODAGID,
                        interfaces=interfaces
                        )
            try: # if this is a newer version of a DODAG, some information needs to be passed down
                dodag.last_DAOSequence  = deepcopy(most_recent_dodag.last_DAOSequence)
                dodag.last_PathSequence = deepcopy(most_recent_dodag.last_PathSequence)
            except NameError:
                pass
            gv.dodag_cache.add(dodag)
            consistent = False
        else:
            logger.debug("DIO dropped")
            if dio.rank == INFINITE_RANK:
                logger.debug("Rank is INFINITE_RANK")
            if not dio.G:
                logger.debug("floating DODAG are not supported")
            if dio.MOP != 2:
                logger.debug("incompatible Mode of Operation (MOP)")
            return


    options = getAllOption(payload)

    logger.debug("DIO message contains the following options:")
    for opt in options:
        logger.debug("- " + opt.__class__.__name__)

        if isinstance(opt, RPL_Option_DODAG_Configuration):
            dodag.authenticated = opt.A
            dodag.PCS = opt.PCS
            dodag.DIOIntDoublings = opt.DIOIntDoubl
            dodag.DIOIntMin = opt.DIOIntMin
            dodag.DIORedundancyConst = opt.DIORedun
            dodag.MaxRankIncrease = opt.MaxRankIncrease
            dodag.MinHopRankIncrease = opt.MinHopRankIncrease
            dodag.OCP = opt.OCP
            dodag.DftLft = opt.DefLifetime
            dodag.LftUnit = opt.LifetimeUnit

        if isinstance(opt, RPL_Option_Prefix_Information):
            if opt.L:
                # TODO: prefix field contains an address that can be used for
                # on-link determination
                # (It means that one can send a packet directly to the parent,
                # meaning that the node can probably have a direct route)
                pass

            if opt.R:
                # TODO: process the R flags (only seems useful if the RPL target
                # option is required somehow)
                # - if L=O and R=1, the parent provides its own address in the
                # PIO, then the parent must advertise that address as a DAO
                # target
                pass

            if opt.A:
                if opt.prefix_len != 64:
                    logger.debug("PIO option: cannot derive an address from a prefix whose length is not 64 bits")
                    continue

                # take only the 64 first bits of the prefix
                prefix = opt.prefix[:8]

                # Compute an IID for each interface/physical address
                # and build an IPv6 address with this prefix for each interfaces
                addresses = []
                for iface in interfaces:
                    address = derive_address(iface, prefix)
                    if address:
                        addresses.append((address, iface))

                # assigns the new addresses
                for (address, iface) in addresses:
                    gv.address_cache.add(repr(address), iface, 64, opt.valid_lifetime, opt.preferred_lifetime)

                # make sure we record this prefix as one of the prefix we
                # advertise
                if prefix not in dodag.advertised_prefixes:
                    dodag.advertised_prefixes.append(prefix)


        if isinstance(opt, RPL_Option_DAG_Metric_Container):
            # TODO
            pass

    if dio.rank != INFINITE_RANK:
        gv.neigh_cache.register_node(message.iface, message.src, dodag, dio.rank, dio.DTSN)

    # update the DIO parent (the new parent could be from a different DODAG)
    updated = gv.neigh_cache.update_DIO_parent()
    if updated: consistent = False

    # if there is no DIO parent for this node, it must advertises an
    # INFINITE_RANK, so that it is not selected by its children
    parent = dodag.preferred_parent
    # there is no parent left for the node
    if not parent and dodag.rank != INFINITE_RANK:
        dodag.rank = INFINITE_RANK
        consistent = False

    # if we moved to a new DODAG version, now is a good time to clean up old
    # versions
    gv.dodag_cache.purge_old_versions()

    # happen when all neighboring nodes send a poison DIO message
    if gv.dodag_cache.is_empty():
        return

    if dodag.rank < dodag.lowest_rank_advertized:
        dodag.lowest_rank_advertized = dodag.rank

    # if not consistent, reset the trickle timer
    try:
        if not consistent:
            dodag.DIOtimer.hear_inconsistent()
            dodag.setDAOtimer()
        else:
            dodag.DIOtimer.hear_consistent()
    except AttributeError:
        pass

    return


def handleDIS(interfaces, message):
    """Handler for DIS messages"""
    dis = DIS()
    payload = dis.parse(message.msg)

    if gv.dodag_cache.is_empty():
        logger.debug("Dropping DIS message: the node does not belong to any DODAG")
        return

    # the following line returns None when no Solicited Information Option is
    # present
    solicited_information = findOption(payload, RPL_Option_Solicited_Information)

    version = None
    instanceID = None
    dodagID = None
    if solicited_information:
        if solicited_information.V:
            version = solicited_information.version

        if solicited_information.I:
            instanceID = solicited_information.instanceID

        if solicited_information.D:
            dodagID = solicited_information.DODAGID

    if Address(message.dst).is_RPL_all_nodes():
        # if there is no Solicited Information option, the trickle timer
        # records an inconsistency
        # or
        # if the Solicited Information option is set and it matches
        # one or more DODAG in the cache, the trickle timer associated
        # to these DODAG records an inconsistency

        logger.debug("DIS request is a multicast, "\
                      "sending DIO on all registered interfaces")

        dodags = gv.dodag_cache.get_dodag(dodagID, version, instanceID)

        for dodag in dodags:
            dodag.DIOtimer.hear_inconsistent()

    else:  # this is a unicast DIS
        if solicited_information:
            dodags = gv.dodag_cache.get_dodag(dodagID, version, instanceID)
            logger.debug("DIS request is unicast, with solicited information, "\
                          "sending unicast DIO(s)")
            for dodag in dodags:
                dodag.sendDIO(message.iface, message.src)
        else:  # this might not be in the RFC, but it makes sense to only send DIO from the active DODAG
            logger.debug("DIS request is unicast, with no solicited information, "\
                          "sending unicast DIO")
            dodag = gv.dodag_cache.get_active_dodag()
            if dodag:
                dodag.sendDIO(message.iface, message.src)


def handleDAO(interfaces, message):
    route_updated = False

    if not Address(message.dst).is_RPL_all_nodes() and not gv.address_cache.is_assigned(message.dst):
        logger.debug("DAO message is for a different node, dropping it")
        return

    is_multicast = Address(message.dst).is_RPL_all_nodes()
    dao = DAO()
    payload = dao.parse(message.msg)

    if gv.dodag_cache.is_empty() or dao.instanceID != gv.global_instanceID:
        logger.debug("Currently not participating in any DODAG for this instanceID, cannot process the DAO message")
        return

    if is_multicast and dao.K:
        logger.debug("Multicast DAO message can not request an acknowledgment (K=1)")
        return

    dodag = gv.dodag_cache.get_active_dodag()

    # when D flag is set in the DAO, check that the DODAGID matches the current DODAG
    if dao.D and dodag.dodagID != dao.DODAGID:
        logger.debug("DAO indicates a DODAG ID (%s) that does not match the active DODAG (%s), dropping it" % \
                     (repr(Address(dao.DODAGID)), repr(Address(dodag.dodagID))))
        return

    options = getAllOption(payload)

    targets = []
    last_opt_is_transit_info = False
    logger.debug("DAO message contains the following (%d) options:" % len(options))
    for opt in options:
        logger.debug("- " + opt.__class__.__name__)

        if isinstance(opt, RPL_Option_RPL_Target):
            if last_opt_is_transit_info:
                targets = []
                last_opt_is_transit_info = False
            targets.append(Route(repr(Address(opt.target_prefix)) + "/" + str(opt.prefix_len),
                                  message.src,
                                  message.iface,
                                  onehop=is_multicast))

        if isinstance(opt, RPL_Option_Transit_Information):
            last_opt_is_transit_info = True

            if opt.E:
                logger.debug("E flag is not supported for the RPL Transit Information Option, dropping DAO message")
                return

            if not opt.path_control == 0:
                logger.debug("Path control different than 0 is not supported, dropping DAO message")
                return

            if opt.path_lifetime == 0:  # this is a No-Path DAO
                route_updated += gv.route_cache.remove_routes(targets)
                for target in targets:
                    try:
                        dodag.downward_route_del(target)
                    except KeyError: pass
            elif opt.path_lifetime == 0xff:  # infinite lifetime
                for target in targets: dodag.downward_route_add(target)

            else:
                logger.debug("Path lifetime that is not null or infinite is not supported")
                return

            (removed_routes, new_routes) = dodag.get_filtered_downward_routes()
            logger.debug("routes to be removed (%d):\n" % len(removed_routes) + repr(removed_routes))
            logger.debug("routes to be added (%d):\n" % len(new_routes) + repr(new_routes))

            route_updated += gv.route_cache.remove_routes(removed_routes)
            route_updated += gv.route_cache.add_routes(new_routes)

    if dao.K:
        dodag.sendDAO_ACK(message.iface, message.src, dao.DAOsequence, dao.DODAGID)

    if route_updated:
        dodag.last_PathSequence += 1
        if not dodag.is_dodagRoot:
            logger.debug("Downward routes have been updated, scheduling a DAO message transmission")
            dodag.setDAOtimer()


def handleDAO_ACK(interfaces, message):
    """Handler for DAO_ACK messages"""
    dao_ack = DAO_ACK()
    payload = dao_ack.parse(message.msg)

    if gv.dodag_cache.is_empty() or dao_ack.instanceID != gv.global_instanceID:
        logger.debug("Currently not participating in any DODAG for this instanceID, cannot process the DAO-ACK message")
        return

    if payload != "":
        logger.debug("DAO-ACK message should not have any option, dropping the DAO-ACK")
        return

    if dao_ack.D:
        try:
            dodag = gv.dodag_cache.get_dodag(dodagID=dao_ack.DODAGID, instanceID=dao_ack.instanceID)[-1]
        except TypeError:
            logger.debug("DAO-ACK message indicates a DODAG ID(%s) that does not match any recorded DODAG %(s), dropping it" % \
                         (repr(Address(dao_ack.DODAGID)), repr(Address(dodag.dodagID))))
            return
    else:
        dodag = gv.dodag_cache.get_active_dodag()

    if dodag.DAO_ACK_source == message.src and \
       dodag.last_DAOSequence == dao_ack.DAOSequence and \
       dao_ack.Status == 0:
        logger.debug("DAO-ACK message received from %s, disabling the DAO retransmission timer" % message.src)
        dodag.DAO_trans_retry = 0
        dodag.cancelDAO_ACKtimer()
    else:
        logger.debug("DAO-ACK message does not match a previously sent DAO message")


def iface_listener(iface, RPL_socket):
    context = zmq.Context()
    sender = context.socket(zmq.PUSH)
    sender.connect("ipc://RPL_listeners")
    logger.info("starting listener on %s" % iface)

    while True:
        (msg, source, destination, iface) = RPL_socket.receive()
        m = Message(msg, source, destination, iface)
        sender.send(dumps(m))
        del m

    print "shutting down listener on %s" % iface
    sys.exit(0)


def register_interfaces(iface_list):
    """Open an ICMP socket for each interfaces.
    Return a dictionary using the interface name as the index
    (if iface_list is None, register all interfaces on the computer)"""
    if iface_list == None:
        iface_list = list_valid_interfaces()
        # remove the loopback interface
        try:
            iface_list.remove("lo")
        except ValueError:
            pass
    else:
    # check that the interface exists
        valid_if = list_valid_interfaces()

        for iface in iface_list:
            if not iface in valid_if:
                raise Exception("Interface %s does not exist" % iface)

    registered_iface = {}
    for iface in iface_list:
        registered_iface[iface] = RplSocket(iface)

    # we do not drop the privileges anymore, as it would prevent the Routing
    # module from working
    # RplSocket.dropCapabilities()

    return registered_iface
