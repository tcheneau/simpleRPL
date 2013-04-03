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
Defines a DODAG object that represent a single DODAG version.
Also defines a DODAG cache that stores multiple DODAGs belonging to a same RPL instance.
"""

from trickle import trickleTimer
from rpl_constants import INFINITE_RANK, \
                          ROOT_RANK, \
                          DEFAULT_PATH_CONTROL_SIZE, \
                          DEFAULT_DIO_INTERVAL_MIN ,\
                          DEFAULT_DIO_INTERVAL_DOUBLINGS, \
                          DEFAULT_DIO_REDUNDANCY_CONSTANT, \
                          DEFAULT_MIN_HOP_RANK_INCREASE, \
                          DEFAULT_MAX_RANK_INCREASE, \
                          DEFAULT_DAO_DELAY, \
                          DEFAULT_DAO_ACK_DELAY, \
                          DEFAULT_DAO_MAX_TRANS_RETRY, \
                          DEFAULT_DAO_NO_PATH_TRANS

from tools import broadcast, ALL_RPL_NODES
from icmp import DAO, DAO_ACK, DIO, RPL_Option_DODAG_Configuration, RPL_Option_Prefix_Information, \
                 RPL_Option_Transit_Information, RPL_Option_RPL_Target
import global_variables as gv
from address import Address
from lollipop import Lollipop
from route_cache import Route

from threading import RLock
from functools import partial
import of_zero as of
from math import floor
import time
import socket
from threading import Timer

import logging
logger = logging.getLogger("RPL")

def undef(* args, ** kwargs):
    """replace existing method when we want to make sure they are not called anymore"""
    logger.debug("a DODAG that has been scheduled for removal is still in use")
    raise ReferenceError("this method should not be called")


class DODAG(object):
    """A DODAG ( part of a RPL instance)"""
    dodagID                = r"\0" * 16
    is_dodagRoot           = False
    DODAGVersionNumber     = 0
    last_DAOSequence       = 0  # used during DAO - DAO_ACK exchanges
    last_PathSequence      = 0
    lowest_rank_advertized = INFINITE_RANK
    rank                   = INFINITE_RANK

    # learned from the DODAG configuration option
    authenticated      = 0
    PCS                = DEFAULT_PATH_CONTROL_SIZE
    DIOIntDoublings    = DEFAULT_DIO_INTERVAL_DOUBLINGS
    DIOIntMin          = DEFAULT_DIO_INTERVAL_MIN
    DIORedundancyConst = DEFAULT_DIO_REDUNDANCY_CONSTANT
    MaxRankIncrease    = DEFAULT_MAX_RANK_INCREASE
    MinHopRankIncrease = DEFAULT_MIN_HOP_RANK_INCREASE
    OCP                = 0
    DftLft             = 0xff  # represents Infinity
    LftUnit            = 0xffff


    def __init__(self, instanceID, version, \
                 G, MOP, Prf, DTSN, \
                 dodagID, \
                 interfaces, advertised_prefixes=[], active=False, is_root=False):
        # TODO:
        # - remove timer (not sure what it actually does)
        #   (expiry may trigger No-Path advertisements or immediately deallocate
        #   the DAO entry if no DAO parents exists)
        self.__lock               = RLock()
        self.instanceID           = instanceID
        self.version              = Lollipop(version)
        self.dodagID              = dodagID
        self.G                    = G
        self.MOP                  = MOP
        self.Prf                  = Prf
        self.DTSN                 = Lollipop(DTSN)
        self.active               = active
        self.advertised_prefixes  = advertised_prefixes
        self.last_DAOSequence     = Lollipop()  # used during DAO - DAO_ACK exchanges
        self.last_PathSequence    = Lollipop()
        self.DAO_ACK_source       = None
        self.DAO_ACK_source_iface = None
        self.DAO_trans_retry      = 0
        self.downward_routes      = set()  # set of tuple in the form of (destination, prefix_len, prefix)
        self.preferred_parent     = None

        # cleanup purposes
        self.no_path_routes       = set()  # store the routes for which we received a No-Path DAO
        self.no_path_routes_trans = 0  # how many times the No-Path DAO have been transmitted

        self.interfaces = interfaces
        if is_root:
            self.is_dodagRoot = True
            self.rank = ROOT_RANK
            if not gv.address_cache.is_assigned(dodagID):
                raise Exception("DODAG ID must be an address assigned to this node")
            if Address(dodagID).is_linklocal():
                raise Exception("DODAG ID must be a routable address (not a link local address)")
            self.dodagID = str(Address(dodagID))
        else:
            self.rank = INFINITE_RANK

        # import objective function related function
        self.compute_rank_increase = partial(of.compute_rank_increase, self)
        self.OCP                   = of.OCP

        self.last_dio = time.time()

        self.setDIOtimer()

        if self.is_dodagRoot:
            self.DIOtimer.hear_inconsistent()


    def sendDIO(self, iface=None, destination=None, dodag_shutdown=False):
        """Send a DIO message:
        - iface: if specified, this is the interface where messages are going
          out, if not, message are broadcasted on all registered interfaces
        - destination: if this is a unicast DIO, destionation is the
          destination address. If destination is not specified, the message is
          sent to the RPL-all-routers multicast address
        - dodag_shutdown: this function also schedule a DAO message to be sent. During
          the shutdown procedure or when a DODAG version is phased out, this is
          not a desirable behavior, as the DAO should be sent right away.
        """
        logger.info("sending DIO message for %s (version %d)" % (repr(Address(self.dodagID)), self.version.get_val()))

        if self.advertised_prefixes:
            extra_option = "".join([str(RPL_Option_Prefix_Information(prefix_len=64, L=0, A=1, R=0,
                                                                      prefix=prefix,
                                                                      valid_lifetime=0xFFFFFFFF, # infinite lifetime
                                                                      preferred_lifetime=0xFFFFFFFF))
                                    for prefix in self.advertised_prefixes])
        else:
            extra_option = ""

        DIO_message = str(DIO(instanceID=self.instanceID, version=self.version.get_val(),
                          rank=self.rank, G=self.G, MOP=self.MOP,
                          Prf=self.Prf, DTSN=self.DTSN.get_val(), flags=0, reserved=0,
                          DODAGID=self.dodagID)) + \
                      str(RPL_Option_DODAG_Configuration(A=self.authenticated,
                                                         PCS=self.PCS,
                                                         DIOIntDoubl=self.DIOIntDoublings,
                                                         DIOIntMin=self.DIOIntMin,
                                                         DIORedun=self.DIORedundancyConst,
                                                         MaxRankIncrease=self.MaxRankIncrease,
                                                         MinHopRankIncrease=self.MinHopRankIncrease,
                                                         OCP=self.OCP,
                                                         DefLifetime=self.DftLft,
                                                         LifetimeUnit=self.LftUnit)) +\
                      extra_option

        if iface and destination:
            self.interfaces[iface].send(destination, DIO_message)
        else:
            broadcast(self.interfaces, DIO_message)

        # DAO message are sent after a short interval  when DIO messages are
        # sent
        if not self.is_dodagRoot and not dodag_shutdown:
            self.setDAOtimer()

        del DIO_message


    def sendDAO(self, iface=None, destination=None, retransmit=False, nopath=False):
        """Send a DAO message to its DAO parent (by default)
        Build the target list on the fly
        nopath parameters indicates that the node must announce all its downward routes as no-path"""

        assert self.active or nopath

        logger.info("sending DAO message for %s (version %d)" % (repr(Address(self.dodagID)), self.version.get_val()))

        if not retransmit: self.last_DAOSequence += 1

        # if no destination is specified, find the DAO parent
        if not destination:
            # here, destination is None if no DAO parent exists
            destination = self.preferred_parent
            try:
                iface = destination.iface
                destination = destination.address
            except:
                destination = None
                iface = None
            assert destination != ALL_RPL_NODES

        # build the RPL Target Options for the addresses allocated on the node
        targets_opt = "".join([str(RPL_Option_RPL_Target(prefix_len=128, target_prefix=str(Address(address))))
                               for (address, pref_len, nh_iface) in gv.address_cache])

        # the Parent Address field is not needed because the node is in Storing Mode
        transit_inf_opt = str(RPL_Option_Transit_Information(path_control=0,
                                                             path_sequence=self.last_PathSequence.get_val(),
                                                             path_lifetime=0x00 if nopath else self.DftLft,
                                                             parent_address=""))

        no_path_targets_opt = ""
        no_path_transit_inf_opt = ""

        if destination and Address(destination).is_RPL_all_nodes():
            logger.debug("sending DAO message to All-RPL-Nodes multicast address: %s" % destination)

            DAO_header = str(DAO(instanceID=self.instanceID, K=0, DAOsequence=self.last_DAOSequence.get_val(), \
                            DODAGID=self.dodagID))

        elif destination and Address(destination).is_linklocal():
            # because the K flag is set, we set a timer for receiving a DAO-ACK
            self.DAO_ACK_source = destination
            self.DAO_ACK_source_iface = iface
            self.setDAO_ACKtimer()

            logger.debug("sending DAO message to a Link-Local address: %s" % destination)
            DAO_header = str(DAO(instanceID=self.instanceID, K=1, DAOsequence=self.last_DAOSequence.get_val(), \
                            DODAGID=self.dodagID))

            with self.__lock:
                # build the RPL Target Options from the list of downward routes
                targets = [tuple(route.target.split("/")) for route in self.downward_routes]
                targets_opt += "".join([str(RPL_Option_RPL_Target(prefix_len=int(preflen), target_prefix=str(Address(prefix))))
                                        for (prefix, preflen) in targets])

                if self.no_path_routes_trans < DEFAULT_DAO_NO_PATH_TRANS and self.no_path_routes:
                    logger.debug("advertising additional routes that need to be removed")
                    self.no_path_routes_trans += 1

                    # there is no need to propagate the No-Path information when an alternative path exists locally
                    reachable_targets = set([route.target for route in self.downward_routes])
                    no_path_targets = [tuple(route.target.split("/")) for route in self.no_path_routes if route.target not in reachable_targets]

                    if no_path_targets:
                        no_path_targets_opt = "".join([str(RPL_Option_RPL_Target(prefix_len=int(preflen), target_prefix=str(Address(prefix))))
                                                for (prefix, preflen) in no_path_targets])

                        no_path_transit_inf_opt = str(RPL_Option_Transit_Information(path_control=0,
                                                                                    path_sequence=self.last_PathSequence.get_val(),
                                                                                    path_lifetime=0x00,
                                                                                    parent_address=""))
                else:
                    self.no_path_routes = set()
        else:
            logger.debug("destination address %s is not a Link-Local address or a Multicast address, dropping command" % destination)
            return

        if nopath:
            DAO_message = DAO_header + targets_opt + no_path_targets_opt + transit_inf_opt
        else:
            DAO_message = DAO_header + targets_opt + transit_inf_opt + no_path_targets_opt + no_path_transit_inf_opt

        if iface and destination:
            self.interfaces[iface].send(destination, DAO_message)
        else:
            broadcast(self.interfaces, DAO_message)


    def sendTwoDAOs(self):
        """Send a multicast DAO, for the node's own destination and a unicast
        DAO to announce all downwards routes known to the node
        (only if the DODAG is currently active"""
        if self.active:
            self.sendDAO(destination=ALL_RPL_NODES, retransmit=True)
            self.sendDAO()


    def sendDAO_ACK(self, iface, destination, DAOsequence, dodagID = None):
        logger.info("sending DAO-ACK to %s" % repr(Address(destination)))

        if dodagID:
            DAO_ACK_message = str(DAO_ACK(instanceID=self.instanceID,
                                          DAOSequence = DAOsequence,
                                          Status = 0,  # unqualified acceptance
                                          DODAGID = dodagID
                                          ))
        else:
            DAO_ACK_message = str(DAO_ACK(instanceID=self.instanceID,
                                          DAOSequence = DAOsequence,
                                          Status = 0  # unqualified acceptance
                                          ))


        self.interfaces[iface].send(destination, DAO_ACK_message)


    def setDIOtimer(self):
        """(Re)set the DIO timer"""
        try:
            self.DIOtimer.cancel()
        except:
            pass

        self.DIOtimer = trickleTimer(self.sendDIO, {}, \
                                         Imin=0.001 * 2 ** self.DIOIntMin, \
                                         Imax=self.DIOIntDoublings, \
                                         k=self.DIORedundancyConst)
        self.DIOtimer.start()


    def setDAOtimer(self):
        """Set the DAO timer, ignore new calls when timer is armed.
        This function ensures that DAO messages is sent after the DEFAULT_DAO_DELAY seconds (so
        that more routes could be aggregated)
        """
        try:
            if not self.DAOtimer.is_alive():
                self.DAOtimer = Timer(DEFAULT_DAO_DELAY, self.sendTwoDAOs)
            else:
                return
        except AttributeError:
            self.DAOtimer = Timer(DEFAULT_DAO_DELAY, self.sendTwoDAOs)

        self.DAOtimer.start()


    def setDAO_ACKtimer(self):
        """Set the DAO ack timer, to retransmit DAO when it is not acknowledged in a timely fashion"""

        self.cancelDAO_ACKtimer()

        if self.DAO_trans_retry >= DEFAULT_DAO_MAX_TRANS_RETRY:
            self.DAO_trans_retry = 0

            # the destination (self.DAO_ACK_source) seems unreachable
            # hence, it should be removed, and if it was the DIO parent, a new
            # DIO parent must be found
            gv.neigh_cache.remove_node_by_address(self, self.DAO_ACK_source)
            updated = gv.neigh_cache.update_DIO_parent()
            if updated: self.DIOtimer.hear_inconsistent()

            return

        self.DAO_trans_retry += 1


        self.DAO_ACKtimer = Timer(DEFAULT_DAO_ACK_DELAY, self.sendDAO, kwargs={'iface':self.DAO_ACK_source_iface, 'destination':self.DAO_ACK_source, 'retransmit':True})
        self.DAO_ACKtimer.start()


    def cancelDAO_ACKtimer(self):
        """cancel the DAO ACK timer (when the acknowledgment message is received)"""
        try:
            self.DAO_ACKtimer.cancel()
        except:
            pass


    def downward_route_add(self, route):
        with self.__lock:
            if not gv.address_cache.is_assigned(route.target.split("/")[0]):
                self.downward_routes.add(route)


    def downward_route_del(self, route):
        with self.__lock:
            if route in self.downward_routes:
                self.downward_routes.remove(route)
                self.no_path_routes_trans = 0
                self.no_path_routes.add(route)


    def downward_routes_reset(self):
        logger.debug("Removing all downward routes for this DODAG (%s)" % str(Address(self.dodagID)))
        with self.__lock:
            gv.route_cache.remove_routes(self.downward_routes)
            self.downward_routes = set()


    def downward_routes_remove_by_nexthop(self, address):
        logger.debug("Removing all downward routes going through %s" % address)

        updated = False

        with self.__lock:
            for route in self.downward_routes.copy():
                if address == route.nexthop:
                    self.downward_route_del(route)
                    if self.active:
                        updated += gv.route_cache.remove_route(route)

        return updated


    def downward_routes_get(self):
        with self.__lock:
            return self.downward_routes.copy()


    def get_filtered_downward_routes(self):
        new_routes = {}
        removed_routes = []

        with self.__lock:
            for route in self.downward_routes:
                    if route.target not in new_routes:
                        new_routes[route.target] = (route.nexthop, route.nexthop_iface, route.onehop)
                        continue

                    (current_nexthop, current_nexthop_iface, current_onehop) = new_routes[route.target]

                    # only one route can be one hop to a destination
                    # (unless a node uses two link local addresses)
                    assert not (current_onehop and route.onehop)

                    # one hop route takes precedence over multiphop routes
                    if current_onehop:
                        removed_routes.append(route)
                        continue

                    # one hop route takes precedence over multihop routes
                    if route.onehop:
                        removed_routes.append(Route(route.target, current_nexthop, current_nexthop_iface, current_onehop))
                        new_routes[route.target] = (route.nexthop, route.nexthop_iface, route.onehop)
                        continue

                    node = gv.neigh_cache.get_node(route.nexthop_iface, route.nexthop, self)
                    current_node = gv.neigh_cache.get_node(current_nexthop_iface, current_nexthop, self)

                    assert id(node) != id(current_node)

                    if not node:
                        removed_routes.append(route)
                        continue

                    if not current_node:
                        removed_routes.append(Route(route.target, current_nexthop, current_nexthop_iface, current_onehop))
                        new_routes[route.target] = (route.nexthop, route.nexthop_iface, route.onehop)
                        continue

                    if self.DAGRank(node.rank) >= self.DAGRank(current_node.rank):
                        removed_routes.append(route)
                    else:
                        new_routes[route.target] = (route.nexthop, route.nexthop_iface, route.onehop)
                        removed_routes.append(Route(route.target, current_nexthop, current_nexthop_iface, current_onehop))

            new_routes = [Route(target, nexthop, nexthop_iface, onehop) for (target, (nexthop, nexthop_iface, onehop)) in new_routes.items()]

            return (removed_routes, new_routes)


    def DAGRank(self, rank):
        return floor(float(rank)/ self.MinHopRankIncrease)


    def poison(self, shutdown=False):
        logger.debug("Poisoning DODAG %s (version %d)" % (repr(Address(self.dodagID)), self.version.get_val()))
        # send a No-PATH DAO message only when the RPL router stops and the
        # downward routes won't be accessible anymore
        if shutdown:
            self.sendDAO(nopath=True, destination=ALL_RPL_NODES)
            if self.preferred_parent:
                self.sendDAO(nopath=True)
        self.rank = INFINITE_RANK
        self.sendDIO(dodag_shutdown=True)


    def cleanup(self):
        # so this ugly, but it's very hard to make sure the DODAG object has
        # really been destroyed, instead, we make sure these methods can never
        # be called again
        self.sendDAO = undef
        self.sendDIO = undef
        self.sendDAO_ACK = undef
        self.setDAOtimer = undef
        self.setDIOtimer = undef
        self.setDAO_ACKtimer = undef

        # disable all the running timers
        try: self.DIOtimer.cancel()
        except: pass
        try: self.DAOtimer.cancel()
        except: pass
        try: self.DAO_ACKtimer.cancel()
        except: pass

        del self.DIOtimer
        try: del self.DAOtimer
        except: pass
        try: del self.DAO_ACKtimer
        except: pass

        gv.neigh_cache.remove_nodes_by_dodag(self)



    def __eq__(self, other):
        """
        Compare DODAG Versions between two DODAGs
        """
        return self.instanceID == other.instanceID and \
               self.version    == other.version and \
               self.dodagID    == other.dodagID


    def __str__(self):
        """Print a text presentation of the DODAG parameters"""
        textdag = "DODAG Identifier: {0}\n" \
                  "RPL Instance Identifier: {1}\n" \
                  "DODAG Root: {2}\n" \
                  "Grounded: {3}\n" \
                  "Mode of operation: {4}\n" \
                  "Administrative Preference: {5}\n" \
                  "DTSN: {6}\n"  \
                  "DODAG Version Number: {7}\n" \
                  "Rank: {8}\n" \
                  "Lowest Rank ever recorded: {9}\n" \
                  "Authenticated: {10}\n" \
                  "Path Control Size: {11}\n" \
                  "DIO Interval Doublings: {12}\n" \
                  "DIO Interval Minimum: {13}\n" \
                  "DIO Redundancy Constant: {14}\n" \
                  "Max Rank Increase: {15}\n" \
                  "Min Hop Rank Increase: {16}\n" \
                  "Objective Code Point: {17}\n" \
                  "Default Lifetime: {18}\n" \
                  "Lifetime Unit: {19}\n" \
                  "This is the active DODAG: {20}\n" \
                  "Advertised prefixes: {21}\n" \
                  "Last DIO received at: {22}\n".format(
                          repr(Address(self.dodagID)),
                          self.instanceID,
                          self.is_dodagRoot and "yes" or "no",
                          self.G and "yes" or "no",
                          self.MOP,
                          self.Prf,
                          self.DTSN.get_val(),
                          self.version.get_val(),
                          self.rank,
                          self.lowest_rank_advertized,
                          self.authenticated and "yes" or "no",
                          self.PCS,
                          self.DIOIntDoublings,
                          self.DIOIntMin,
                          self.DIORedundancyConst,
                          self.MaxRankIncrease,
                          self.MinHopRankIncrease,
                          self.OCP,
                          self.DftLft,
                          self.LftUnit,
                          self.active and "yes" or "no",
                          " ".join([socket.inet_ntop(socket.AF_INET6, prefix[:8] + "\x00" * 8) for prefix in self.advertised_prefixes]),
                          time.ctime(self.last_dio))
        return textdag

    def __del__(self):
        # identify neighbors that need to be removed
        self.cleanup()
        super(DODAG, self).__del__()


class DODAG_cache(object):
    """Store multiple DODAG instance"""

    def __init__(self):
        self.__dodag_cache = []


    def add(self, dodag):
        """Register a DODAG in the DODAG cache"""
        # make sure we don't track the same DODAG twice
        assert not self.has_dodag(dodag.dodagID, dodag.version, dodag.instanceID)

        self.__dodag_cache.insert(0, dodag)


    def has_dodag(self, dodagID=None,  version=None, instanceID=None):
        """Indicates if the DODAG with the corresponding DODAG ID is registered in the cache"""
        return bool(self.get_dodag(dodagID, version, instanceID))


    def get_dodag(self, dodagID=None, version=None, instanceID=None, is_root=None):
        """Retrieves the DODAG with the corresponding DODAG ID.
        Returns None if no such DODAG exists"""
        dodags = []

        for dodag in self.__dodag_cache:
            if dodagID is not None and dodag.dodagID != dodagID:
                continue
            if version is not None and dodag.version != version:
                continue
            if instanceID is not None and dodag.instanceID != instanceID:
                continue
            if isinstance(is_root, bool) and dodag.is_dodagRoot != is_root:
                continue

            dodags.append(dodag)

        return dodags


    def get_active_dodag(self):
        """Retrieves the active DODAGID"""
        active_dodags =  [dodag for dodag in self.__dodag_cache if dodag.active]

        # only one DODAG must be active at a time
        assert len(active_dodags) <= 1

        if active_dodags:
            return active_dodags[0]
        else:
            return None


    def purge_old_versions(self):
        """Remove from the cache DODAGs whose version has been updated"""
        # retrieves all unique DODAG IDs
        dodagIDs = set()
        for dodag in self.__dodag_cache:
            dodagIDs.add(dodag.dodagID)

        for dodagID in dodagIDs:
            # it could probably be optimized, as I go through the cache 3 times in total
            latest_version = None
            for dodag in self.__dodag_cache: # find the more recent cache entry for this DODAG
                if dodag.dodagID == dodagID:
                    if latest_version is None:
                        latest_version = dodag.version
                    elif dodag.version > latest_version:
                        latest_version = dodag.version

            # remove all old DODAG
            for (index, dodag) in reversed(list(enumerate(self.__dodag_cache))):
                if dodag.dodagID == dodagID \
                   and dodag.version < latest_version:
                    # this DODAG should already have been migrated (because
                    # there is a new version), thus it has no reason to still
                    # be active
                    assert not dodag.active
                    logger.debug("Removing old DODAG %s (version %d)" % (repr(Address(dodag.dodagID)), dodag.version.get_val()))
                    dodag.poison()
                    dodag.cleanup()
                    del self.__dodag_cache[index]
                    del dodag


    def is_empty(self):
        return len(self.__dodag_cache) == 0


    def poison_all(self):
        for dodag in self.__dodag_cache:
            dodag.poison(shutdown=True)


    def cleanup(self):
        for dodag in self.__dodag_cache:
            dodag.cleanup()


