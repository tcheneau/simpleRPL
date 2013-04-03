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
Neighbor Cache (store the preferred parent and the set of backup parents)
"""
from threading import RLock
import of_zero as of
from address import Address
from route_cache import Route
import global_variables as gv
from rpl_constants import INFINITE_RANK
from lollipop import Lollipop


import logging
logger = logging.getLogger("RPL")

class NeighborCache(object):
    __cache = []
    __parents = []
    __preferred = None


    def __init__(self):
        self.__lock = RLock()


    def register_node(self, iface, address, dodag, rank, dtsn):
        """Register a node to the neighbor cache"""
        with self.__lock:
            for node in self.__cache:
                # check if the neighbor is not already in the cache
                # update the rank value if necessary
                if node.iface == iface and \
                node.address == address and \
                node.dodag == dodag:
                    node.rank = rank
                    node.dtsn.set_val(dtsn)
                    return
            self.__cache.append(Node(iface, address, dodag, rank, dtsn))
            logger.debug("Register new node: %s" % self.__cache[-1])


    def get_node(self, iface, address, dodag):
        """Return a matching Node object or None"""
        with self.__lock:
            for node in self.__cache:
                if node.iface == iface and \
                node.address == address and \
                node.dodag == dodag:
                    return node


    @staticmethod
    def compute_DIO_parents(neighs):
        """Establish a parent list for the node"""
        parents = []

        for n in neighs:
            if n.dodag.DAGRank(n.dodag.rank) > n.dodag.DAGRank(n.rank):
                parents.append(n)

        return parents

    @staticmethod
    def rank_increase_is_legit(node):
        """Check if the rank increase is too important"""

        dodag = node.dodag

        # this mechanism is disabled when value is 0
        if dodag.MaxRankIncrease:
            rank = dodag.compute_rank_increase(node.rank)
            # when rank increase is too big, the node broadcasts an infinite rank
            # instead (see RFC 6550, Section 8.2.2.4)
            if rank > dodag.lowest_rank_advertized + dodag.MaxRankIncrease:
                logger.debug("Parent's rank is higher than the authorized MaxRankIncrease. " \
                                "need to advertise Infinite Rank instead.")
                return False
        return True


    def set_preferred(self, parents):
        """Set the preferred parent, based on the sorted list of parents.
        Returns True when the procedure is terminated (regardless if a no
        preferred parent is selected), False otherwise.
        In the latter case, the function can be called again"""
        with self.__lock:
            if len(parents) == 0:
                if self.__preferred:
                    logger.info("Removing route through %s" % self.__preferred.address)
                    # remove routes to preferred
                    gv.route_cache.remove_route(Route("default",
                                                      self.__preferred.address,
                                                      self.__preferred.iface,
                                                      True))

                    self.__preferred.preferred = False
                    self.__preferred = None
                return True
            elif id(parents[0]) != id(self.__preferred):
                logger.info("A new DIO parent has been selected %s" % parents[0].address)
                if self.__preferred:
                    logger.info("Removing route through %s" % self.__preferred.address)
                    # remove routes to preferred
                    gv.route_cache.remove_route(Route("default",
                                                      self.__preferred.address,
                                                      self.__preferred.iface,
                                                      True))
                    self.__preferred.preferred = False

                    DAGRank = self.__preferred.dodag.DAGRank

                    # moving to a new DODAG version or a completely different
                    # DODAG, hence some downward routes might need to be
                    # removed, while some others might need to be added
                    if parents[0].dodag != self.__preferred.dodag:
                        logger.debug("downward routes need to be updated")
                        routes_to_remove = self.__preferred.dodag.downward_routes_get() - \
                                           parents[0].dodag.downward_routes_get()
                        gv.route_cache.remove_routes(routes_to_remove)
                        routes_to_add = parents[0].dodag.downward_routes_get() - \
                                        self.__preferred.dodag.downward_routes_get()
                        gv.route_cache.add_routes(routes_to_add)
                    # new parent is from the exact same DODAG, check if the
                    # new rank matches the DAGMaxRankIncrease value
                    elif DAGRank(parents[0].rank) > DAGRank(self.__preferred.rank):
                        logger.info("New parent has a higher rank that the previous preferred parent, poisoning the DODAG")
                        self.__preferred.dodag.rank = INFINITE_RANK
                        self.__preferred = None
                        return False

                dodag = gv.dodag_cache.get_active_dodag()
                if dodag:
                    dodag.active = False

                parents[0].preferred = True
                parents[0].dodag.active = True

                # if the new preferred DIO parent is on a different DODAG version,
                # or if there was no preferred DIO parent, reset the trickle timer
                if (self.__preferred and id(parents[0].dodag) != id(self.__preferred.dodag)) or\
                   not self.__preferred:
                    parents[0].dodag.DIOtimer.hear_inconsistent()

                self.__preferred = parents[0]

                logger.info("Adding route through %s" % self.__preferred.address)
                # add routes to the new preferred node
                gv.route_cache.add_route(Route("default",
                                               self.__preferred.address,
                                               self.__preferred.iface,
                                               True))
                return True
            return True

    def get_preferred(self):
        """Return the preferred parent"""
        with self.__lock:
            if self.__preferred is not None:
                assert self.__preferred.preferred == True
            return self.__preferred

    def get_parent_list(self):
        with self.__lock:
            return self.__parents

    def get_neighbor_list(self):
        with self.__lock:
            return self.__cache


    def update_DIO_parent(self):
        """
        Update the DIO parent using the information stored on the neighbors.
        The DODAG associated to this parent is then updated accordingly.
        Returns true of the preferred rank has been changed.
        """
        old_pref_parent = self.get_preferred()

        self.__parents = []

        # select or update one preferred parent per DODAG
        # (even if not currently active)
        dodags = gv.dodag_cache.get_dodag()


        for dodag in dodags:
            with self.__lock:
                neighbors = [neigh for neigh in self.__cache if neigh.dodag == dodag]
            parents = self.compute_DIO_parents(neighbors)
            self.__parents.extend(parents)
            parents.sort()
            try:
                if self.rank_increase_is_legit(parents[0]):
                    dodag.preferred_parent = parents[0]
                else:
                    dodag.preferred_parent = None
            except:
                dodag.preferred_parent = None


        # update the globally preferred parent
        # (default route will go through this parent)

        # select the preferred parent
        parents = [dodag.preferred_parent for dodag in dodags if dodag.preferred_parent]
        parents.sort()

        completed = self.set_preferred(parents)
        while not completed:
            completed = self.set_preferred(parents)
            try:
                del parents[0]
            except IndexError:
                pass


        pref_parent = self.get_preferred()

        # TODO: should be somewhere else
        # compute node own's rank:
        if pref_parent:
            old_rank = pref_parent.dodag.rank
            pref_parent.dodag.rank = pref_parent.dodag.compute_rank_increase(pref_parent.rank)
            # node's rank has been updated
            if old_rank > pref_parent.dodag.rank:
                pref_parent.dodag.DIOtimer.hear_inconsistent()
                return True
            else: return False
        else:
            logger.debug("DIO parent set is empty")

        return id(old_pref_parent) != id(pref_parent)


    def remove_nodes_by_dodag(self, dodag):
        """
        Remove all neighboring nodes attached to a DODAG
        Note: it is expected that this function is not be called on the currently active DODAG
        """
        with self.__lock:
            for (index, node) in reversed(list(enumerate(self.__cache))):
                if dodag == node.dodag\
                   and not node.dodag.active:
                    logger.debug("Removing node %s from cache (DODAG ID: %s, version: %d)" % (repr(Address(node.address)), repr(Address(dodag.dodagID)), dodag.version.get_val()))

                    del self.__cache[index]

                    # remove from the parent list (if appropriate)
                    try:
                        self.__parents.remove(node)
                    except ValueError:
                        pass

                    del node


    def remove_node_by_address(self, dodag, address):
        """Remove a specified node from the neighbor cache using its address and DODAG information"""
        updated = False
        with self.__lock:
            for (index, node) in reversed(list(enumerate(self.__cache))):
                if dodag == node.dodag \
                   and node.address == address:
                    logger.debug("Removing node %s from cache (DODAG ID: %s, version: %d)" % (repr(Address(node.address)), repr(Address(dodag.dodagID)), dodag.version.get_val()))

                    del self.__cache[index]

                    # remove from the parent list (if appropriate)
                    try:
                        self.__parents.remove(node)
                    except ValueError:
                        pass

                    if node.dodag.active:
                        dodag.downward_routes_remove_by_nexthop(node.address)

                        updated += gv.route_cache.remove_nexthop(node.address)

                        if id(node) == id(self.__preferred):
                            # remove routes to the preferred DIO parent
                            updated += gv.route_cache.remove_route(Route("default",
                                                            self.__preferred.address,
                                                            self.__preferred.iface,
                                                            True))
                            self.__preferred = None

                    del node
        return updated


    def has_neighbors(self, dodag):
        """
        Returns true of the neighbor cache contains at least one node belonging to the DODAG in its cache.
        Returns false otherwise.
        """

        has_neighbor = False

        with self.__lock:
            for node in self.__cache:
                if node.dodag == dodag:
                    has_neighbor = True
                    break

        return has_neighbor




class Node(object):
    __cmp__ = of.compare_parents
    def __init__(self, iface, address, dodag, rank, dtsn):
        self.iface = iface
        self.address = address
        self.rank = rank
        self.dodag = dodag
        self.preferred = False
        self.dtsn = Lollipop(dtsn)

        assert Address(self.address).is_linklocal()

    def __str__(self):
        string  = "address: %s\n" % self.address
        string += "rank: %d\n" % self.rank
        string += "interface: %s\n" % self.iface
        string += "dodag: %s" % repr(Address(self.dodag.dodagID))

        return string

