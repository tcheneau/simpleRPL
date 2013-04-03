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


"""Route cache"""
from Routing import Routing
from copy import copy
import global_variables as gv

import logging
logger = logging.getLogger("RPL")


class RouteCache(object):
    routing_obj = None
    route_cache = []

    def __init__(self):
        self.routing_obj = Routing()
        self.routing_obj.set_family("inet6")
        self.route_cache = []

    def remove_route(self, route):
        """Remove a route from the route cache"""
        if route not in self.route_cache:
            return False

        target, nexthop, nexthop_iface = route.to_tuple()

        logger.debug("Remove route to %s through %s on iface %s" % (target, nexthop, nexthop_iface))

        self.routing_obj.remove(target, (nexthop, nexthop_iface), table="local")
        self.route_cache.remove(route)
        return True


    def remove_routes(self, routes):
        """Remove a list of routes from the route cache"""
        route_update = False
        for route in routes:
            route_update += self.remove_route(route)
        return bool(route_update)


    def lookup_nexthop(self, nexthop, target=None):
        """Lookup a next hop in the route cache.
        The point is to make it easier to remove routes going through a specific router"""
        if target:
            return [route for route in self.route_cache if route.nexthop == nexthop and route.target == target]
        else:
            return [route for route in self.route_cache if route.nexthop == nexthop]


    def remove_nexthop(self, nexthop, target=None):
        route_update = False
        for route in self.lookup_nexthop(nexthop, target):
            route_update += self.remove_route(route)
        return bool(route_update)


    def add_route(self, route):
        """add a route to a target through a next hop"""

        if route in self.route_cache:
            return False

        (target, nexthop, nexthop_iface) = route.to_tuple()

        logger.debug("Add route to %s through %s on iface %s" % (target, nexthop, nexthop_iface))

        # sanity check: do not add a route to an address that is assigned on
        # the node
        assert target == "default" or not gv.address_cache.is_assigned(target.split("/")[0])

        try:
            self.routing_obj.add(target, (nexthop, nexthop_iface), table="local")
        except: pass

        self.route_cache.append(route)
        return True


    def add_routes(self, routes):
        """Add a list of routes to the route cache"""
        route_update = False
        for route in routes:
            route_update += self.add_route(route)
        return bool(route_update)


    def empty_cache(self):
        """Empty the route cache"""
        for route in copy(self.route_cache):
            self.remove_route(route)

        assert self.route_cache == []


    def __str__(self):
        """Print the complete route cache"""
        return self.routing_obj.__str__()


class Route(object):
    def __init__(self, target, nexthop, nexthop_iface, onehop=False):
        """Store route information:
        - target is the route target address (it can be a prefix e.g "2000::/3"))
        - nexthop is the next hop to reach target (e.g. "fe80::a3)
        - nexthop_iface is the interface name where nexthop can be reached (e.g. "eth0")
        - onehop indicate if the route is for a direct neighbor"""
        self.target = target
        self.nexthop = nexthop
        self.nexthop_iface = nexthop_iface
        self.onehop = onehop


    def to_tuple(self):
        """Return a route tuple"""
        return (self.target, self.nexthop, self.nexthop_iface)


    def __eq__(self, other):
        return self.target == other.target and \
           self.nexthop == other.nexthop and \
           self.nexthop_iface == other.nexthop_iface and \
           self.onehop == other.onehop


    def __neq__(self, other):
        return not self.__eq__(other)


    def __str__(self):
        return "target: %s, next hop: %s, interface: %s, onehop: %s" %\
               (self.target, self.nexthop, self.nexthop_iface, str(self.onehop))


    def __repr__(self):
        return "Route(%s, %s, %s, %s,)" %\
               (self.target, self.nexthop, self.nexthop_iface, str(self.onehop))


    def __hash__(self):
        return hash((self.target, self.nexthop, self.nexthop_iface, self.onehop))
