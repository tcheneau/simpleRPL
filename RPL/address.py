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

"""Manages address related operations"""

import socket
from socket import AF_INET6
import global_variables as gv

# all-RPL-nodes multicast address (ff02::1a)
ALL_RPL_NODES = '\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1a'

class Address(object):
    """Represent an IPv6 address and its prefix length"""

    @staticmethod
    def __is_printable_address(address):
        try:
            socket.inet_pton(AF_INET6, address)
            return True
        except (ValueError, TypeError):
            return False

    @staticmethod
    def __is_network_address(address):
        try:
            socket.inet_ntop(AF_INET6, address)
            return True
        except (ValueError, TypeError):
            return False

    def __init__(self, address, preflen=64):
        super(Address, self).__init__()

        if self.__is_printable_address(address):
            self.address = socket.inet_pton(AF_INET6, address)
        elif self.__is_network_address(address):
            self.address = address
        else:
            raise ValueError("Cannot parse address %s" % repr(address))

        self.preflen = preflen

    def __str__(self):
        return self.address

    def __repr__(self):
        return socket.inet_ntop(AF_INET6, self.address)

    def is_linklocal(self):
        """Return True if the address is a link-local address (as defined per RFC 4291, Sec. 2.5.6),
        else return False"""
        return self.address.startswith("\xfe\x80\x00\x00\x00\x00\x00\x00")  # address starts with fe80::/64

    def is_RPL_all_nodes(self):
        """Return True if the address is the All-RPL-Nodes multicast address"""
        return self.address == ALL_RPL_NODES


def lladdr_to_iid(lladdr):
    """Convert a Link Layer address to a valid interface identifier
    Only EUI-64 and EUI-48 address format is supported.
    The address conversion is documented in RFC 4291.
    """

    # convert to a hex string
    lladdr = [int(chunk, 16) for chunk in lladdr.split(":")]

    if len(lladdr) == 6: # this is a EUI-48 address
        lladdr.insert(3,0xff)
        lladdr.insert(4,0xfe)
        # flip the universal bit
        lladdr[0] ^= 2
    elif len(lladdr) == 8:
        # flip the universal bit
        lladdr[0] ^= 2
    else: # format to supported
        return None

    # raw string that represents the IID
    return "".join([chr(chunk) for chunk in lladdr])


def derive_address(interface, prefix):
    """Mimic the SLAAC to derive a valid IPv6 address from a given interface and prefix
    Here, the `interface` parameter is used to retrieve the Link-Layer address associated to the interface.
    """
    lladdr = gv.link_cache.get_lladdr(interface)

    if not lladdr:
        return None

    iid = lladdr_to_iid(lladdr)

    if not iid:
        return None

    # combine with the IID
    # return as an Address object
    return Address(prefix + iid)
