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

"""Address Cache (store addresses assigned to interfaces)"""
from Routing import Addressing
from address import Address

class AddressCache(object):
    def __init__(self):
        self.__address_obj = Addressing()
        self.__address_obj.set_family("inet6")
        self.__address_cache = []  # store addresses that are added by the node

    def is_assigned(self, address):
        """Indicates if the address is assigned on the node"""
        return repr(Address(address)) in str(self.__address_obj)

    def is_assigned_if(self, address, interface):
        """Indicates if the address is assigned on the interface"""
        iface_address = [address for address \
                         in str(self.__address_obj).splitlines() \
                         if "dev %s" % interface in address]
        return address in iface_address

    def add(self, address, interface, pref_len=64, valid_lft=None, preferred_lft=None):
        """Add an address to an interface"""
        if (address, pref_len, interface) not in self.__address_cache:
            self.__address_obj.add(address + "/" + str(pref_len), interface, str(valid_lft), str(preferred_lft))
            self.__address_cache.append((address, pref_len, interface))
        else:
            self.__address_obj.add(address + "/" + str(pref_len), interface, str(valid_lft), str(preferred_lft), replace=True)

    def emptyCache(self):
        for (addr, pref_len, iface) in self.__address_cache:
            self.__address_obj.remove(addr + "/" + str(pref_len), iface)

    def __iter__(self):
        return iter(self.__address_cache)
