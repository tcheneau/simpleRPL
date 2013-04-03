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

"""Helper functions"""

# all-RPL-nodes multicast address
ALL_RPL_NODES = "ff02::1a"

def list_valid_interfaces():
    """Return a list with the name of network interfaces"""

    # read from /proc/net/dev, as adviced in netdevice(7) manpage
    raw_devices = open("/proc/net/dev").readlines()
    raw_devices = raw_devices[2:]  # skip the header
    return [device[:device.index(":")].strip() for device in raw_devices]


def broadcast(interfaces, msg):
    """Broadcast a message on all the registered interfaces"""
    for rpl_socket in interfaces.values():
        rpl_socket.send(ALL_RPL_NODES, msg)


