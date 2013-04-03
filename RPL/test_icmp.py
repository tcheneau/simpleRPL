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


import nose

from icmp import *


# Helper function for the unitary tests
def hexstring_to_binstring(string):
    """Take an hexstring (such as the output of Wireshark withough the offset)
    and returns a binary string"""
    return "".join(map(chr, map(lambda x: int(x, 16), string.split())))


def test_DIS():
    # from a pcap file obtained runing the contiki rpl-udp client/server example
    # (git tip 01/03/2012)
    dis_contiki = """9b 00 40 fc 00 00"""
    dis_contiki_msg = hexstring_to_binstring(dis_contiki)

    d = DIS()
    d.parse(dis_contiki_msg)
    assert str(d) == dis_contiki_msg


def test_DIO():
    # from a pcap file obtained runing the contiki rpl-udp client/server example
    # (git tip 01/03/2012)
    # this message contains additional options that are not parsed here
    dio_contiki = """9b 01 9a 2c 1e f0 01 00 10 2d 00 00 aa aa 00 00
                     00 00 00 00 00 00 00 ff fe 00 00 01 02 06 07 04
                     00 02 00 00 04 0e 00 08 0c 0a 07 00 01 00 00 01
                     00 ff ff ff 08 1e 40 40 00 00 00 00 00 00 00 00
                     00 00 00 00 aa aa 00 00 00 00 00 00 00 00 00 00
                     00 00 00 00"""
    dio_contiki_msg = hexstring_to_binstring(dio_contiki)

    d = DIO()
    payload = d.parse(dio_contiki_msg)
    assert str(d) == dio_contiki_msg[:- len(payload)]

    d2 = RPL_Option_DAG_Metric_Container()
    payload2 = d2.parse(payload)

    d3 = RPL_Option_DODAG_Configuration()
    payload3 = d3.parse(payload2)

    d4 = RPL_Option_Prefix_Information()
    payload4 = d4.parse(payload3)

    assert payload4 == ""


def test_DAO():
    dao_contiki = """9b 02 bd 7f 1e 40 00 f2 aa aa 00 00 00 00 00 00
                     00 00 00 ff fe 00 00 01 05 12 00 80 aa aa 00 00
                     00 00 00 00 02 05 0c 2a 8c f4 8b 01 06 04 00 00
                     00 ff"""
    dao_contiki_msg = hexstring_to_binstring(dao_contiki)

    d = DAO()
    payload = d.parse(dao_contiki_msg)
    assert str(d) == dao_contiki_msg[: -len(payload)]

    # test for the optional DODAG field
    d = DAO()
    payload = d.parse(str(DAO(D=0)))
    assert payload == "" and str(d) == str(DAO(D=0))

    d = DAO()
    payload = d.parse(str(DAO(D=1)))
    assert payload == "" and str(d) == str(DAO(D=1))


def test_DAO_ACK():
    # test for the optional DODAG field
    d = DAO_ACK()
    payload = d.parse(str(DAO_ACK(D=0)))
    assert payload == "" and str(d) == str(DAO_ACK(D=0))

    d = DAO_ACK()
    payload = d.parse(str(DAO_ACK(D=1)))
    assert payload == "" and str(d) == str(DAO_ACK(D=1))


def test_CC():
    d = CC()
    payload = d.parse(str(CC(R=1)))
    assert payload == ""
    assert str(d) == str(CC(R=1))


def test_options():
    d = RPL_Option_Pad1()
    payload = d.parse(str(RPL_Option_Pad1()))
    assert payload == ""
    assert str(d) == str(RPL_Option_Pad1())

    d = RPL_Option_PadN()
    payload = d.parse(str(RPL_Option_PadN(length=10)))
    assert payload == ""
    assert str(d) == str(RPL_Option_PadN(length=10))

    d = RPL_Option_DAG_Metric_Container()
    payload = d.parse(str(RPL_Option_DAG_Metric_Container(data="test")))
    assert payload == ""
    assert str(d) == str(RPL_Option_DAG_Metric_Container(data="test"))

    d = RPL_Option_Routing_Information()
    payload = d.parse(str(RPL_Option_Routing_Information(prefix_len=130, \
                                                 prefix="aaaa", \
                                                 Prf=2, \
                                                 route_lifetime=65535)))
    assert payload == ""
    assert str(d) == str(RPL_Option_Routing_Information(prefix_len=130, \
                                                        prefix="aaaa", \
                                                        Prf=2, \
                                                        route_lifetime=65535))
    d = RPL_Option_DODAG_Configuration()
    payload = d.parse(str(RPL_Option_DODAG_Configuration()))
    assert payload == ""
    assert str(d) == str(RPL_Option_DODAG_Configuration())

    d = RPL_Option_RPL_Target()
    payload = d.parse(str(RPL_Option_RPL_Target()))
    assert payload == ""
    assert str(d) == str(RPL_Option_RPL_Target())

    d = RPL_Option_Transit_Information()
    payload = d.parse(str(RPL_Option_Transit_Information()))
    assert payload == ""
    assert str(d) == str(RPL_Option_Transit_Information())

    d = RPL_Option_Solicited_Information()
    payload = d.parse(str(RPL_Option_Solicited_Information()))
    assert payload == ""
    assert str(d) == str(RPL_Option_Solicited_Information())

    d = RPL_Option_Prefix_Information()
    payload = d.parse(str(RPL_Option_Prefix_Information()))
    assert payload == ""
    assert str(d) == str(RPL_Option_Prefix_Information())

    d = RPL_Option_Target_Descriptor()
    payload = d.parse(str(RPL_Option_Target_Descriptor()))
    assert payload == ""
    assert str(d) == str(RPL_Option_Target_Descriptor())

def test_options_advanced():
    Payload_Opt_DAG_Metric = '\x02\x06\x07\x04\x00\x02\x00\x00\x04\x0e\x00\x08\x0c\n\x07\x00\x01\x00\x00\x01\x00\xff\xff\xff\x08\x1e@@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    Payload_Opt_DODGA_Configuration = '\x04\x0e\x00\x08\x0c\n\x07\x00\x01\x00\x00\x01\x00\xff\xff\xff\x08\x1e@@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    Payload_Opt_Prefix_Information = '\x08\x1e@@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    d2 = RPL_Option_DAG_Metric_Container()
    assert Payload_Opt_DODGA_Configuration == d2.parse(Payload_Opt_DAG_Metric)

    d3 = RPL_Option_DODAG_Configuration()
    Payload_Opt_Prefix_Information = d3.parse(Payload_Opt_DODGA_Configuration)

    d4 = RPL_Option_Prefix_Information()
    empty_payload = d4.parse(Payload_Opt_Prefix_Information)

    assert empty_payload == ""



def test_options_parser():
    # from a pcap file obtained runing the contiki rpl-udp client/server example
    # (git tip 01/03/2012)
    # this message contains additional options that are not parsed here
    dio_contiki = """9b 01 9a 2c 1e f0 01 00 10 2d 00 00 aa aa 00 00
                     00 00 00 00 00 00 00 ff fe 00 00 01 02 06 07 04
                     00 02 00 00 04 0e 00 08 0c 0a 07 00 01 00 00 01
                     00 ff ff ff 08 1e 40 40 00 00 00 00 00 00 00 00
                     00 00 00 00 aa aa 00 00 00 00 00 00 00 00 00 00
                     00 00 00 00"""
    dio_contiki_msg = hexstring_to_binstring(dio_contiki)

    d = DIO()
    payload = d.parse(dio_contiki_msg)

    assert ['RPL_Option_DAG_Metric_Container', 'RPL_Option_DODAG_Configuration', 'RPL_Option_Prefix_Information'] == \
           [opt.__class__.__name__ for opt in  getAllOption(payload)]

    assert isinstance(findOption(payload, RPL_Option_Prefix_Information), RPL_Option_Prefix_Information)
    assert findOption(payload, RPL_Option_Prefix_Information, position=1) ==  None
    assert findOption(payload, RPL_Option_Pad1) ==  None

nose.main()
