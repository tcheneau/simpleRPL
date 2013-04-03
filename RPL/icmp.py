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

"""This file contains the ICMP headers for all the RPL message"""
import struct
try:
    from collections import OrderedDict
except ImportError:  # your python version might be too old already
    from backport import OrderedDict

# constant values for the RPL protocol

# ICMPv6 message type
ICMPv6_RPL = 155

# ICMPv6 message codes for RPL messages
RPL_DIS = 0x00
RPL_DIO = 0x01
RPL_DAO = 0x02
RPL_DAO_ACK = 0x03
RPL_SEC_DIS = 0x80
RPL_SEC_DIO = 0x81
RPL_SEC_DAO = 0x82
RPL_SEC_DAO_ACK = 0x83
RPL_CC = 0x8A  # Consistency Check

# RPL control message option type
RPL_OPT_Pad1 = 0x00
RPL_OPT_PadN = 0x01
RPL_OPT_DAG_Metric_Container = 0x02
RPL_OPT_Routing_Information = 0x03
RPL_OPT_DODAG_Configuration = 0x04
RPL_OPT_RPL_Target = 0x05
RPL_OPT_Transit_Information = 0x06
RPL_OPT_Solicited_Information = 0x07
RPL_OPT_Prefix_Information = 0x08
RPL_OPT_Target_Descriptor = 0x09


class Header(object):
    """A Generic Packet Header"""
    _fields = None
    _compound_fields = None

    _format = "!"
    _header_size = 0  # in bytes
    _header = None
    _compound = None  # compound fields (i.e. fields that contains flag)
    _pure = True  # per Packet instances that are directly derived from Packet

    def __init__(self):
        super(Header, self).__init__()
        object.__setattr__(self, "_fields", [])
        object.__setattr__(self, "_compound_fields", [])
        object.__setattr__(self, "_header", OrderedDict())
        object.__setattr__(self, "_compound", OrderedDict())
        Header.build_compound_fields(self)

    def __str__(self):
        self.build_compound_fields()
        return struct.pack(self._format, * self._header.values())

    def __repr__(self):
        self.build_compound_fields()
        fields = "Field: \n" + \
                 "\n".join([field + ": " + repr(self._header[field]) for field in self._fields])
        if self._compound.keys:
            compound_fields = "\nCompound fields: \n" + \
                              "\n".join([field + ": " + repr(self._compound[field]) for field in self._compound])
        else:
            compound_fields = ""
        return fields + compound_fields

    def build_compound_fields(self):
        """Build the compound fields from the data that are smaller than a bytes.
        This is the place where the flags are packed into bytes prior sending."""
        pass

    def unpack_compound_fields(self):
        pass

    def parse(self, string):
        """parse a binary string into an ICMPv6 header and return the (remaining, unparsed)  payload"""
        if len(string) < self._header_size:
            raise Exception("string argument is to short to be parsed")

        unamed_fields = struct.unpack(self._format, string[:self._header_size])
        if len(unamed_fields) != len(self._fields):
            raise Exception("unpacked field data does not match, check your header definition")

        for k, field in zip(self._header.keys(), unamed_fields):
            self._header[k] = field
        self.unpack_compound_fields()
        return string[self._header_size:]

    # provide a dict like interface
    def __getitem__(self, key):
        try:
            return self._header[key]
        except KeyError:
            pass
        try:
            return self._compound[key]
        except KeyError:
            pass

        return object.__getattribute__(self, key)

    def __setitem__(self, key, value):
        if key in self._fields:
            self._header[key] = value
        elif key in self._compound_fields:
            self._compound[key] = value
        else:
            raise KeyError

        # self.unpack_compound_fields()

    def __getattr__(self, name):
        return self.__getitem__(name)

    def __setattr__(self, name, value):
        if hasattr(self, name):
            if name in self._fields or name in self._compound_fields:
                self.__setitem__(name, value)
            else:
                object.__setattr__(self, name, value)
        else:
            raise AttributeError("new attributes can not be added to this class")

    def __div__(self, other):
        """Syntaxic sugar for easier Header construction construction.
        Example:
        MyXYZHeader()/MyOtherXYZHeader() would be equivalent to
        "".join([str(MyXYZHeader()), str(MyOtherXYZHeader())])
        """
        return "".join(str(self), str(other))

#
# Definition of the ICMPv6 header
#


class ICMPv6(Header):
    """A Generic Packet header"""

    def __init__(self, mtype=ICMPv6_RPL, code=RPL_DIO, checksum=0):
        super(ICMPv6, self).__init__()

        self._format += "BBH"
        self._fields += ['type', 'code', 'checksum']
        self._header_size += 4  # size of an ICMP header

        self._header['type'] = mtype
        self._header['code'] = code
        self._header['checksum'] = checksum

        ICMPv6.build_compound_fields(self)

    def build_compound_fields(self):
        super(ICMPv6, self).build_compound_fields()

    def unpack_compound_fields(self):
        super(ICMPv6, self).unpack_compound_fields()

#
# Definition of the RPL messages
#


# From Section 6.2.1, format of the DIS message:
#  0                   1                   2
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Flags     |   Reserved    |   Option(s)...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class DIS(ICMPv6):
    """DODAG Information Solicitation"""
    def __init__(self, flags=0, reserved=0, \
                pure=False):
        if (not pure):
            super(DIS, self).__init__(code=RPL_DIS)
            self._pure = False
        else:
            Header.__init__(self)

        self._fields += ['flags', 'reserved']
        self._format += "BB"
        self._header_size += 2

        self._header['flags'] = flags
        self._header['reserved'] = reserved

# From Section 6.3.1 (RFC 6550):
# DIO Format
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | RPLInstanceID |Version Number |             Rank              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |G|0| MOP | Prf |     DTSN      |     Flags     |   Reserved    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            DODAGID                            +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Option(s)...
# +-+-+-+-+-+-+-+-+


class DIO(ICMPv6):
    """DODAG Information Object (DIO) message header"""

    def __init__(self, instanceID=0, version=0, rank=0, G=0, MOP=0,\
                 Prf=0, DTSN=0, flags=0, reserved=0, DODAGID='\x00' * 16,\
                 pure=False):
        if (not pure):
            super(DIO, self).__init__(code=RPL_DIO)
            self._pure = False
        else:
            Header.__init__(self)

        # expend the format
        self._fields += ['instanceID', 'version', 'rank', \
                         'G_MOP_Prf', 'DTSN', 'flags', 'reserved', \
                          'DODAGID',\
                         ]
        self._compound_fields += ['G', 'MOP', 'Prf']
        self._format += 'BBHBBBB16s'
        self._header_size += 24

        self._header['instanceID'] = instanceID
        self._header['version'] = version
        self._header['rank'] = rank
        self._header['G_MOP_Prf'] = 0  # compound field
        self._header['DTSN'] = DTSN
        self._header['flags'] = flags
        self._header['reserved'] = reserved
        self._header['DODAGID'] = DODAGID

        self._compound['G'] = G
        self._compound['MOP'] = MOP
        self._compound['Prf'] = Prf

        self.build_compound_fields()

    def build_compound_fields(self):
        if (not self._pure):
            super(DIO, self).build_compound_fields()

        # verifies the field content
        if self.G < 0 or self.G > 1:
            raise ValueError("G must be 0 or 1")

        if self.MOP < 0 or self.MOP > 4:
            raise ValueError("MOP must be within range 0 to 4")

        if self.Prf < 0 or self.Prf > 7:
            raise ValueError("Prf (DODAGPreference) must be within range 0 to 7")

        self.G_MOP_Prf = self.G << 7 | self.MOP << 3 | self.Prf

    def unpack_compound_fields(self):
        if (not self._pure):
            super(DIO, self).unpack_compound_fields()

        self.G = (self.G_MOP_Prf >> 7) & 0x01
        self.MOP = (self.G_MOP_Prf >> 3) & 0x07
        self.Prf = self.G_MOP_Prf & 0x07

# From Section 6.4.1 (RFC 6550):
# DAO Format
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | RPLInstanceID |K|D|   Flags   |   Reserved    | DAOSequence   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            DODAGID (optional)                 +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Option(s)...
# +-+-+-+-+-+-+-+-+

class DAO(ICMPv6):
    """Destination Advertisement Object"""
    def __init__(self, instanceID=0, K=0, D=0, flags=0, reserved=0, DAOsequence=0, \
                 DODAGID='\x00' * 16, pure=False):
        if (not pure):
            super(DAO, self).__init__(code=RPL_DAO)
            self._pure = False
        else:
            Header.__init__(self)

        self._fields += ['instanceID', 'KDflags', 'reserved', 'DAOsequence', \
                         'DODAGID']
        self._compound_fields += ['K', 'D', 'flags']
        self._format += "BBBB16s"
        self._header_size += 20

        self._header['instanceID'] = instanceID
        self._header['KDflags'] = 0  # compound field
        self._header['reserved'] = reserved
        self._header['DAOsequence'] = DAOsequence
        # depends if the D flag is set or not
        self._header['DODAGID'] = DODAGID

        self._compound['K'] = K
        self._compound['D'] = D
        self._compound['flags'] = flags

        self.build_compound_fields()

    def build_compound_fields(self):
        if (not self._pure):
            super(DAO, self).build_compound_fields()

        # verifies the field content
        if self.K < 0 or self.K > 1:
            raise ValueError("K must be 0 or 1")

        if self.D < 0 or self.D > 1:
            raise ValueError("D must be 0 to 1")

        if self.flags < 0 or self.flags > 2**6 - 1:
            raise ValueError("flags must be within range 0 to 63")

        self.KDflags = self.K << 7 | self.D << 6 | self.flags

    def unpack_compound_fields(self):
        if (not self._pure):
            super(DAO, self).unpack_compound_fields()

        self.K = (self.KDflags >> 7) & 0x01
        self.D = (self.KDflags >> 6) & 0x01
        self.flags = self.KDflags & 0x3f

    def __str__(self):
        # there is a need to override the default string convertion
        # this is because the DODAGID field is optional
        if not self.D:  # the DODADID must not be present
            return struct.pack(self._format[:-1], * self._header.values()[:-1])
        else:
            return super(DAO, self).__str__()

    def parse(self, string):
        # there is a need to override the default input parsing
        # this is because the DODAGID field is optional
        if len(string) < self._header_size - 16:  # that is, if the DODAGID is not present
            raise Exception("string argument is to short to be parsed")

        unamed_fields = struct.unpack(self._format[:-1], string[:self._header_size - 16])
        if len(unamed_fields) != len(self._fields) - 1:
            raise Exception("unpacked field data does not match, check your header definition")

        for k, field in zip(self._header.keys(), unamed_fields):
            self._header[k] = field
        self.unpack_compound_fields()

        if not self.D:
            return string[self._header_size - 16:]
        else:
            return super(DAO, self).parse(string)

# From Section 6.5
# DAO-ACK
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | RPLInstanceID |D|  Reserved   |  DAOSequence  |    Status     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            DODAGID*                           +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Option(s)...
# +-+-+-+-+-+-+-+-+

class DAO_ACK(ICMPv6):
    """Destination Advertisement Object Acknowledgment"""

    def __init__(self, instanceID=0, D=0, reserved=0, DAOSequence=0, Status=0, \
                 DODAGID='\x00' * 16,
                 pure=False):
        if (not pure):
            super(DAO_ACK, self).__init__(code=RPL_DAO_ACK)
            self._pure = False
        else:
            Header.__init__(self)

        self._fields += ['instanceID', 'Dreserved', 'DAOSequence', 'Status', \
                         'DODAGID']
        self._compound_fields += ['D', 'reserved']
        self._format += "BBBB16s"
        self._header_size += 20

        self._header['instanceID'] = instanceID
        self._header['Dreserved'] = 0  # compound field
        self._header['DAOSequence'] = DAOSequence
        self._header['Status'] = Status
        self._header['DODAGID'] = DODAGID

        self._compound['D'] = D
        self._compound['reserved'] = reserved

        self.build_compound_fields()

    def build_compound_fields(self):
        if (not self._pure):
            super(DAO_ACK, self).build_compound_fields()

        if self.D < 0 or self.D > 1:
            raise ValueError("D must be 0 to 1")

        if self.reserved < 0 or self.reserved > 2**7 - 1:
            raise ValueError("reserved must be within range 0 to 127")

        self.Dreserved = self.D << 7 | self.reserved

    def unpack_compound_fields(self):
        if (not self._pure):
            super(DAO_ACK, self).unpack_compound_fields()

        self.D = (self.Dreserved >> 7) & 0x01
        self.reserved = self.Dreserved & 0x7f

    def __str__(self):
        # there is a need to override the default string convertion
        # this is because the DODAGID field is optional
        if not self.D:  # the DODADID must not be present
            return struct.pack(self._format[:-1], * self._header.values()[:-1])
        else:
            return super(DAO_ACK, self).__str__()

    def parse(self, string):
        # there is a need to override the default input parsing
        # this is because the DODAGID field is optional
        if len(string) < self._header_size - 16:  # that is, if the DODAGID is not present
            raise Exception("string argument is to short to be parsed")

        unamed_fields = struct.unpack(self._format[:-1], string[:self._header_size - 16])
        if len(unamed_fields) != len(self._fields) - 1:
            raise Exception("unpacked field data does not match, check your header definition")

        for k, field in zip(self._header.keys(), unamed_fields):
            self._header[k] = field
        self.unpack_compound_fields()

        if not self.D:
            return string[self._header_size - 16:]
        else:
            return super(DAO_ACK, self).parse(string)

# From Section 6.6.1.
# Format of the CC Base Object
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | RPLInstanceID |R|    Flags    |           CC Nonce            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            DODAGID                            +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                      Destination Counter                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Option(s)...
# +-+-+-+-+-+-+-+-+


class CC(ICMPv6):
    """Consistency Check message format"""
    def __init__(self, instanceID=0, R=0, flags=0, Nonce=0, \
                DODAGID='\x00' * 16, \
                DestCounter=0,\
                pure=False):
        if (not pure):
            super(CC, self).__init__(code=RPL_CC)
            self._pure = False
        else:
            Header.__init__(self)

        self._fields += ['instanceID', 'Rflags', 'Nonce', \
                         'DODAGID', 'DestCounter']
        self._compound_fields += ['R', 'flags']
        self._format += "BBH16sI"
        self._header_size += 24

        self._header['instanceID'] = instanceID
        self._header['Rflags'] = 0
        self._header['Nonce'] = Nonce
        self._header['DODAGID'] = DODAGID
        self._header['DestCounter'] = DestCounter

        self._compound['R'] = R
        self._compound['flags'] = flags

        self.build_compound_fields()

    def build_compound_fields(self):
        if (not self._pure):
            super(CC, self).build_compound_fields()

        # verifies the field content
        if self.R < 0 or self.R > 1:
            raise ValueError("R must be 0 or 1")

        if self.flags < 0 or self.flags > 2**7 - 1:
            raise ValueError("flags must be within range 0 to 127")

        self.Rflags = self.R << 7 | self.flags

    def unpack_compound_fields(self):
        if (not self._pure):
            super(CC, self).unpack_compound_fields()

        self.R = (self.Rflags >> 7) & 0x01
        self.flags = self.Rflags & 0x7f
#
# Definition of the RPL options
#


# From Section 6.7.1
# RPL Control message option generic format
#
#  0                   1                   2
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - -
# |  Option Type  | Option Length | Option Data
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - -


class RPL_Option(Header):
    """A Generic Option header"""

    def __init__(self, mtype=RPL_OPT_Pad1, length=0):
        super(RPL_Option, self).__init__()

        self._format += "BB"
        self._fields += ['type', 'length']
        self._header_size += 2

        self._header['type'] = mtype
        self._header['length'] = length


# From Section 6.7.2
# Pad1 option format
#  0
#  0 1 2 3 4 5 6 7
# +-+-+-+-+-+-+-+-+
# |   Type = 0x00 |
# +-+-+-+-+-+-+-+-+

class RPL_Option_Pad1(Header):
    """Pad1 option header"""
    def __init__(self):
        super(RPL_Option_Pad1, self).__init__()

        self._format += "B"
        self._fields += ['type']
        self._header_size += 1

        self._header['type'] = RPL_OPT_Pad1


# From Section 6.7.3
# PadN option format
#  0                   1                   2
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - -
# |   Type = 0x01 | Option Length | 0x00 Padding...
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - -


class RPL_Option_PadN(RPL_Option):
    """PadN option header"""
    def __init__(self, ** kwargs):
        super(RPL_Option_PadN, self).__init__(mtype=RPL_OPT_PadN, ** kwargs)

    def __str__(self):
        return super(RPL_Option_PadN, self).__str__() + "\x00" * self.length

    def parse(self, string):
        payload = super(RPL_Option_PadN, self).parse(string)
        if len(string) < self._header_size + self.length:
            raise Exception("string argument is to short to be parsed")

        return payload[self.length:]


# From Section 6.7.4
# DAG Metric Container
#  0                   1                   2
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - -
# |   Type = 0x02 | Option Length | Metric Data
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- - - - - - - -
#     Figure 22: Format of the DAG Metric Container Option


class RPL_Option_DAG_Metric_Container(RPL_Option):
    """DAG Metric container option"""
    def __init__(self, data=""):
        """data is the Metric Data and should contains is expected to be a raw string.
        Formating of the Metric Data is defined in RFC 6551"""
        super(RPL_Option_DAG_Metric_Container, self).__init__(mtype=RPL_OPT_DAG_Metric_Container)

        self._format += "0s"  # data is considered as an empty string
        self._fields += ["data"]
        self._header['data'] = data
        self.length = len(str(self.data))

    def __str__(self):
        self.length = len(self.data)
        return super(RPL_Option_DAG_Metric_Container, self).__str__() + str(self.data)

    def parse(self, string):
        payload = super(RPL_Option_DAG_Metric_Container, self).parse(string)
        self.data = payload[:self.length]
        return payload[self.length:]


# From Section 6.7.5
# Format of the Route Information Option
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Type = 0x03 | Option Length | Prefix Length |Resvd|Prf|Resvd|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Route Lifetime                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# .                   Prefix (Variable Length)                    .
# .                                                               .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class RPL_Option_Routing_Information(RPL_Option):
    """Routing Information option"""
    def __init__(self, prefix_len=0, reserved=0, Prf=0, reserved2=0, \
                 route_lifetime=0, \
                 prefix=""):
        super(RPL_Option_Routing_Information, self).__init__(mtype=RPL_OPT_Routing_Information)

        self._format += "BBI0s"
        self._fields += ["prefix_len", "resvdPrfresvd2", \
                         "route_lifetime", "prefix"]
        self._compound_fields += ["reserved", "Prf", "reserved2"]
        self._header_size += 6

        self._header['prefix_len'] = prefix_len
        self._header['resvdPrfresvd2'] = 0  # compound field
        self._header['route_lifetime'] = route_lifetime
        self._header['prefix'] = prefix

        self._compound['reserved'] = reserved
        self._compound['Prf'] = Prf
        self._compound['reserved2'] = reserved2

        # length is inferred by the size of the prefix field
        self.length = len(self.prefix) + 6

        self.build_compound_fields()

    def build_compound_fields(self):
        # verifies the field content
        if self.Prf < 0 or self.Prf > 3:
            raise ValueError("Prf must be between 0 or 3")

        if self.reserved < 0 or self.reserved > 7:
            raise ValueError("reserved must be between 0 and 7")

        if self.reserved2 < 0 or self.reserved2 > 7:
            raise ValueError("reserved2 must be between 0 and 7")

        self.resvdPrfresvd2 = self.reserved << 5 | self.Prf << 3 | self.reserved2

    def unpack_compound_fields(self):
        self.reserved = (self.resvdPrfresvd2 >> 5) & 0x05
        self.Prf = (self.resvdPrfresvd2 >> 3) & 0x03
        self.reserved2 = self.resvdPrfresvd2 & 0x05

    def __str__(self):
        self.length = len(self.prefix) + 6
        return super(RPL_Option_Routing_Information, self).__str__() + str(self.prefix)

    def parse(self, string):
        payload = super(RPL_Option_Routing_Information, self).parse(string)
        if self.length < 6:
            raise ValueError("Length field is invalid (< 6)")
        self.prefix = payload[:self.length - 6]
        return payload[self.length - 6:]


# From Sectino 6.7.6
# Format of the DODAG Configuration Option
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Type = 0x04 |Opt Length = 14| Flags |A| PCS | DIOIntDoubl.  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  DIOIntMin.   |   DIORedun.   |        MaxRankIncrease        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      MinHopRankIncrease       |              OCP              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Reserved    | Def. Lifetime |      Lifetime Unit            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class RPL_Option_DODAG_Configuration(RPL_Option):
    """DODAG Configuration option"""
    def __init__(self, flags=0, A=0, PCS=0, DIOIntDoubl=0, \
                 DIOIntMin=0, DIORedun=0, MaxRankIncrease=0, \
                 MinHopRankIncrease=0, OCP=0, \
                 reserved=0, DefLifetime=0, LifetimeUnit=0):
        super(RPL_Option_DODAG_Configuration, self).__init__(mtype=RPL_OPT_DODAG_Configuration, length=14)

        self._format += "BBBBHHHBBH"
        self._fields += ["flagsAPCS", "DIOIntDoubl", "DIOIntMin", "DIORedun", "MaxRankIncrease", \
                          "MinHopRankIncrease", "OCP", "reserved", "DefLifetime", "LifetimeUnit"]
        self._compound_fields += ['flags', 'A', 'PCS']
        self._header_size += 14

        self._header['flagsAPCS'] = 0  # compound field
        self._header['DIOIntDoubl'] = DIOIntDoubl
        self._header['DIOIntMin'] = DIOIntMin
        self._header['DIORedun'] = DIORedun
        self._header['MaxRankIncrease'] = MaxRankIncrease
        self._header['MinHopRankIncrease'] = MinHopRankIncrease
        self._header['OCP'] = OCP
        self._header['reserved'] = reserved
        self._header['DefLifetime'] = DefLifetime
        self._header['LifetimeUnit'] = LifetimeUnit

        self._compound['flags'] = flags
        self._compound['A'] = A
        self._compound['PCS'] = PCS

    def build_compound_fields(self):
        # verifies the field content
        if self.A < 0 or self.A > 1:
            raise ValueError("A must be 0 or 1")

        if self.flags < 0 or self.flags > 15:
            raise ValueError("flags must be between 0 and 5")

        if self.PCS < 0 or self.PCS > 7:
            raise ValueError("PCS must be between 0 and 7")

        self.flagsAPCS = self.flags << 4 | self.A << 3 | self.PCS

    def unpack_compound_fields(self):
        self.flags = (self.flagsAPCS >> 4) & 0x0F
        self.A = (self.flagsAPCS >> 3) & 0x01
        self.PCS = self.flagsAPCS & 0x05


# From Section 6.7.7
# Format of the RPL Target Option
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Type = 0x05 | Option Length |     Flags     | Prefix Length |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                Target Prefix (Variable Length)                |
# .                                                               .
# .                                                               .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class RPL_Option_RPL_Target(RPL_Option):
    """RPL Target option"""
    def __init__(self, flags=0, prefix_len=0, target_prefix=""):
        super(RPL_Option_RPL_Target, self).__init__(mtype=RPL_OPT_RPL_Target)
        self._format += "BB0s"
        self._fields += ["flags", "prefix_len", "target_prefix"]
        self._header_size += 2

        self._header['flags'] = flags
        self._header['prefix_len'] = prefix_len
        self._header['target_prefix'] = target_prefix

        self.length = len(target_prefix) + 2

    def __str__(self):
        self.length = len(self.target_prefix) + 2
        return super(RPL_Option_RPL_Target, self).__str__() + str(self.target_prefix)

    def parse(self, string):
        payload = super(RPL_Option_RPL_Target, self).parse(string)
        if self.length < 2:
            raise ValueError("Length field is invalid (< 2)")
        self.target_prefix = payload[:self.length - 2]
        return payload[self.length - 2:]


# From Section 6.7.8
# Format of the Transit Information Option
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Type = 0x06 | Option Length |E|    Flags    | Path Control  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Path Sequence | Path Lifetime |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# |                                                               |
# +                                                               +
# |                                                               |
# +                        Parent Address*                        +
# |                                                               |
# +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class RPL_Option_Transit_Information(RPL_Option):
    """Transit Information option"""
    def __init__(self, E=0, flags=0, path_control=0,\
                 path_sequence=0, path_lifetime=0, \
                 parent_address=""):
        super(RPL_Option_Transit_Information, self).__init__(mtype=RPL_OPT_Transit_Information)
        self._format += "BBBB0s"
        self._fields += ["Eflags", "path_control", "path_sequence", "path_lifetime", \
                         "parent_address"]
        self._compound_fields += ["E", "flags"]
        self._header_size += 4

        self._header['Eflags'] = 0  # compound field
        self._header['path_control'] = path_control
        self._header['path_sequence'] = path_sequence
        self._header['path_lifetime'] = path_lifetime
        self._header['parent_address'] = parent_address

        self._compound['E'] = E
        self._compound['flags'] = flags

        self.length = len(parent_address) + 4
        self.build_compound_fields()

    def build_compound_fields(self):
        # verifies the field content
        if self.E < 0 or self.E > 1:
            raise ValueError("E must be 0 or 1")

        if self.flags < 0 or self.flags > 127:
            raise ValueError("flags must be between 0 and 127")

        self.Eflags = self.E << 7 | self.flags

    def unpack_compound_fields(self):
        self.flags = self.Eflags & 0x7F
        self.E = (self.Eflags >> 7) & 0x01

    def __str__(self):
        self.build_compound_fields()
        self.length = len(self.parent_address) + 4
        return super(RPL_Option_Transit_Information, self).__str__() + str(self.parent_address)

    def parse(self, string):
        payload = super(RPL_Option_Transit_Information, self).parse(string)
        if self.length < 4:
            raise ValueError("Length field is invalid (< 4)")
        self.parent_address = payload[:self.length - 4]
        return payload[self.length - 4:]


# From Section 6.7.9
# Format of the Solicited Information Option
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Type = 0x07 |Opt Length = 19| RPLInstanceID |V|I|D|  Flags  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            DODAGID                            +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version Number |
# +-+-+-+-+-+-+-+-+


class RPL_Option_Solicited_Information(RPL_Option):
    """Solicited information option"""
    def __init__(self, instanceID=0, V=0, I=0, D=0, flags=0, \
                DODAGID='\x00' * 16, \
                version=0):
        super(RPL_Option_Solicited_Information, self).__init__(mtype=RPL_OPT_Solicited_Information, length=19)
        self._format += "BB16sB"
        self._fields += ["instanceID", "VIDflags", 'DODAGID', 'version']
        self._compound_fields += ["V", "I", "D", "flags"]
        self._header_size += 19

        self._header['instanceID'] = instanceID
        self._header['VIDflags'] = 0  # compound field
        self._header['DODAGID'] = DODAGID
        self._header['version'] = version

        self._compound['V'] = V
        self._compound['I'] = I
        self._compound['D'] = D
        self._compound['flags'] = flags

        self.build_compound_fields()

    def build_compound_fields(self):
        # verifies the field content
        if self.V < 0 or self.V > 1:
            raise ValueError("V must be 0 or 1")

        if self.I < 0 or self.I > 1:
            raise ValueError("I must be 0 or 1")

        if self.D < 0 or self.D > 1:
            raise ValueError("D must be 0 or 1")

        if self.flags < 0 or self.flags > 31:
            raise ValueError("flags must be between 0 and 31")

        self.VIDflags = self.V << 7 | self.I << 6 | self.D << 5 | self.flags

    def unpack_compound_fields(self):
        self.V = self.VIDflags >> 7 & 0x01
        self.I = self.VIDflags >> 6 & 0x01
        self.D = self.VIDflags >> 5 & 0x01
        self.flags = self.VIDflags & 0x1F


# From Section 6.7.10
# Format of the Prefix Information Option
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Type = 0x08 |Opt Length = 30| Prefix Length |L|A|R|Reserved1|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Valid Lifetime                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Preferred Lifetime                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved2                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            Prefix                             +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class RPL_Option_Prefix_Information(RPL_Option):
    """Prefix Inforrmation Option"""
    def __init__(self, prefix_len=0, L=0, A=0, R=0, reserved=0, \
                valid_lifetime=0, preferred_lifetime=0, \
                reserved2=0,
                prefix=""):
        super(RPL_Option_Prefix_Information, self).__init__(mtype=RPL_OPT_Prefix_Information, length=30)
        self._format += "BBIII16s"
        self._fields += ["prefix_len", "LARreserved", "valid_lifetime", \
                         "preferred_lifetime", "reserved2", "prefix"]
        self._compound_fields += ["L", "A", "R", "reserved"]
        self._header_size += 30

        self._header['prefix_len'] = prefix_len
        self._header['LARreserved'] = 0  # compound field
        self._header['valid_lifetime'] = valid_lifetime
        self._header['preferred_lifetime'] = preferred_lifetime
        self._header['reserved2'] = reserved2
        self._header['prefix'] = prefix

        self._compound['L'] = L
        self._compound['A'] = A
        self._compound['R'] = R
        self._compound['reserved'] = reserved

        self.build_compound_fields()

    def build_compound_fields(self):
        # verifies the field content
        if self.L < 0 or self.L > 1:
            raise ValueError("L must be 0 or 1")

        if self.A < 0 or self.A > 1:
            raise ValueError("A must be 0 or 1")

        if self.R < 0 or self.R > 1:
            raise ValueError("R must be 0 or 1")

        if self.reserved < 0 or self.reserved > 31:
            raise ValueError("reserved must be between 0 and 31")

        self.LARreserved = self.L << 7 | self.A << 6 | self.R << 5 | self.reserved

    def unpack_compound_fields(self):
        self.L = self.LARreserved >> 7 & 0x01
        self.A = self.LARreserved >> 6 & 0x01
        self.R = self.LARreserved >> 5 & 0x01
        self.reserved = self.LARreserved & 0x1F


# From Section 6.7.11
# Format of the RPL Target Descriptor Option
#  0                   1                   2                   3
#  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Type = 0x09 |Opt Length = 4 |           Descriptor
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#        Descriptor (cont.)       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
class RPL_Option_Target_Descriptor(RPL_Option):
    """Target Descriptor option"""
    def __init__(self, descriptor=0):
        super(RPL_Option_Target_Descriptor, self).__init__(mtype=RPL_OPT_Target_Descriptor, length=4)
        self._format += "I"
        self._fields += ["descriptor"]
        self._header_size += 4

        self._header['descriptor'] = descriptor

# map the type/code with the appropriate class

RPL_Header_map = {
    RPL_DIS: DIS,
    RPL_DIO: DIO,
    RPL_DAO: DAO,
    RPL_DAO_ACK: DAO_ACK,
    # not implemented so far
    # RPL_SEC_DIS: None,
    # RPL_SEC_DIO: None,
    # RPL_SEC_DAO: None,
    # RPL_SEC_DAO_ACK: None,
    RPL_CC: CC,
}

RPL_Option_map = {
    RPL_OPT_Pad1: RPL_Option_Pad1,
    RPL_OPT_PadN: RPL_Option_PadN,
    RPL_OPT_DAG_Metric_Container: RPL_Option_DAG_Metric_Container,
    RPL_OPT_Routing_Information: RPL_Option_Routing_Information,
    RPL_OPT_DODAG_Configuration: RPL_Option_DODAG_Configuration,
    RPL_OPT_RPL_Target: RPL_Option_RPL_Target,
    RPL_OPT_Transit_Information: RPL_Option_Transit_Information,
    RPL_OPT_Solicited_Information: RPL_Option_Solicited_Information,
    RPL_OPT_Prefix_Information: RPL_Option_Prefix_Information,
    RPL_OPT_Target_Descriptor: RPL_Option_Target_Descriptor,
}

#
# utility functions
#

def findOption(payload, opt_type, position=0):
    """Returns an option of type opt_type if it exists, or None.

    The position argument is used when the option appears multiple times.
    It indicates the option position (0 being the first time the option is met)"""

    # bottom case
    if payload == "":
        return None

    # Pad1 need special treatment
    if ord(payload[0]) == RPL_OPT_Pad1:
        if opt_type.__name__ == "RPL_Option_Pad1":
            if position == 0:
                return RPL_Option_Pad1()
            else:
                return findOption(payload[:1], opt_type, position - 1)
        else:
            return findOption(payload[:1], opt_type, position)

    option = RPL_Option()
    next_header = option.parse(payload)
    try:  # parse the current option
        option = RPL_Option_map[option.type]()
        next_header = option.parse(payload)
        if isinstance(option, opt_type):
            if position == 0:
                return option
            else:  # we skip this option
                return findOption(next_header, opt_type, position - 1)
        else:
            return findOption(next_header, opt_type, position)
    except KeyError:
        raise AttributeError("unable to find option of type %d" % option.type)

def getAllOption(payload):
    """Decode all option of the payload and returns a list"""
    if payload == "":
        return []

    # Pad1 need special treatment
    if ord(payload[0]) == RPL_OPT_Pad1:
        return [ RPL_Option_Pad1() ] + getAllOption(payload[1:])

    option = RPL_Option()
    option.parse(payload)

    try:
        real_option = RPL_Option_map[option.type]()
        next_option = real_option.parse(payload)
    except KeyError:
        raise AttributeError("unable to find option of type %d" % option.type)

    return [real_option] + getAllOption(next_option)


