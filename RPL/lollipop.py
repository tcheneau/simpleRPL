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

"""implementation of a sequence counter divided in a lollipop fashion (as per
Section 7.2 of RFC 6550)"""

SEQUENCE_WINDOW = 16
MIN_VAL = 0
MAX_VAL = 256
LOLLIPOP_INT = 128
DEFAULT_SEQUENCE_VAL = 256 - SEQUENCE_WINDOW


class Lollipop(object):

    def __init__(self, val = DEFAULT_SEQUENCE_VAL):
        """Counter divided in a lollipop fashion"""
        if val < MIN_VAL or val >= MAX_VAL :
            raise ValueError("value is not in Lollipop counter range")

        self.val = val

    def __add__(self, other):
        if isinstance(other, int):
            val = other
        elif isinstance(other, Lollipop):
            val = other.val
        else:
            raise NotImplementedError("Addition is not implemented for this type of data")

        if self.val >= LOLLIPOP_INT:
            new_val = (self.val + val) % MAX_VAL
        else:
            new_val = (self.val + val) % LOLLIPOP_INT

        return Lollipop(new_val)

    def __cmp__(self, other):
        if isinstance(other, int):
            other = other
        elif isinstance(other, Lollipop):
            other = other.val
        else:
            raise NotImplementedError("Comparison is not implemented for this type of data")
        if (MAX_VAL > self.val > LOLLIPOP_INT \
           and LOLLIPOP_INT > other >= MIN_VAL) or\
           (MAX_VAL > other > LOLLIPOP_INT \
           and LOLLIPOP_INT > self.val >= MIN_VAL):
            if (MAX_VAL + other - self.val) <= SEQUENCE_WINDOW:
                return -1
            else:
                return 1
        elif (LOLLIPOP_INT > self.val >= MIN_VAL and\
              LOLLIPOP_INT > other >= MIN_VAL) or\
             (MAX_VAL > self.val >= LOLLIPOP_INT and\
              MAX_VAL > other >= LOLLIPOP_INT):
            if abs(self.val - other) <= SEQUENCE_WINDOW:
                # serial number comparison, as described in RFC 1982
                if self.val == other:
                    return 0
                elif (self.val < other and other - self.val < MAX_VAL) or\
                     (self.val > other and self.val - other > MAX_VAL):
                    return -1
                else:
                    return 1
            else:
                # the two sequence number are not comparable
                # try to minimize the changes to the node's state
                return 0
        else:
            # the two sequence number are not comparable
            # try to minimize the changes to the node's state
            return 0

    def set_val(self, val):
        self.val = val

    def get_val(self):
        return self.val

def test_lollipop():
    # comparisons
    assert Lollipop(240) > Lollipop(5)
    assert Lollipop(250) < Lollipop(5)
    assert Lollipop(255) < Lollipop(0)
    assert Lollipop(0) > Lollipop(255)
    assert Lollipop(0) < Lollipop(6)
    assert Lollipop(128) < Lollipop(140)
    assert Lollipop(127) > Lollipop(140)
    assert Lollipop(240) < 241
    assert Lollipop(241) > 240
    assert Lollipop(240) == 240

    # additions
    assert Lollipop(110) + 10 == Lollipop(120)
    a = Lollipop(120) + 20
    assert a.get_val() == 12
    a = Lollipop(250) + 20
    assert a.get_val() == 14
    a +=1
    assert a.get_val() == 15


