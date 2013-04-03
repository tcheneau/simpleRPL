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

# RPLInstanceID that is used by this protocol by a node without any overriding policy.
RPL_DEFAULT_INSTANCE = 0

# default value used to configure PCS in the DODAG Configuration option
# (dictates the number of significant bits in the Path Control field of the Transit Information option)
# value 0 means that a router sends a DAO to only one of its parents
DEFAULT_PATH_CONTROL_SIZE = 0

# default value used to configure Imin for the DIO Trickle timer
DEFAULT_DIO_INTERVAL_MIN = 3  # 8 ms

# default value used to configure Imax for the DIO Trickle timer
DEFAULT_DIO_INTERVAL_DOUBLINGS = 20  # 2.3 hours

# default value used to configure k for the DIO Trickle timer
DEFAULT_DIO_REDUNDANCY_CONSTANT = 10

# default value of MinHopRankIncrease
DEFAULT_MIN_HOP_RANK_INCREASE = 256

# default value for the DelayDAO Timer
DEFAULT_DAO_DELAY = 1

# default duration to wait in order to receive a DAO-ACK message
# (this value is not defined in the RFC)
DEFAULT_DAO_ACK_DELAY = 2

# number of times the node should try to send a DAO message before giving up
# (this value is not defined in the RFC)
DEFAULT_DAO_MAX_TRANS_RETRY = 3

# number of time a DAO will transmit No-Path that contains information on
# routes that recently have been deleted
DEFAULT_DAO_NO_PATH_TRANS = 3

# default maximum rank increased (0 means the mechanism is disabled)
DEFAULT_MAX_RANK_INCREASE = 3 * DEFAULT_MIN_HOP_RANK_INCREASE

# Rank for a virtual root that might be used to coordinate multiple roots
BASE_RANK = 0

# Rank for a DODAG root
# See Section 17: ROOT_RANK has a value of MinHopRankIncrease
ROOT_RANK = DEFAULT_MIN_HOP_RANK_INCREASE

# constant maximum for the Rank
INFINITE_RANK = 0xffff

#
# Non RFC defined constants
#
DEFAULT_INTERVAL_BETWEEN_DIS = 300  # 5 minutes (should be probably be set to a higher value)
