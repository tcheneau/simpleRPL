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
Implementation of the Objective Function Zero (see RFC 6552)
"""

from rpl_constants import INFINITE_RANK

# Objective Code Point
OCP = 0

# Constants (as defined in Section 6.3)
DEFAULT_STEP_OF_RANK = 3
MINIMUM_STEP_OF_RANK = 1
MAXIMUM_STEP_OF_RANK = 9
DEFAULT_RANK_STRETCH = 0
MAXIMUM_RANK_STRETCH = 5
DEFAULT_RANK_FACTOR  = 1
MINIMUM_RANK_FACTOR  = 1
MAXIMUM_RANK_FACTOR  = 4


def compute_rank_increase(dodag, parent_rank):
    """Compute the rank increase for a node"""
    # this is static here, because our implementation does not receive much
    # feedback from lower layers
    rank_increase = (DEFAULT_STEP_OF_RANK * DEFAULT_RANK_FACTOR + DEFAULT_RANK_STRETCH) * dodag.MinHopRankIncrease
    if parent_rank + rank_increase > INFINITE_RANK:
        return INFINITE_RANK
    else:
        return parent_rank + rank_increase

def compare_parents(parent1, parent2):
    """Compare two parents"""

    # sanity check
    if parent1.dodag.OCP != parent2.dodag.OCP:
        raise NotImplementedError("unable to compare rank between two different objective functions")

    # comparison only make sense within the same RPL instance
    if parent1.dodag.instanceID != parent2.dodag.instanceID:
        raise NotImplementedError("current implementation only support a single RPL instance")

    # over two grounded DODAG, select the one with the best administrative preference
    if (parent1.dodag.G and parent2.dodag.G):
        if parent1.dodag.Prf != parent2.dodag.Prf:
            return parent2.dodag.Prf - parent1.dodag.Prf

    # prefer grounded DODAG over a floating one
    if (not parent1.dodag.G and parent2.dodag.G):
        return 1  # parent 2
    if (not parent2.dodag.G and parent1.dodag.G):
        return -1 # parent 1

    # if the parent belong to the same DODAG,
    # the router that offer the most recent DODAG Version should be preferred
    if (parent1.dodag.dodagID == parent2.dodag.dodagID) and \
       (parent1.dodag.version != parent2.dodag.version):
        if parent2.dodag.version > parent1.dodag.version:
            return 1
        else:
            return -1

    # the parent that causes the lesser resulting Rank for this node should
    # be preferred
    rank1 = parent1.dodag.compute_rank_increase(parent1.rank)
    rank2 = parent2.dodag.compute_rank_increase(parent2.rank)
    if (parent1.dodag.DAGRank(rank1) != parent2.dodag.DAGRank(rank2)):
        return rank1 - rank2

    # a preferred parent should stay preferred
    if parent1.preferred:
        return -1

    if parent2.preferred:
        return 1

    # router that has announced a DIO message more recently should be
    # preferred
    return parent2.dodag.last_dio - parent1.dodag.last_dio

