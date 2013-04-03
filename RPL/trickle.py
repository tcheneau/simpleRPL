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

"""(Somewhat generic) Trickle timer (See RFC 6206)"""
from random import uniform
from threading import Timer, RLock

import logging
logger = logging.getLogger("RPL")


class trickleTimer(object):
    I = 0  # current interval size
    t = 0  # time within the current interval
    c = 0  # a counter

    def __init__(self, function, kwargs={}, Imin=0.1, Imax=16, k=2):
        """Trickle timer:
        - function: function to execute when the timer expires
        - kwargs: argument of the function
        - Imin: minimum interval size (default 100 ms)
        - Imax: maximum interval size, expressed in the number of doubling of
          the minimum interval size (default 16, that is 6553.6 seconds)
        - k: redundancy constant"""
        super(trickleTimer, self).__init__()
        self.Imin = Imin
        self.Imax = Imin * 2 ** Imax
        self.k = k

        # step 1
        self.I = uniform(self.Imin, self.Imax)
        # step 2
        self.c = 0
        self.t = uniform(self.I / 2, self.I)

        # store the function, so that it can be rescheduled multiple times
        self.function = function
        self.kwargs = kwargs
        logger.debug("next trickle timer is set to run in %f seconds" % self.t)
        self.lock = RLock()
        self.thread = Timer(self.t, self.__run)
        self.thread.daemon = True

    def start(self):
        """Actually starts the timer"""
        with self.lock:
            if not self.thread.is_alive():
                self.thread.start()

    def cancel(self):
        """Cancel the timer"""
        with self.lock:
            if self.thread.is_alive():
                self.thread.cancel()

    def __run(self):
        """Run the function passed to the trickleTimer"""
        with self.lock:
            if self.can_transmit():
                self.function(** self.kwargs)
            self.expired()

    def hear_consistent(self):
        """Receive a consistent message"""
        with self.lock:
            # step 3
            logger.debug("Hearing a consistent message")
            self.c += 1

    def can_transmit(self):
        """Check if the node can transmit its message (t has been reached)"""
        with self.lock:
            # step 4
            return self.k == 0 or self.c < self.k

    def expired(self):
        """Trickle timer has expired"""
        with self.lock:
            # step 5
            logger.debug("trickle timer has expired, increasing minimum interval size")
            self.I = self.I * 2
            if self.I > self.Imax:
                logger.info("trickle timer has reached maximum interval size")
                self.I = self.Imax

            # this is not in the RFC, but in the trickle paper from NSDI'04
            self.c = 0

            # set the new timer
            self.t = uniform(self.I / 2, self.I)
            logging.debug("next trickle timer is set to run in %f seconds" % self.t)

            try:
                self.thread.cancel()  # should never be needed
            except:
                pass

            self.thread = Timer(self.t, self.__run)
            self.thread.daemon = True
            self.thread.start()

    def hear_inconsistent(self):
        """Receive an inconsistent message (triggers timer reset)"""
        with self.lock:
            # step 6
            logger.info("hearing an inconsistent message, reset trickle timer")
            if self.I != self.Imin:
                self.I = self.Imin
                self.c = 0
                self.t = uniform(self.I / 2, self.I)

                self.cancel()
                self.thread = Timer(self.t, self.__run)
                self.thread.daemon = True
                self.thread.start()

    def __del__(self):
        self.cancel()
        super(trickleTimer, self).__del__()
