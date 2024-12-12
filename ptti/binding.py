# Copyright Notice:
# Copyright 2023-2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0280 communications binding.
##############################################################################

import socket
import threading

from scapy.all import raw
from testframework.medium import physicalMedium
from ptti.dmtf import TestServiceWrapper


class PTTIMedium(physicalMedium):
    """ Socket connection to Test Server supporting DSP0280 specification """

    DEFAULT_TIMEOUT = 2  # in seconds

    def __init__(self, TargetIP, TargetPort):
        """ Initialize PTTIMedium class and underlying base class """

        # Initialize the base class
        super().__init__(self, self.DEFAULT_TIMEOUT)

        # Initialize local variables
        self.__ExceptionOcurred = None

        # Open the network connection
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((TargetIP, TargetPort))

        # Start up packet receiver thread
        self.__TerminateReadThread = False
        self.__readThread = threading.Thread(target=self.__readFn)
        self.__readThread.start()

        return

    def _close(self):
        """ Gracefully shutdown the communications interface """

        self.__TerminateReadThread = True
        return

    def _write(self, payload, rsp_expected=True):
        """ Output a protocol packet to the communications interface """

        if self.__TerminateReadThread is False:
            self._socket.sendall(raw(payload))

        return

    def _checkStatus(self):
        """ Check the operational status of the communications interface """

        return self.__ExceptionOcurred

    def _packetize(self, rawData):
        """ Create a protocol packet from received raw binary data """

        return TestServiceWrapper(rawData)

    def __readFn(self):
        """ Thread to receive network packets """

        while self.__TerminateReadThread is False:
            try:
                # Read packet header
                _chunk = self._socket.recv(16)

                if len(_chunk) >= 16:

                    # Read the remainder of the packet
                    _len = int.from_bytes(_chunk[8:9], byteorder='little')
                    _chunk = _chunk + self._socket.recv(_len)

                    # Add packet to RX queue
                    self._addReadPacket(_chunk)
            except:
                pass

        self._socket.close()
        return
