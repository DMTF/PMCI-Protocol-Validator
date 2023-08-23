# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0280 communications binding.
##############################################################################

import socket
from scapy.all import raw
from testframework.medium import physicalMedium
from ptti.dmtf import TestServiceWrapper


class PTTIMedium(physicalMedium):
    """Socket connection to Test Server supporting DSP0280 specification"""

    DEFAULT_TIMEOUT = 2  # in seconds

    def __init__(self, TargetIP, TargetPort):
        """Initialize PTTIMedium class and underlying base class"""

        # Initialize base class
        super().__init__(self, self.DEFAULT_TIMEOUT)

        # Open the network connection
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((TargetIP, TargetPort))

        # Initialize local variables
        self.__ExceptionOcurred = None
        return

    def _close(self):
        """Gracefully shutdown the communications interface"""

        self._socket.close()
        return

    def _write(self, payload, rsp_expected=True):
        """Output a protocol packet to the communications interface"""

        self._socket.sendall(raw(payload))

        if rsp_expected is True:
            self.__readFn()

        return

    def _checkStatus(self):
        """Check the operational status of the communications interface"""

        return self.__ExceptionOcurred

    def _packetize(self, rawData):
        """Create a protocol packet from received raw binary data"""

        return TestServiceWrapper(rawData)

    def __readFn(self):
        """Helper function to read network packets"""

        _chunk = b''

        try:
            _chunk = self._socket.recv(255)
        except:
            pass

        if len(_chunk) > 0:
            self._addReadPacket(raw(TestServiceWrapper(_chunk)))

        return
