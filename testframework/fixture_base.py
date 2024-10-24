# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Base class to represent test fixtures
##############################################################################

from scapy.packet import Packet
from testframework.medium import physicalMedium


class c_FixtureBase(object):
    """ Test fixture base class """

    def __init__(self, comm_if: physicalMedium):
        """ c_FixtureBase class constructor """

        if comm_if is None:
            raise Exception("c_FixtureBase: ERROR: A comm object is required")

        self.commObject = comm_if
        return

    def __del__(self):
        """ c_FixtureBase class destructor """

        if self.commObject is not None:
            self.commObject._close()

        return

    def VerifyCommonFields(self, rsp_pkt: Packet, req_pkt: Packet):
        """ Verify common fields """

        return

    def logMessage(self, msg_str: str):
        """ Log a message """

        print(msg_str)
        return

    def showPacket(self, packet: Packet):
        """ Display the packet contents """

        packet.show2()
        return
