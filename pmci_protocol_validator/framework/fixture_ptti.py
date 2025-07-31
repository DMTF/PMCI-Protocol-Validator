# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Class to represent PTTI test fixtures
##############################################################################

from scapy.packet import Packet
from testframework.fixture_base import c_FixtureBase
from ptti.binding import PTTIMedium
from ptti.dmtf import VERSION_COMPLIANCE, TestServiceWrapper


class c_PTTI_fixture(c_FixtureBase):
    """ PTTI test fixture """

    def __init__(self, prmTcpAddress: str, prmTcpPort: int):
        """ c_PTTI_fixture class constructor """

        super().__init__(PTTIMedium(prmTcpAddress, prmTcpPort))

        self.tcpAddress = prmTcpAddress
        self.tcpPort = prmTcpPort
        self.testClientID = 0
        return

    def __del__(self):
        """ c_PTTI_fixture class destructor """

        super().__del__()
        return

    def VerifyCommonFields(self, rsp_pkt: Packet, req_pkt: Packet):
        """ Verify TestServiceWrapper common fields """

        assert (rsp_pkt[TestServiceWrapper].Version == VERSION_COMPLIANCE), "Incorrect PTTI version"
        assert (rsp_pkt[TestServiceWrapper].ProtocolType == req_pkt[TestServiceWrapper].ProtocolType), "Protocol mismatch"
        assert (rsp_pkt[TestServiceWrapper].Reserved_0 == 0), "Reserved field NOT zero"
        assert (rsp_pkt[TestServiceWrapper].Reserved_1 == 0), "Reserved field NOT zero"
        assert (rsp_pkt[TestServiceWrapper].TestClientID == self.testClientID), "Incorrect Test Client ID"
        return
