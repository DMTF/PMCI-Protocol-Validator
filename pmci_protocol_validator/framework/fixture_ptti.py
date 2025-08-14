# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Class to represent PTTI test fixtures
##############################################################################

from scapy.packet import Packet
from pmci_protocol_validator.framework.fixture_base import FixtureBase
from pmci_protocol_validator.ptti.classes.dsp0280 import VERSION_COMPLIANCE, TestServiceWrapper
from pmci_protocol_validator.ptti.classes.dsp0280_comm import PTTIMedium


class PTTI_fixture(FixtureBase):
    """ PTTI test fixture """

    def __init__(self, prm_tcp_addr: str, prm_tcp_port: int):
        """ c_PTTI_fixture class constructor """

        super().__init__(PTTIMedium(prm_tcp_addr, prm_tcp_port))

        self.tcp_address = prm_tcp_addr
        self.tcp_port = prm_tcp_port
        self.test_client_id = 0
        return

    def __del__(self):
        """ c_PTTI_fixture class destructor """

        super().__del__()
        return

    def verify_common_fields(self, rsp_pkt: Packet, req_pkt: Packet) -> bool:
        """ Verify TestServiceWrapper common fields """

        assert (rsp_pkt[TestServiceWrapper].Version == VERSION_COMPLIANCE), "Incorrect PTTI version"
        assert (rsp_pkt[TestServiceWrapper].ProtocolType == req_pkt[TestServiceWrapper].ProtocolType), "Protocol mismatch"
        assert (rsp_pkt[TestServiceWrapper].Reserved_0 == 0), "Reserved field NOT zero"
        assert (rsp_pkt[TestServiceWrapper].Reserved_1 == 0), "Reserved field NOT zero"
        assert (rsp_pkt[TestServiceWrapper].TestClientID == self.test_client_id), "Incorrect Test Client ID"
        return True
