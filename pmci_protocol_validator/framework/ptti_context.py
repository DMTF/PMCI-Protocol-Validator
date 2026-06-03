# Copyright Notice:
# Copyright 2024-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Class defining PTTI test framework context

File : ptti_context.py

Brief : Class defining PTTI test framework context.
"""

from scapy.packet import Packet
from pmci_protocol_validator.framework.context import FwkContext
from pmci_protocol_validator.ptti.dsp0280 import VERSION_COMPLIANCE, TestServiceWrapper
from pmci_protocol_validator.ptti.dsp0280_comm import PTTIMedium


class PTTI_Context(FwkContext):
    """ PTTI test fixture """

    def __init__(self, prm_tcp_addr: str, prm_tcp_port: int, log_pkts:bool = False):
        """ c_PTTI_fixture class constructor """

        super().__init__(PTTIMedium(prm_tcp_addr, prm_tcp_port), log_pkts)

        self.tcp_address = prm_tcp_addr
        self.tcp_port = prm_tcp_port
        self.test_client_id = 0
        return
