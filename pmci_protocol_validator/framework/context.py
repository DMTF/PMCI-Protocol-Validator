# Copyright Notice:
# Copyright 2024-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Test framework context

File : context.py

Brief : Base class to represent the test framework context
"""

from scapy.packet import Packet
from pmci_protocol_validator.framework.medium import CommMedium


class FwkContext:
    """ Test framework context base class """

    def __init__(self, comm_if: CommMedium, log_pkts: bool = False):
        """ Class constructor """

        assert (isinstance(comm_if, CommMedium)), "Invalid type for comm_if"

        self.commObject: CommMedium = comm_if
        self.log_packets: bool = log_pkts
        return

    def close(self, close_comm_if: bool =False):
        """ Close down test framework """

        if close_comm_if is True:
            self.commObject.close()

        return

    def log_msg(self, msg_str: str) -> None:
        """ Log a message """

        if self.log_packets is True:
            print(msg_str)
        return

    def show_pkt(self, packet: Packet) -> None:
        """ Display the packet contents """

        self.log_msg(str(packet.show2(dump=True)))
        return
