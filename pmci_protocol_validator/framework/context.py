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


class FwkContext(object):
    """ Test framework context base class """

    def __init__(self, comm_if: CommMedium, log_pkts: bool = False):
        """ Class constructor """

        assert (comm_if is not None), "ERROR: comm_if parameter is required"

        self.commObject: CommMedium = comm_if
        self.log_packets: bool = log_pkts
        return

    def __del__(self):
        """ Class destructor """

        try:
            self.commObject.close()
        except:
            pass

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
