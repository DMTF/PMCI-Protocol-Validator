# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Base class to represent test fixtures
##############################################################################

from scapy.packet import Packet
from pmci_protocol_validator.framework.medium import CommMedium


class FixtureBase(object):
    """ Test fixture base class """

    def __init__(self, comm_if: CommMedium):
        """ Class constructor """

        if comm_if is None:
            raise Exception("FixtureBase: ERROR: A comm object is required")

        self.commObject = comm_if
        return

    def __del__(self):
        """ Class destructor """

        if self.commObject is not None:
            self.commObject._close()

        return

    def verify_common_fields(self, rsp_pkt: Packet, req_pkt: Packet) -> bool:
        """ Verify common fields """

        return True

    def log_msg(self, msg_str: str) -> None:
        """ Log a message """

        print(msg_str)
        return

    def show_pkt(self, packet: Packet) -> None:
        """ Display the packet contents """

        packet.show2()
        return
