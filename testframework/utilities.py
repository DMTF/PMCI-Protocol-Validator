# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Common library functions to support test cases.
##############################################################################

from testframework.medium import physicalMedium
from scapy.packet import Packet


def common_send_receive(commObject, SendPacket, fctShowPacket=None):
    """Send a request packet and receive the response packet"""

    assert (isinstance(commObject, physicalMedium)), "common_send_receive: commObject is invalid"
    assert (isinstance(SendPacket, Packet)), "common_send_receive: SendPacket is NOT type Packet"

    if fctShowPacket is not None:
        assert (callable(fctShowPacket)), "common_send_receive: fctShowPacket() is NOT callable"

    if fctShowPacket is not None:
        fctShowPacket(SendPacket)

    ErrorCode = commObject.Write(SendPacket)

    assert (ErrorCode == physicalMedium.ERROR_SUCCESS), \
        "%s" % physicalMedium.ResponseToStr(ErrorCode)

    (ErrorCode, RecvPacket) = commObject.Read()

    if ErrorCode == physicalMedium.ERROR_SUCCESS and fctShowPacket is not None:
        fctShowPacket(RecvPacket)

    assert (ErrorCode == physicalMedium.ERROR_SUCCESS), \
        "%s" % physicalMedium.ResponseToStr(ErrorCode)

    return RecvPacket
