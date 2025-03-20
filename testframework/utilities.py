# Copyright Notice:
# Copyright 2023-2025 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Common library functions to support test cases.
##############################################################################

from testframework.medium import physicalMedium
from scapy.packet import Packet, raw


def common_send_receive(commObject: physicalMedium, sendPacket: Packet, fctShowPacket=None) -> Packet:
    """ Send a request packet and receive the response packet """

    assert (isinstance(commObject, physicalMedium)), "common_send_receive: commObject is invalid"
    assert (isinstance(sendPacket, Packet)), "common_send_receive: SendPacket is NOT type Packet"

    if fctShowPacket is not None:
        assert (callable(fctShowPacket)), "common_send_receive: fctShowPacket() is NOT callable"
        fctShowPacket(sendPacket)

    ErrorCode = commObject.Write(sendPacket)
    assert (ErrorCode == physicalMedium.ERROR_SUCCESS), f"common_send_receive: {commObject.ResponseToStr(ErrorCode)}"

    (ErrorCode, RecvPacket) = commObject.Read()

    if ErrorCode == physicalMedium.ERROR_SUCCESS and fctShowPacket is not None:
        fctShowPacket(RecvPacket)

    assert (ErrorCode == physicalMedium.ERROR_SUCCESS), f"common_send_receive: {commObject.ResponseToStr(ErrorCode)}"
    return RecvPacket


def render_packet(packet: Packet) -> Packet:
    """ Build a packet so that all fields are populated """

    assert (isinstance(packet, Packet)), "render_packet: parameter is NOT type Packet"
    return packet.__class__(raw(packet))
