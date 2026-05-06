# Copyright Notice:
# Copyright 2023-2025 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Common library functions to support test cases.
##############################################################################

from scapy.packet import Packet, raw
from pmci_protocol_validator.framework.medium import CommMedium
from pmci_protocol_validator.framework.fixture_base import FixtureBase


def common_send_receive(fwk_ctx: FixtureBase, send_pkt: Packet) -> tuple[int, Packet|None]:
    """ Send a request packet and receive the response packet """

    _error_code, _recv_pkt = common_send_receive_ex(fwk_ctx.commObject, send_pkt, fwk_ctx.show_pkt)
    return _error_code, _recv_pkt


def common_send_receive_ex(comm_obj: CommMedium, send_pkt: Packet, fct_show_pkt=None) -> tuple[int, Packet|None]:
    """ Send a request packet and receive the response packet """

    assert (isinstance(comm_obj, CommMedium)), "common_send_receive: commObject is invalid"
    assert (isinstance(send_pkt, Packet)), "common_send_receive: SendPacket is NOT type Packet"

    if fct_show_pkt is not None:
        assert (callable(fct_show_pkt)), "common_send_receive: fctShowPacket() is NOT callable"
        fct_show_pkt(send_pkt)

    _error_code = comm_obj.write(send_pkt)

    _recv_pkt = None
    if _error_code == CommMedium.ERROR_SUCCESS:
        _error_code, _recv_pkt = comm_obj.read()

        if _error_code == CommMedium.ERROR_SUCCESS and fct_show_pkt is not None:
            fct_show_pkt(_recv_pkt)

    return _error_code, _recv_pkt


def render_packet(packet: Packet) -> Packet:
    """ Build a packet so that all fields are populated """

    assert (isinstance(packet, Packet)), "render_packet: parameter is NOT type Packet"
    return packet.__class__(raw(packet))


def bin2hex(bin_data: bytes) -> str:
    """ Convert a binary arrary to an array ASCII hex """

    return ''.join('{:02x} '.format(x) for x in bin_data)
