# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Class for MCTP over USB (DSP0283)

File : dsp283.py

Brief : Contains protocol class for MCTP over USB (DSP0283)
"""

import struct
from scapy.all import bind_layers
from scapy.packet import Packet
from scapy.fields import XByteField, XShortField, PacketField, ByteField
from pmci_protocol_validator.mctp.dsp0236 import MCTP_HEADER


DMTF_VENDOR_ID = 0x1AB4
DSP0283_COMPLIANCE_VERSION = int.from_bytes([1, 0, 0, 0], 'big')


class USB(Packet):
    """ MCTP over USB binding class (DSP0283 v1.0.0) """

    name = "MCTP USB Header"

    fields_desc = [
        XShortField("DMTF_ID", DMTF_VENDOR_ID),
        XByteField("RSVD", 0x00),
        ByteField("Length", None),
        PacketField("MctpHeader", None, MCTP_HEADER)
    ]

    def post_build(self, pkt: bytes, payload: bytes) -> bytes:
        """ Populate length field AFTER Scapy builds the packet """

        if self.MctpHeader is not None:
            payload = pkt[4:]

        if self.Length is None:
            self.Length = len(payload)

        _byte_count = struct.pack("B", self.Length)

        returnPacket = pkt[:3] + _byte_count + payload
        return returnPacket


# Bind SCAPY layer
bind_layers(USB, MCTP_HEADER, DMTF_ID=DMTF_VENDOR_ID)
