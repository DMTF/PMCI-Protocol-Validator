# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
RMII Based Transport (RBT)

File : dsp0222_rbt.py

Brief : Wrapper for RMII Based Transport (RBT)
"""

import struct
from scapy.all import bind_layers, scapy
from scapy.packet import Packet
from scapy.fields import XShortField

from pmci_protocol_validator.ncsi.dsp0222 import NCSI_HEADER, getNcsiClassFromRaw

DSP0261_COMPLIANCE_VERSION = int.from_bytes([1, 2, 3, 0], 'big')


class RBT(Packet):
    """Scapy RMII Based Transport (RBT) Layer"""

    name = "RMII Based Transport"
    fields_desc = [
        scapy.layers.l2.DestMACField("DA"),
        scapy.layers.l2.SourceMACField("SA"),
        XShortField("EtherType", 0x88F8)
    ]

    def post_build(self, pkt, pay):
        """pads the Ethernet from to at least 64 bytes"""
        fullPkt = super().post_build(pkt, pay)

        """ call the super to do the build then append padding """
        pktLen = len(fullPkt)
        if pktLen < 60:
            pad_len = 60 - pktLen
            pad = b"\x00" * pad_len
            fullPkt = fullPkt + pad

        return fullPkt

    def extract_padding(self, payload):
        """removes the Ethernet Padding from RBT layer"""

        # get the Packet Length from the NC-SI header
        (pktLen,) = struct.unpack("!H", payload[6:8])
        pktLen = pktLen & 0x0FFF  # top 4 bits are reserved, and not part of pktlen

        ncsiPadLen = (4 - (pktLen % 4)) % 4  # calculate NCSI Pad Length
        # not all commands have checksums
        # so go figure out what the payload type is, create a
        # quick instance and call the method to get the checksum len
        # and need to know if there is a checksum to properly strip
        # Ethernet padding from packet
        ncsiPayloadtClass = getNcsiClassFromRaw(payload)
        inst = ncsiPayloadtClass()

        ncsiChecksumLen = inst.getChecksumLen()

        startOfPad = (
            pktLen + NCSI_HEADER.NCSI_HEADER_LENGTH + ncsiPadLen + ncsiChecksumLen
        )

        ncsiPayload = payload[
            :startOfPad
        ]  # this is the NC-IS payload, including NC-SI pad and checksum

        paddingData = payload[startOfPad:]  # this will be the ethernet pad
        return ncsiPayload, paddingData


# SCAPY bind EtherType in RBT to NC-SI Payload
bind_layers(RBT, NCSI_HEADER, EtherType=0x88F8)
