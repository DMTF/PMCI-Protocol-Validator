# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Class for MCTP over PCIe VDM (DSP0238)

File : dsp0238.py

Brief : Contains protocol class for MCTP over PCIe VDM (DSP0238)
"""

import struct
from scapy.all import bind_layers
from scapy.packet import Packet
from scapy.fields import BitField, XByteField, XShortField, PacketField
from pmci_protocol_validator.mctp.classes.dsp0236 import MCTP_HEADER


DMTF_VENDOR_ID = 0x1AB4
DSP0238_COMPLIANCE_VERSION = int.from_bytes([1, 2, 0, 0], 'big')


class PCIE_VDM(Packet):
    """ MCTP over PCIe VDM binding class (DSP0238 v1.2.0) """

    # DSP0238 - Figure 1
    name = "MCTP PCIe VDM Header"

    fields_desc = [
        # Byte 0
        BitField("Format", 3, 3),
        BitField("Type", 2, 5),

        # Byte 1
        BitField("T9", 0x0, 1),
        BitField("TC", 0x0, 3),
        BitField("Reserved0", 0x0, 4),

        # Bytes 2 & 3
        BitField("TD", 0, 1),
        BitField("EP", 0, 1),
        BitField("Attr", 0, 2),
        BitField("AT", 0x0, 2),
        BitField("Length", None, 10),

        # Bytes 4 & 5
        XByteField("RequesterBus", 0x00),
        BitField("RequesterDevice", 0x00, 5),
        BitField("RequesterFunction", 0x00, 3),

        # Byte 6
        BitField("Reserved1", 0, 2),
        BitField("PadLen", None, 2),
        BitField("MctpVdmCode", 0, 4),

        # Byte 7
        XByteField("MessageCode", 0x7F),

        # Bytes 8 & 9
        XByteField("TargetBus", 0x00),
        BitField("TargetDevice", 0x00, 5),
        BitField("TargetFunction", 0x00, 3),

        # Bytes 10 & 11
        XShortField("VendorID", DMTF_VENDOR_ID),

        # MCTP Transport Header
        PacketField("MctpHeader", None, MCTP_HEADER)
    ]

    def addPaddingToPayload(self, pkt: bytes, pay: bytes) -> bytes:
        """ Add the padding to the payload """

        currLen = len(pkt) + len(pay)

        if self.PadLen is None:
            padLen = (4 - (currLen % 4)) % 4
            self.PadLen = padLen

        padData = b"\00" * self.PadLen  # add the padding to end of packet

        retPkt = pay + padData
        return retPkt

    def updateLength(self, pkt: bytes, pay: bytes) -> bytes:
        """ Insert the length in DWORDS into PCIE VDM header """

        if self.Length is None:
            payloadLen = len(pay) - 4  # Payload Len starts after MCTP Transport Header

            if payloadLen > 0:
                self.Length = payloadLen / 4  # Convert bytes to DWORD
            else:
                self.Length = 0

            self.Length = int(self.Length)  # Remove floating point from div

            (LenAndOther,) = struct.unpack("!H", pkt[2:4])
            other = LenAndOther & 0xFC00  # mask of any existing Len
            combined = (
                other | self.Length
            )  # combine the upper bits back with the length

            encodedShort = struct.pack("!H", combined)
            return_pkt = (pkt[:2] + encodedShort + pkt[4:])

        else:
            return_pkt = pkt

        return return_pkt

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        """ Adds padding, padlen and payload len """

        if self.MctpHeader is not None:
            pay = pkt[12:]
            pkt = pkt[0:12]

        # Add padding
        paddedPayload = self.addPaddingToPayload(pkt, pay)

        # Insert the padLen into the packet
        (byteWithPadLen,) = struct.unpack("B", bytes([pkt[6]]))
        byteWithPadLen = byteWithPadLen & 0xCF  # zero out the PadLen Bits
        padLen = self.PadLen << 4
        byteWithPadLen = byteWithPadLen | padLen  # put padLen back
        encodedByte = struct.pack("B", byteWithPadLen)
        updatedPkt = (pkt[:6] + encodedByte + pkt[7:])

        # Update payload length
        return_pkt = self.updateLength(updatedPkt, paddedPayload)  # add payloadLen
        return_pkt = return_pkt + paddedPayload  # final packet
        return return_pkt


# Bind SCAPY layer
bind_layers(PCIE_VDM, MCTP_HEADER, VendorID=DMTF_VENDOR_ID)
