# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Classes for MCTP over SMBus (DSP0237)

File : dsp0237.py

Brief : Contains protocol class for MCTP over SMBus (DSP0237)
"""

import struct
from scapy.all import bind_layers
from scapy.packet import Packet
from scapy.fields import BitField, XByteField, XShortField, PacketField, ByteField
from pmci_protocol_validator.mctp.classes.dsp0236 import MCTP_HEADER


DMTF_VENDOR_ID = 0x1AB4
DSP0237_COMPLIANCE_VERSION = int.from_bytes([1, 2, 0, 0], 'big')


PEC_CRC8 = [
    0x00, 0x07, 0x0E, 0x09, 0x1C, 0x1B, 0x12, 0x15, 0x38, 0x3F, 0x36, 0x31, 0x24, 0x23, 0x2A, 0x2D,
    0x70, 0x77, 0x7E, 0x79, 0x6C, 0x6B, 0x62, 0x65, 0x48, 0x4F, 0x46, 0x41, 0x54, 0x53, 0x5A, 0x5D,
    0xE0, 0xE7, 0xEE, 0xE9, 0xFC, 0xFB, 0xF2, 0xF5, 0xD8, 0xDF, 0xD6, 0xD1, 0xC4, 0xC3, 0xCA, 0xCD,
    0x90, 0x97, 0x9E, 0x99, 0x8C, 0x8B, 0x82, 0x85, 0xA8, 0xAF, 0xA6, 0xA1, 0xB4, 0xB3, 0xBA, 0xBD,
    0xC7, 0xC0, 0xC9, 0xCE, 0xDB, 0xDC, 0xD5, 0xD2, 0xFF, 0xF8, 0xF1, 0xF6, 0xE3, 0xE4, 0xED, 0xEA,
    0xB7, 0xB0, 0xB9, 0xBE, 0xAB, 0xAC, 0xA5, 0xA2, 0x8F, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9D, 0x9A,
    0x27, 0x20, 0x29, 0x2E, 0x3B, 0x3C, 0x35, 0x32, 0x1F, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0D, 0x0A,
    0x57, 0x50, 0x59, 0x5E, 0x4B, 0x4C, 0x45, 0x42, 0x6F, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7D, 0x7A,
    0x89, 0x8E, 0x87, 0x80, 0x95, 0x92, 0x9B, 0x9C, 0xB1, 0xB6, 0xBF, 0xB8, 0xAD, 0xAA, 0xA3, 0xA4,
    0xF9, 0xFE, 0xF7, 0xF0, 0xE5, 0xE2, 0xEB, 0xEC, 0xC1, 0xC6, 0xCF, 0xC8, 0xDD, 0xDA, 0xD3, 0xD4,
    0x69, 0x6E, 0x67, 0x60, 0x75, 0x72, 0x7B, 0x7C, 0x51, 0x56, 0x5F, 0x58, 0x4D, 0x4A, 0x43, 0x44,
    0x19, 0x1E, 0x17, 0x10, 0x05, 0x02, 0x0B, 0x0C, 0x21, 0x26, 0x2F, 0x28, 0x3D, 0x3A, 0x33, 0x34,
    0x4E, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5C, 0x5B, 0x76, 0x71, 0x78, 0x7F, 0x6A, 0x6D, 0x64, 0x63,
    0x3E, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2C, 0x2B, 0x06, 0x01, 0x08, 0x0F, 0x1A, 0x1D, 0x14, 0x13,
    0xAE, 0xA9, 0xA0, 0xA7, 0xB2, 0xB5, 0xBC, 0xBB, 0x96, 0x91, 0x98, 0x9F, 0x8A, 0x8D, 0x84, 0x83,
    0xDE, 0xD9, 0xD0, 0xD7, 0xC2, 0xC5, 0xCC, 0xCB, 0xE6, 0xE1, 0xE8, 0xEF, 0xFA, 0xFD, 0xF4, 0xF3
]


class SMBUS(Packet):
    """ MCTP over SMBus binding class (DSP0237)"""

    # DSP0237 - Figure 1
    name = "MCTP SM Bus Header"

    fields_desc = [
        # Byte 0
        BitField("DestAddr", 0, 7),
        BitField("DestRW", 0, 1),

        # Byte 1
        XByteField("CommandCode", 0x0F),

        # Byte 2
        ByteField("ByteCount", None),

        # Byte 3
        BitField("SrcAddr", 0, 7),
        BitField("SrcRW", 1, 1),

        # the MCTP payload
        PacketField("MctpHeader", None, MCTP_HEADER),
        XByteField("PEC", None)
    ]

    def calculate_pec(self, pkt: bytes) -> bytes:
        """ Generates CRC-8 value from the input data """

        crc = 0
        for _data in pkt:
            crc = PEC_CRC8[(_data ^ crc)]

        return crc

    def post_build(self, pkt: bytes, pay: bytes) -> bytes:
        """
        Override default behavior and build the packet then
        insert the ByteCount and PEC.
        """

        if self.MctpHeader is not None:
            pay = pkt[4:-1]

        pkt = pkt[0:4]

        # Only calculate if it was not overridden (for testing purposes)
        if self.ByteCount is None:
            # This is the MCTP payload plus the Source Address byte
            self.ByteCount = len(pay) + 1

        _byte_count = struct.pack("B", self.ByteCount)

        # This will be the SMBus header without PEC
        _return_pkt = pkt[:2] + _byte_count + pkt[3:4]

        # Entire packet (MCTP over SMBus) without PEC
        _return_pkt = _return_pkt + pay

        if self.PEC is None:
            self.PEC = self.calculate_pec(_return_pkt)

        _encoded_pec = struct.pack("B", self.PEC)
        _return_pkt = _return_pkt + _encoded_pec  # Append on the PEC
        return _return_pkt

    def do_dissect(self, pkt):
        """
        Need to override this to pull out the PEC because the SCAPY framework
        does not seem to be able to do it when you have a PacketField in the
        layer.  This code from SCAPY's Packet class and inserted code to
        extract the checksum.
        """
        _raw = pkt

        ### Begining of custom code ###
        if len(pkt) > 4:
            PEC = pkt[-1:]
            (self.PEC,) = struct.unpack("B", PEC)
            self.fields["PEC"] = self.PEC
            pkt = pkt[:-1]
        ### End of custom code ###

        self.raw_packet_cache_fields = {}
        for f in self.fields_desc:
            if not pkt:
                break
            pkt, fval = f.getfield(self, pkt)
            # Need to track fields with mutable values to discard
            # .raw_packet_cache when needed.
            if f.islist or f.holds_packets or f.ismutable:
                self.raw_packet_cache_fields[f.name] = f.do_copy(fval)
            self.fields[f.name] = fval
        self.raw_packet_cache = _raw[: -len(pkt)] if pkt else _raw
        self.explicit = 1
        return pkt


# Bind SCAPY layer
bind_layers(SMBUS, MCTP_HEADER, CommandCode=0x0F)
