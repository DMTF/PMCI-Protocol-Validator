# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Class for MCTP over Serial (DSP0253)

File : dsp0253.py

Brief : Contains protocol class for MCTP over Serial (DSP0253)
"""

import struct
from scapy.all import bind_layers
from scapy.packet import Packet
from scapy.fields import XByteField, XShortField, PacketField, ByteField, ConditionalField
from pmci_protocol_validator.mctp.classes.dsp0236 import MCTP_HEADER

DSP0253_COMPLIANCE_VERSION = int.from_bytes([1, 0, 0, 0], 'big')


class SERIAL(Packet):
    """ MCTP over Serial binding class (DSP0253) """

    name = "MCTP Serial Header"

    fields_desc = [
        XByteField("FramingFlagStart", 0x7E),
        ByteField("ProtocolRevision", 1),
        ByteField("ByteCount", None),
        ConditionalField(
            PacketField("MctpHeader", None, MCTP_HEADER),
            lambda pkt: pkt is not None
        ),
        XShortField("FrameCheckSequence", None),
        XByteField("FramingFlagEnd", None)
    ]

    def post_build(self, pkt: bytes, payload: bytes) -> bytes:
        """ Insert the ByteCount and FrameCheckSequence AFTER the packet is built. """

        if self.MctpHeader is not None:
            payload = pkt[3:-3]

        pkt = pkt[0:3]

        if self.ByteCount is None:
            self.ByteCount = len(payload)

        _byte_count = struct.pack("B", self.ByteCount)
        _return_pkt = pkt[:2] + _byte_count + pkt[3:]

        _return_pkt = _return_pkt + payload

        # TODO: Add code to calculate checksum
        if self.FrameCheckSequence is None:
            self.FrameCheckSequence = 0xDEAD

        _checksum = struct.pack(">H", self.FrameCheckSequence)
        _return_pkt = _return_pkt + _checksum

        _return_pkt = _return_pkt + struct.pack("B", 0x7E)
        return self.encode(_return_pkt)

    def pre_dissect(self, s: bytes) -> bytes:
        """ Reverse line encoding BEFORE dissecting packet """

        return self.decode(s)

    def do_dissect(self, pkt: bytes) -> bytes:
        """
        Dissect the packet for use

        Need to override this to pull out the PEC because the SCAPY framework
        does not seem to be able to do it when you have a PacketField in the
        layer.  This code from SCAPY's Packet class and inserted code to
        extract the checksum.
        """

        _raw_pkt = pkt

        ### Begining of custom code ###
        if len(pkt) >= 6:
            _end_of_frame = pkt[-1:]
            (_end_of_frame,) = struct.unpack("B", _end_of_frame)
            self.fields["FramingFlagEnd"] = _end_of_frame
            pkt = pkt[:-1]

            _frame_checksum = pkt[-2:]
            (_frame_checksum,) = struct.unpack(">H", _frame_checksum)
            self.fields["FrameCheckSequence"] = _frame_checksum
            pkt = pkt[:-2]
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
        self.raw_packet_cache = _raw_pkt[: -len(pkt)] if pkt else _raw_pkt
        self.explicit = 1

        return pkt

    @staticmethod
    def encode(data: bytes) -> bytes:
        """ Encode data. See DSP0253 "7. Packet Framing and Encapsulation" """

        # The first byte should be a FRAMING FLAG
        _encoded_data = data[0:1]

        # Iterate the payload encoding bytes as required
        for value in data[1:-1]:
            if value == 0x7E:
                _encoded_data += b'\x7D\x5E'
            elif value == 0x7D:
                _encoded_data += b'\x7D\x5D'
            else:
                _encoded_data += value.to_bytes(1, 'little')

        # The last byte should be a FRAMING FLAG
        _encoded_data += data[-1::1]
        return _encoded_data

    @staticmethod
    def decode(data: bytes) -> bytes:
        """ Decode data. See DSP0253 "7. Packet Framing and Encapsulation" """

        # The first byte should be a FRAMING FLAG
        decoded_data = data[0:1:1]

        # Iterate the data decoding bytes as required
        i = 1
        while i < (len(data) - 1):
            if data[i] == 0x7D and data[i+1] == 0x5E:
                decoded_data += b'\x7E'
                i += 1  # Skip the next data[] byte
            elif data[i] == 0x7D and data[i+1] == 0x5D:
                decoded_data += b'\x7D'
                i += 1  # Skip the next data[] byte
            else:
                decoded_data += data[i:i+1:1]
            i += 1

        # The last byte should be a FRAMING FLAG
        decoded_data += data[-1::1]
        return decoded_data


# Bind SCAPY layer
bind_layers(SERIAL, MCTP_HEADER, FramingFlagStart=0x7E)
