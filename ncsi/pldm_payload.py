# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  This is where PLDM over NC-SI specific commands and wrappers are implemented
##############################################################################

import struct
from scapy.fields import *  # pylint: disable=unused-import, unused-wildcard-import
from scapy.packet import Packet
from scapy.all import bind_layers, checksum
from ncsi.dmtf_enums import STANDARD_RESPONSE_CODE_VALUES, STANDARD_REASON_CODE_VALUES

from pldm.dmtf import PLDM_HEADER
from ncsi.dmtf import (
    register_ncsi_class,
    NCSI_PAYLOAD,
    NCSI_HEADER
)


# Register a PLDM over NC-SI class
def register_pldm_over_ncsi(cls):
    register_ncsi_class(cls)


class NcsiOtherPayloadReversePadField(ReversePadField):
    """customize behavior of the ReversePadField to store the payload length
    in the packet, so it can be used in calculating the length of the packet
    later in the process. VERY important to have this at end of a NC-SI
    packet class definition, unless that packet does not have a checksum -
    such as OEM commands, in which case the payload.packet_len field
    must be set some place else. The payload.packet_len field is key to
    building the NC-SI header, checksum and padding. This one also includes
    the length of the payload
    """

    def addfield(
        self,
        pkt,  # type: BasePacket
        s,  # type: bytes
        val,  # type: Any
    ):
        # type: (...) -> bytes
        sval = self._fld.addfield(pkt, b"", val)

        fullLen = len(s)  # need length of this layer plus payload
        if len(pkt.payload) > 0:
            fullLen += len(pkt.payload)

        pkt.payload_len = fullLen

        return s + struct.pack("%is" % (self.padlen(fullLen)), self._padwith) + sval


class NCSI_PAYLOAD_OTHER(NCSI_PAYLOAD):
    """base class for Non NC-SI payloads within NC-SI, such as PLDM
    NOTE: This class is in this file for convenience, and because PLDM is
    the only 'other' payload available for NC-SI at this time - if there
    are others in the future, then this can be placed in its own file for
    easier common access.
    """

    __slots__ = ["Checksum"]

    def do_build2(self):
        try:
            x = self.payload
            x.show2()
            print()
        except:
            pass
        # if paylod is
        return Packet.do_build(self)

    def post_build(self, pkt, pay):
        if not hasattr(self, "payload_len"):
            self.payload_len = len(pay)

        x = self.payload
        """ override default behavior and build the packet """
        if len(pay) == 0:
            return pkt

        payloadLen = (
            self.payload_len
        )   # this will include the Reason/Response and any data within
            # command (like PLDM payload) and is set in the
            # NcsiOtherPayloadReversePadField

        if None == self.Checksum:
            checksumVal = checksum(pay)
            chksumLen = 4
            complementedChecksum = NCSI_HEADER.twos_complement(
                checksumVal, chksumLen * 4
            )
            self.Checksum = complementedChecksum
        else:
            checksumVal = self.Checksum
            complementedChecksum = checksumVal

        chksum = struct.pack("!i", complementedChecksum)

        while len(pay) % 4 > 0:  # Add padding
            pay = pay + b"\x00"

        retPkt = (
            pkt + pay + chksum
        )   # finished is pkt (header) payload, with padding and the checksum

        return retPkt

    def do_dissect(self, rawPkt):
        """
        Need to override this to pull out the checksum because the SCAPY
        framework does not seem to be able to do it when you have a
        PacketField in the layer. So this code was copied from scapy's
        Packet class and inserted some code to extract the checksum.
        """
        _raw = rawPkt

        ### Begining of custom code ###
        if len(rawPkt) > 4:
            chkSum = rawPkt[-4:]
            (chkSumVal,) = struct.unpack("!I", chkSum)
            self.fields["Checksum"] = chkSumVal
            rawPkt = rawPkt[:-4]
        ### End of custom code ###

        self.raw_packet_cache_fields = {}
        for f in self.fields_desc:
            if not rawPkt:
                break
            rawPkt, fval = f.getfield(self, rawPkt)
            # We need to track fields with mutable values to discard
            # .raw_packet_cache when needed.
            if f.islist or f.holds_packets or f.ismutable:
                self.raw_packet_cache_fields[f.name] = f.do_copy(fval)
            self.fields[f.name] = fval
        self.raw_packet_cache = _raw[: -len(rawPkt)] if rawPkt else _raw
        self.explicit = 1
        return rawPkt

    def extract_padding(self, s):
        return (s, "", )


class NCSI_PLDM_PAYLOAD(NCSI_PAYLOAD_OTHER):
    """base class for PLDM over NC-SI payloads. The PLDM message is the payload"""

    name = "PLDM Payload {NC-SI}"
    fields_desc = [
        ConditionalField(
            XShortField("ResponseCode", 0x00), lambda pkt: pkt.CommandValue & 0x80 > 0
        ),
        ConditionalField(
            XShortField("ReasonCode", 0x12), lambda pkt: pkt.CommandValue & 0x80 > 0
        ),
        XIntField("Checksum", None),
    ]


class NcsiPldm_Request(NCSI_PAYLOAD):
    """The NC-IS PLDM payload Request class,
    all of the work is done in the parent class,
    this one is for registration with NC-SI header
    """

    name = "PLDM Request {NC-SI}"
    CommandValue = 0x51

    def do_build(self):
        """need to remove the Checksum field, because it actually goes AFTER
        the PLDM header and payload, so we want to be able to manipulate it
        but put it in later in the post_build fn
        """
        for f in self.fields_desc:
            if f.name == "Checksum":
                chkSumField = f
        retVal = Packet.do_build(self)
        return retVal

    def post_build(self, pkt, pay):
        if not hasattr(self, "payload_len"):
            self.payload_len = len(pay)

        """ override default behavior and build the packet """
        if len(pay) == 0:
            return pkt

        payloadLen = (
            self.payload_len
        )   # this will include the Reason/Response and any data within
            # command (like PLDM payload) and is set in the
            # NcsiOtherPayloadReversePadField

        checksumVal = checksum(pay)
        chksumLen = 4
### mrd        complementedChecksum = NCSI_HEADER.twos_complement(checksumVal, chksumLen * 4)
        complementedChecksum = checksumVal ### mrd

        chksum = struct.pack("!I", complementedChecksum)

        while False and len(pay) % 4 > 0:  # Add padding
            pay = pay + b"\x00"

        retPkt = (
            pkt + pay + chksum
        )  # finished is pkt (header) payload, with padding and the checksum

        return retPkt

    def do_dissect2(self, rawPkt):
        """need to override this to pull out the checksum because the SCAPY
        framework does not seem to be able to do it when you have a PacketField
        in the layer.  So I copied this code from SCAPY's Packet class and
        inserted some code to extract the checksum.
        """
        _raw = rawPkt

        ### Begining of custom code ###
        if len(rawPkt) > 4:
            chkSum = rawPkt[-4:]
            (chkSumVal,) = struct.unpack("!I", chkSum)
            self.fields["Checksum"] = chkSumVal
            # rawPkt = rawPkt[:-4]
        ### End of custom code ###

        self.raw_packet_cache_fields = {}
        for f in self.fields_desc:
            if not rawPkt:
                break
            rawPkt, fval = f.getfield(self, rawPkt)
            # We need to track fields with mutable values to discard
            # .raw_packet_cache when needed.
            if f.islist or f.holds_packets or f.ismutable:
                self.raw_packet_cache_fields[f.name] = f.do_copy(fval)
            self.fields[f.name] = fval
        self.raw_packet_cache = _raw[: -len(rawPkt)] if rawPkt else _raw
        self.explicit = 1
        return rawPkt

    def extract_padding(self, s):
        return s[:-4], s[-4:]  # last 4 bytes are Checksum


class NcsiPldm_Response(NCSI_PLDM_PAYLOAD):
    """The NC-IS PLDM payload Response class,
    all of the work is done in the parent class,
    this one is for registration with NC-SI header
    """

    name = "PLDM Response {NC-SI}"
    CommandValue = 0xD1
    fields_desc = [
        XShortField("ResponseCode", 0x00),
        XShortField("ReasonCode", 0x12)
    ]


class QueryPendingNcPldm_Request(NCSI_PLDM_PAYLOAD):  # This is NOT PLDM
    """Query Pending NC PLDM Request"""

    name = "Query Pending NC PLDM Request"
    CommandValue = 0x56


class QueryPendingNcPldm_Response(NCSI_PLDM_PAYLOAD):
    """Query Pending NC PLDM Response"""

    name = "Query Pending NC PLDM Response"
    CommandValue = QueryPendingNcPldm_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES)
    ]


class SendNcPldmReply_Request(NCSI_PLDM_PAYLOAD):  # This is NOT PLDM
    """Send NC PLDM Reply"""

    name = "Send NC PLDM Reply"
    CommandValue = 0x57


class SendNcPldmReply_Response(NCSI_PLDM_PAYLOAD):
    """Send NC PLDM Reply Response"""

    name = "Send NC PLDM Reply Response"
    CommandValue = SendNcPldmReply_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        X3BytesField("Reserved", 0x000000),
        BitField("ReservedBits", 0, 7),
        BitEnumField(
            "PendingRequest",
            0,
            1,
            {
                0: "No additional pending PLDM command from NC to MC.",
                1: "The NC has an additional pending PLDM command to the MC."
            }
        )
    ]


# Register the classes, and bind to NC-SI Header layer
register_pldm_over_ncsi(NcsiPldm_Request)
register_pldm_over_ncsi(NcsiPldm_Response)
register_pldm_over_ncsi(QueryPendingNcPldm_Request)
register_pldm_over_ncsi(QueryPendingNcPldm_Response)

bind_layers(NCSI_PLDM_PAYLOAD, PLDM_HEADER)
bind_layers(NcsiPldm_Request, PLDM_HEADER)
