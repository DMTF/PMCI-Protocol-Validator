# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Contains the PLDM Type 6 (PLDM for Redfish) wrappers from DSP0218
##############################################################################

from scapy.fields import *  # pylint: disable=unused-import, unused-wildcard-import
from scapy.packet import Packet


BEJFormatCodes = {
    0: "BEJ Set",
    1: "BEJ Array",
    2: "BEJ Null",
    3: "BEJ Integer",
    4: "BEJ Enum",
    5: "BEJ String",
    6: "BEJ Real",
    7: "BEJ Boolean",
    8: "BEJ Bytestring",
    9: "BEJ Choice",
    10: "BEJ Property Annotation",
    11: "BEJ Registry Item",
    0xE: "BEJ Resource Link",
    0xF: "BEJ Resource Link Expansion",
}

FLAG_SET = {0: "False", 1: "True"}


# Tuple elements for Sequence Number field
bejTupleS = [
    ByteField("BytesOfSeq", 1),
    MultipleTypeField(
        [  # SequenceId with flag on bit 0
            (ByteField("SequenceNumber", 0x00), lambda pkt: pkt.BytesOfSeq in [1]),
            (LEShortField("SequenceNumber", 0x0000), lambda pkt: pkt.BytesOfSeq in [2]),
            (NBytesField("SequenceNumber", 0, 3), lambda pkt: pkt.BytesOfSeq in [3]),
            (
                LEIntField("SequenceNumber", 0x00000000),
                lambda pkt: pkt.BytesOfSeq in [4],
            ),
        ],
        ByteField("SequenceNumber", 0x00),  # Default field
    )
]


# Tuple element for Format field
bejTupleF = [
    BitEnumField("PrincipleDataType", 0, 4, BEJFormatCodes),
    BitEnumField("reserved_flag", 0, 1, FLAG_SET),
    BitEnumField("nullable_property", 0, 1, FLAG_SET),
    BitEnumField("read_only", 0, 1, FLAG_SET),
    BitEnumField("deferred_binding", 0, 1, FLAG_SET),
]


bejTupleL = [
    ByteField("BytesOfLength", 1),
    MultipleTypeField(
        [
            (ByteField("Length", 0x00), lambda pkt: pkt.BytesOfLength in [1]),
            (LEShortField("Length", 0x0000), lambda pkt: pkt.BytesOfLength in [2]),
            (NBytesField("Length", 0, 3), lambda pkt: pkt.BytesOfLength in [3]),
            (LEIntField("Length", 0x00000000), lambda pkt: pkt.BytesOfLength in [4]),
        ],
        ByteField("Length", 0x00),  # Default field
    )
]


bejTupleV = [
    MultipleTypeField(
        [
            (ByteField("Value", 0x00), lambda pkt: pkt.Length in [1]),
            (LEShortField("Value", 0x0000), lambda pkt: pkt.Length in [2]),
            (NBytesField("Value", 0, 3), lambda pkt: pkt.Length in [3]),
            (LEIntField("Value", 0x00000000), lambda pkt: pkt.Length in [4]),
        ],
        ByteField("Value", 0x00),   # Default field
    )
]


class BejNULL(Packet):
    name = "BejNULL "
    fields_desc = [
        *bejTupleL,
    ]

    # This object has no padding, but may have something following it
    # like an array of objects so override the behavior.
    def extract_padding(self, s):
        return ("", s)


class BejInteger(Packet):
    fields_desc = [
        *bejTupleL,
        *bejTupleV,
    ]

    def extract_padding(self, s):
        return ("", s)


class BejEnum(Packet):
    fields_desc = [
        *bejTupleL,
        ByteField("BytesOfValue", 0x00),
        MultipleTypeField(
            [
                (ByteField("Value", 0x00), lambda pkt: pkt.BytesOfValue in [1]),
                (LEShortField("Value", 0x0000), lambda pkt: pkt.BytesOfValue in [2]),
                (NBytesField("Value", 0, 3), lambda pkt: pkt.BytesOfValue in [3]),
                (LEIntField("Value", 0x00000000), lambda pkt: pkt.BytesOfValue in [4]),
            ],
            ByteField("Value", 0x00),  # Default field
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class BejString(Packet):
    fields_desc = [
        *bejTupleL,
        StrLenField("Value", "", length_from=lambda pkt: pkt.Length),
    ]

    def extract_padding(self, s):
        return ("", s)


class BejResourceLink(Packet):
    fields_desc = [
        *bejTupleL,
        ByteField("BytesOfValue", 0x00),
        MultipleTypeField(
            [
                (ByteField("Value", 0x00), lambda pkt: pkt.BytesOfValue in [1]),
                (LEShortField("Value", 0x0000), lambda pkt: pkt.BytesOfValue in [2]),
                (NBytesField("Value", 0, 3), lambda pkt: pkt.BytesOfValue in [3]),
                (LEIntField("Value", 0x00000000), lambda pkt: pkt.BytesOfValue in [4]),
            ],
            ByteField("Value", 0x00),  # Default field
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class BejTuple(Packet):
    def extract_padding(self, s):
        return ("", s)


class BejSetTuple(Packet):
    def extract_padding(self, s):
        return ("", s)


BejSetTuple.fields_desc = [
    *bejTupleL,
    ByteField("CountOfBytes", 1),
    MultipleTypeField(
        [
            (ByteField("Count", 0x00), lambda pkt: pkt.CountOfBytes in [1]),
            (LEShortField("Count", 0x0000), lambda pkt: pkt.CountOfBytes in [2]),
            (NBytesField("Count", 0, 3), lambda pkt: pkt.CountOfBytes in [3]),
            (LEIntField("Count", 0x00000000), lambda pkt: pkt.CountOfBytes in [4]),
        ],
        ByteField("Count", 0x00),  # Default field
    ),
    PacketListField("BejTuple", None, BejTuple, count_from=lambda pkt: pkt.Count),
]


BejTuple.fields_desc = [
    # Tuple elements for Sequence Number field
    *bejTupleS,
    # Tuple element for Format field
    *bejTupleF,
    ConditionalField(
        PacketField("BejSetTuple", BejSetTuple(), BejSetTuple),
        lambda pkt: pkt.PrincipleDataType == 0,
    ),
    # BejArray is similar to BejSetTuple so use BejSetTuple as Bej Array
    ConditionalField(
        PacketField("BejArray", BejSetTuple(), BejSetTuple),
        lambda pkt: pkt.PrincipleDataType == 1,
    ),
    ConditionalField(
        PacketField("BejNULL", BejNULL(), BejNULL),
        lambda pkt: pkt.PrincipleDataType == 2,
    ),
    ConditionalField(
        PacketField("BejInteger", BejInteger(), BejInteger),
        lambda pkt: pkt.PrincipleDataType == 3,
    ),
    ConditionalField(
        PacketField("BejEnum", BejEnum(), BejEnum),
        lambda pkt: pkt.PrincipleDataType == 4,
    ),
    ConditionalField(
        PacketField("BejString", BejString(), BejString),
        lambda pkt: pkt.PrincipleDataType == 5,
    ),
    ConditionalField(
        PacketField("BejResourceLink", BejResourceLink(), BejResourceLink),
        lambda pkt: pkt.PrincipleDataType == 14,
    )
]
