# Copyright Notice:
# Copyright 2024-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
PLDM Type 7 (PLDM for File Transfer) Scapy classes

File : dsp0242.py

Brief : PLDM Type 7 (PLDM for File Transfer) Scapy classes from DSP0242
"""

from scapy.fields import *
from scapy.all import bind_layers, Packet

from pmci_protocol_validator.pldm.classes.dsp0240_base import (
    PLDM_HEADER,
    PLDM_PAYLOAD,
    register_pldm_class,
    PLDM_BASE_CODES
)

DSP0242_COMPLIANCE_VERSION = int.from_bytes([1, 0, 0, 0], 'big')

""" DSP0242 - PLDM File Transfer Completion Codes """
DSP0242_RESPONSE_CODE_VALUES = {
    0x80: "INVALID_FILE_DESCRIPTOR",
    0x81: "INVALID_DF_ATTRIBUTE",
    0x82: "ZEROLENGTH_NOT_ALLOWED",
    0x83: "EXCLUSIVE_OWNERSHIP_NOT_ESTABLISHED",
    0x84: "EXCLUSIVE_OWNERSHIP_NOT_ALLOWED",
    0x85: "EXCLUSIVE_OWNERSHIP_NOT_AVAILABLE",
    0x86: "INVALID_FILE_IDENTIFIER",
    0x87: "DFOPEN_DIR_NOT_ALLOWED",
    0x88: "MAX_NUM_FDS_EXCEEDED",
    0x89: "FILE_OPEN",
    0x8A: "UNABLE_TO_OPEN_FILE"
}


class PLDM_TYPE_7_PAYLOAD(PLDM_PAYLOAD):
    """ Base class for all PLDM Type 7 Message Payloads """

    name = "PLDM for File Transfer"
    PldmPayloadType = 0x07


class DfOpen_Request(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfOpen Request """

    name = "DfOpen Request"
    CommandValue = 0x01

    fields_desc = [
        XShortField("FileIdentifier", 0x0000),
        BitEnumField("DfOpenReadWrite", 0, 1, {0: "Read", 1: "Write"}),
        BitEnumField("DfOpenExclusive", 0, 1, {0: "Non-exclusive", 1: "Exclusive"}),
        BitEnumField("DfOpenRegFIFO", 0, 1, {0: "Regular", 1: "Streaming FIFO (Serial FIFO)"}),
        BitEnumField("DfOpenPolledPushed", 0, 1, {0: "Polled", 1: "Pushed,"}),
        BitField("Reserved", 0, 12)
    ]


class DfOpen_Response(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfOpen Response """

    name = "DfOpen Response"
    CommandValue = DfOpen_Request.CommandValue

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, {**PLDM_BASE_CODES, **DSP0242_RESPONSE_CODE_VALUES}),
        ConditionalField(
            XShortField("FileDescriptor", 0),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class DfClose_Request(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfClose Request """

    name = "DfClose Request"
    CommandValue = 0x02

    fields_desc = [
        XShortField("FileDescriptor", 0),
        BitEnumField("ZeroLength", 0, 1, {0: "No request", 1: "Request the File Host set the File Length to zero (0)"}),
        BitField("Reserved", 0, 15)
    ]


class DfClose_Response(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfClose Response """

    name = "DfClose Response"
    CommandValue = DfClose_Request.CommandValue

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, {**PLDM_BASE_CODES, **DSP0242_RESPONSE_CODE_VALUES}),
    ]


class DfHeartbeat_Request(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfHeartbeat Request """

    name = "DfHeartbeat Request"
    CommandValue = 0x03

    fields_desc = [
        XShortField("FileDescriptor", 0),
        IntField("RequestorMaxInterval", 0)
    ]


class DfHeartbeat_Response(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfHeartbeat Response """

    name = "DfHeartbeat Response"
    CommandValue = DfHeartbeat_Request.CommandValue

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            IntField("ResponderMaxInterval", 0),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class DfProperties_Request(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfProperties Request """

    name = "DfProperties Request"
    CommandValue = 0x10

    fields_desc = [
        XShortField("FileDescriptor", 0),
        BitEnumField("MaxConcurrentMedium", 0, 1, {0: "DfPropertyAttribute not requested", 1: "Request the specified DfPropertyAttribute"}),
        BitEnumField("MaxFileDescriptors", 0, 1, {0: "DfPropertyAttribute not requested", 1: "Request the specified DfPropertyAttribute"}),
        BitField("Reserved", 0, 30)
    ]


class DfProperties_Response(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfProperties Response """

    name = "DfProperties Response"
    CommandValue = DfProperties_Request.CommandValue

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, {**PLDM_BASE_CODES, **DSP0242_RESPONSE_CODE_VALUES}),
        ConditionalField(
            IntField("FileAttributeValue", 0),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class DfGetFileAttribute_Request(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfGetFileAttribute Request """

    name = "DfGetFileAttribute Request"
    CommandValue = 0x11

    fields_desc = [
        XShortField("FileIdentifier", 0x0000),
        BitEnumField("ClientDeleteOnly", 0, 1, {0: "Attribute status not requested", 1: "Request the specified current attribute status"}),
        BitField("Reserved_1_15", 0, 15),
        BitEnumField("RequestCI", 0, 1, {0: "Attribute status not requested", 1: "Request the specified current attribute status"}),
        BitEnumField("ReqMaxPoll", 0, 1, {0: "Attribute status not requested", 1: "Request the specified current attribute status"}),
        BitField("Reserved_18_31", 0, 14)
    ]


class DfGetFileAttribute_Response(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfGetFileAttribute Response """

    name = "DfGetFileAttrib Response"
    CommandValue = DfGetFileAttribute_Request.CommandValue

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, {**PLDM_BASE_CODES, **DSP0242_RESPONSE_CODE_VALUES}),
        ConditionalField(
            IntField("FileAttributeValue", 0),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class DfSetFileAttribute_Request(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfSetFileAttribute Request """

    name = "DfSetFileAttribute Request"
    CommandValue = 0x12

    fields_desc = [
        XShortField("FileIdentifier", 0x0000),
        BitEnumField("ClientZeroLengthOnly", 0, 1, {0: "setting of attribute not requested", 1: "Request setting specified attribute"}),
        BitField("Reserved_1_15", 0, 15),
        IntField("FileAttributeValue", 0),
    ]


class DfSetFileAttribute_Response(PLDM_TYPE_7_PAYLOAD):
    """ DSP0242 DfSetFileAttribute Response """

    name = "DfSetFileAttrib Response"
    CommandValue = DfSetFileAttribute_Request.CommandValue

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, {**PLDM_BASE_CODES, **DSP0242_RESPONSE_CODE_VALUES}),
    ]
