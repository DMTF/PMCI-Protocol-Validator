# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Contains the PLDM Type 0 (PLDM Messaging Control and Discovery) wrappers
##############################################################################

import struct

from scapy.fields import *
from scapy.packet import Packet
from scapy.all import checksum, bind_layers

from pmci_protocol_validator.pldm.classes.dsp0240_base import (
    PLDM_HEADER,
    PLDM_PAYLOAD,
    PLDM_BASE_CODES,
    register_pldm_class,
    TransferFlags,
)

DSP0240_COMPLIANCE_VERSION = int.from_bytes([1, 1, 0, 0], 'big')


class PLDM_TYPE_0_PAYLOAD(PLDM_PAYLOAD):
    name = "PLDM Payload"
    PldmPayloadType = 0x00

    def extract_padding(self, s):
        return ("", s)


class SetTID_Request(PLDM_TYPE_0_PAYLOAD):
    name = "Set TID Request"
    CommandValue = 0x01

    fields_desc = [
        XByteField("TID", 0x01)
    ]


class SetTID_Response(PLDM_TYPE_0_PAYLOAD):
    name = "Set TID Response"
    CommandValue = 0x01

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES)
    ]


class GetTID_Request(PLDM_TYPE_0_PAYLOAD):
    name = "Get TID Request"
    CommandValue = 0x02


class GetTID_Response(PLDM_TYPE_0_PAYLOAD):
    name = "Get TID Response"
    CommandValue = 0x02

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            ByteField("TID", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetPldmVersion_Request(PLDM_TYPE_0_PAYLOAD):
    name = "Get PLDM Version Request"
    CommandValue = 0x03

    fields_desc = [
        XLEIntField("DataTransferHandle", 0x00000000),
        ByteEnumField(
            "TransferOperationFlag",
            0x01,
            {
                0x00: "GetNextPart",
                0x01: "GetFirstPart",
            },
        ),
        XByteField("PldmType", 0x00)
    ]


class GetPldmVersion_Response(PLDM_TYPE_0_PAYLOAD):
    name = "Get PLDM Version Response"
    CommandValue = 0x03

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_DATA_TRANSFER_HANDLE",
                0x81: "INVALID_TRANSFER_OPERATION_FLAG",
                0x83: "INVALID_PLDM_TYPE_IN_REQUEST_DATA",
            },
        ),
        ConditionalField(
            XLEIntField("NextDataTransferHandle", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteEnumField("TransferFlag", 0x01, TransferFlags),
             lambda pkt: pkt.CompletionCode == 0
        ),
        # there will be a number of 32 bit version fields, the number can be
        # calculated by subtracting from the total length, the fields before
        # this, the checksum and then divide by 4.
        ConditionalField(
            FieldListField(
                "Version",
                None,
                XLEIntField("", 0x00000000),
                count_from=lambda pkt: pkt.NumVersions,
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("PLDMVersionDataIntegrityChecksum", None),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]

    __slots__ = ["NumVersions"]

    def __init__(self, _pkt=b"", *args, **kwargs):
        self.NumVersions = 0
        Packet.__init__(self, _pkt, *args, **kwargs)

    def addChecksum(self, pkt):
        """
        Append checksum to end of packet
        """
        chkSumVal = checksum(pkt[:-4])
        chksum = struct.pack("!i", chkSumVal)
        return pkt[:-4] + chksum

    def do_build(self):
        """
        Overridden to know how many version fields
        there are, and stored in instance variable
        """
        self.NumVersions = len(self.Version)
        pkt = super().do_build()
        pkt = self.addChecksum(pkt)
        return pkt

    def pre_dissect(self, s):
        """ Need to calculate the # of versions in the payload """
        self.NumVersions = (len(s) - 10) / 4
        return super().pre_dissect(s)

    def extract_padding(self, s):  # all payloads need to do this
        return "", s


class GetPldmTypes_Request(PLDM_TYPE_0_PAYLOAD):
    name = "Get PLDM Types Request"
    CommandValue = 0x04


class GetPldmTypes_Response(PLDM_TYPE_0_PAYLOAD):
    name = "Get PLDM Types Response"
    CommandValue = 0x04

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),

        ConditionalField(
            BitEnumField("Type7", 0, 1, {0: "Not supported", 1: "Supported"}),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField("Type6", 0, 1, {0: "Not supported", 1: "Supported"}),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField("Type5", 0, 1, {0: "Not supported", 1: "Supported"}),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField("Type4", 0, 1, {0: "Not supported", 1: "Supported"}),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField("Type3", 0, 1, {0: "Not supported", 1: "Supported"}),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField("Type2", 0, 1, {0: "Not supported", 1: "Supported"}),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField("Type1", 0, 1, {0: "Not supported", 1: "Supported"}),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField("Type0", 0, 1, {0: "Not supported", 1: "Supported"}),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetPldmCommands_Request(PLDM_TYPE_0_PAYLOAD):
    name = "Get PLDM Commands Request"
    CommandValue = 0x05

    fields_desc = [
        XByteEnumField(
            "PldmType",
            0x0,
            {
                0x0: "PLDM Messaging Control and Discovery",
                0x1: "PLDM for SMBIOS",
                0x2: "PLDM for Platform Monitoring and Control",
                0x3: "PLDM for BIOS Control and Configuration",
                0x4: "PLDM for FRU Data",
                0x5: "PLDM for Firmware Update",
                0x6: "PLDM for Redfish Device Enablement",
                0x3F: "OEM Specific"
                # 0x7 - 0x3E - Reserved
            },
        ),
        XLEIntField("Version", 0x00000000),
    ]


class GetPldmCommands_Response(PLDM_TYPE_0_PAYLOAD):
    name = "Get PLDM Commands Response"
    CommandValue = 0x05

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x83: "INVALID_PLDM_TYPE_IN_REQUEST_DATA",
                0x84: "INVALID_PLDM_VERSION_IN_REQUEST_DATA",
            },
        )
    ]

    # 256 bitfields for 256 commands in 32 bytes
    for cmd in range(0, 32):
        for i in range(7, -1, -1):
            fields_desc.append(BitField("Command_{}".format(i + cmd * 8), 0, 1))


# Added new PLDM0 commands from DSP0240 ver. 1.1.0

class SelectPLDMVersion_Request(PLDM_TYPE_0_PAYLOAD):
    name = "Select PLDM Version Request"
    CommandValue = 0x06

    fields_desc = [
        XByteEnumField(
            "PldmType",
            0x1,
            {  # This command is NOT used to select PLDM Type 0 version.
                0x0: "PLDM Messaging Control and Discovery",
                0x1: "PLDM for SMBIOS",
                0x2: "PLDM for Platform Monitoring and Control",
                0x3: "PLDM for BIOS Control and Configuration",
                0x4: "PLDM for FRU Data",
                0x5: "PLDM for Firmware Update",
                0x6: "PLDM for Redfish Device Enablement",
                0x3F: "OEM Specific"
                # 0x7 - 0x3E - Reserved
            },
        ),
        XLEIntField("Version", 0x00000000)
    ]


class SelectPLDMVersion_Response(PLDM_TYPE_0_PAYLOAD):
    name = "Select PLDM Version Response"
    CommandValue = 0x06

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x83: "INVALID_PLDM_TYPE_IN_REQUEST_DATA",
                0x84: "INVALID_PLDM_VERSION_IN_REQUEST_DATA",
            },
        )
    ]


class NegotiateTransferParameters_Request(PLDM_TYPE_0_PAYLOAD):
    name = "Negotiate Transfer Parameters Request"
    CommandValue = 0x07

    fields_desc = [
        XLEShortField("RequestorPartSize", 0x0000),
        BitEnumField(
            "RequestorProtocolType7_Supported",
            0,
            1,
            {0: "Not supported", 1: "Supported"},
        ),
        BitEnumField(
            "RequestorProtocolType6_Supported",
            0,
            1,
            {0: "Not supported", 1: "Supported"},
        ),
        BitEnumField(
            "RequestorProtocolType5_Supported",
            0,
            1,
            {0: "Not supported", 1: "Supported"},
        ),
        BitEnumField(
            "RequestorProtocolType4_Supported",
            0,
            1,
            {0: "Not supported", 1: "Supported"},
        ),
        BitEnumField(
            "RequestorProtocolType3_Supported",
            0,
            1,
            {0: "Not supported", 1: "Supported"},
        ),
        BitEnumField(
            "RequestorProtocolType2_Supported",
            0,
            1,
            {0: "Not supported", 1: "Supported"},
        ),
        BitEnumField(
            "RequestorProtocolType1_Supported",
            0,
            1,
            {0: "Not supported", 1: "Supported"},
        ),
        BitEnumField(
            "RequestorProtocolType0_Supported",
            0,
            1,
            {0: "Not supported", 1: "Supported"},
        )
    ]


class NegotiateTransferParameters_Response(PLDM_TYPE_0_PAYLOAD):
    name = "Negotiate Transfer Parameters Response"
    CommandValue = 0x07

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            XLEShortField("ResponderPartSize", 0x0000),

            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField(
                "ResponderProtocolType7_Supported",
                0,
                1,
                {0: "Not supported", 1: "Supported"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField(
                "ResponderProtocolType6_Supported",
                0,
                1,
                {0: "Not supported", 1: "Supported"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField(
                "ResponderProtocolType5_Supported",
                0,
                1,
                {0: "Not supported", 1: "Supported"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField(
                "ResponderProtocolType4_Supported",
                0,
                1,
                {0: "Not supported", 1: "Supported"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField(
                "ResponderProtocolType3_Supported",
                0,
                1,
                {0: "Not supported", 1: "Supported"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField(
                "ResponderProtocolType2_Supported",
                0,
                1,
                {0: "Not supported", 1: "Supported"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField(
                "ResponderProtocolType1_Supported",
                0,
                1,
                {0: "Not supported", 1: "Supported"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitEnumField(
                "ResponderProtocolType0_Supported",
                0,
                1,
                {0: "Not supported", 1: "Supported"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class MultipartSend_Request(PLDM_TYPE_0_PAYLOAD):
    name = "Multipart Send Request"
    CommandValue = 0x08

    fields_desc = [
        XByteEnumField(
            "PldmType",
            0x0,
            {
                0x0: "PLDM Messaging Control and Discovery",
                0x1: "PLDM for SMBIOS",
                0x2: "PLDM for Platform Monitoring and Control",
                0x3: "PLDM for BIOS Control and Configuration",
                0x4: "PLDM for FRU Data",
                0x5: "PLDM for Firmware Update",
                0x6: "PLDM for Redfish Device Enablement",
                0x3F: "OEM Specific"
                # 0x7 - 0x3E - Reserved
            },
        ),
        ByteEnumField("TransferFlag", 0x01, TransferFlags),
        XLEIntField("TransferContext", 0x00000000),
        XLEIntField("DataTransferHandle", 0x00000000),
        XLEIntField("NextDataTransferHandle", 0x00000000),
        XLEIntField("SectionOffset", 0x00000000),
        XLEIntField("SectionLengthBytes", 0x00000000),
        XLEIntField("DataLengthBytes", 0x00000000),
        FieldListField(
            "Data",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.DataLengthBytes
        ),
        XLEIntField("DataIntegrityChecksum", 0x00000000),
    ]


class MultipartSend_Response(PLDM_TYPE_0_PAYLOAD):
    name = "Multipart Send Response"
    CommandValue = 0x08

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {**PLDM_BASE_CODES, 0x83: "INVALID_PLDM_TYPE_IN_REQUEST_DATA"},
        ),
        ConditionalField(
            XByteEnumField(
                "NextTransferOperation",
                0x00,
                {
                    0x00: "XFER_FIRST_PART",
                    0x01: "XFER_NEXT_PART",
                    0x02: "XFER_ABORT",
                    0x04: "XFER_COMPLETE",
                    0x05: "XFER_CURRENT_PART",
                },
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class MultipartReceive_Request(PLDM_TYPE_0_PAYLOAD):
    name = "Multipart Receive Request"
    CommandValue = 0x09

    fields_desc = [
        XByteEnumField(
            "PldmType",
            0x0,
            {
                0x0: "PLDM Messaging Control and Discovery",
                0x1: "PLDM for SMBIOS",
                0x2: "PLDM for Platform Monitoring and Control",
                0x3: "PLDM for BIOS Control and Configuration",
                0x4: "PLDM for FRU Data",
                0x5: "PLDM for Firmware Update",
                0x6: "PLDM for Redfish Device Enablement",
                0x3F: "OEM Specific"
                # 0x7 - 0x3E - Reserved
            },
        ),
        XByteEnumField(
            "TransferOperation",
            0x00,
            {
                0x00: "XFER_FIRST_PART",
                0x01: "XFER_NEXT_PART",
                0x02: "XFER_ABORT",
                0x04: "XFER_COMPLETE",
                0x05: "XFER_CURRENT_PART",
            },
        ),
        XLEIntField("TransferContext", 0x00000000),
        XLEIntField("DataTransferHandle", 0x00000000),
        XLEIntField("RequestedSectionOffset", 0x00000000),
        XLEIntField("RequestedSectionLengthBytes", 0x00000000),
    ]


class MultipartReceive_Response(PLDM_TYPE_0_PAYLOAD):
    name = "Multipart Receive Response"
    CommandValue = 0x09

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {**PLDM_BASE_CODES, 0x83: "INVALID_PLDM_TYPE_IN_REQUEST_DATA"},
        ),
        ConditionalField(
            ByteEnumField("TransferFlag", 0x01, TransferFlags),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("NextDataTransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("DataLengthBytes", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField(
                "Data",
                [],
                XByteField("", 0x00),
                count_from=lambda pkt: pkt.DataLengthBytes
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(

            XLEIntField("DataIntegrityChecksum", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


### Register for dissection ###
bind_layers(PLDM_HEADER, PLDM_TYPE_0_PAYLOAD, PldmType=0x00)


### Determine Commands/Packets based on Payload Type, Rq/Rs & Command Type ###
register_pldm_class(SetTID_Request)
register_pldm_class(SetTID_Response)
register_pldm_class(GetTID_Request)
register_pldm_class(GetTID_Response)
register_pldm_class(GetPldmVersion_Request)
register_pldm_class(GetPldmVersion_Response)
register_pldm_class(GetPldmTypes_Request)
register_pldm_class(GetPldmTypes_Response)
register_pldm_class(GetPldmCommands_Request)
register_pldm_class(GetPldmCommands_Response)
register_pldm_class(SelectPLDMVersion_Request)
register_pldm_class(SelectPLDMVersion_Response)
register_pldm_class(NegotiateTransferParameters_Request)
register_pldm_class(NegotiateTransferParameters_Response)
register_pldm_class(MultipartSend_Request)
register_pldm_class(MultipartSend_Response)
register_pldm_class(MultipartReceive_Request)
register_pldm_class(MultipartReceive_Response)
