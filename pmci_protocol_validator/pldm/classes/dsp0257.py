# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Contains the PLDM Type 4 (PLDM for FRU) wrappers from DSP 0257
##############################################################################

from scapy.fields import *
from scapy.all import bind_layers, Packet

from pmci_protocol_validator.pldm.classes.dsp0240_base import (
    PLDM_BASE_CODES,
    PLDM_HEADER,
    PLDM_PAYLOAD
)

DSP0257_COMPLIANCE_VERSION = int.from_bytes([1, 0, 0, 0], 'big')

# [DSP0257] Table 4 – FRU Record Type Definitions
RECORD_TYPE_GENERAL_FRU_RECORD = 1
RECORD_TYPE_OEM_FRU_RECORD = 254

# [DSP0257] Table 5 – General FRU Record Field Type Definitions
GENERAL_FIELD_TYPE_RESERVED = 0
GENERAL_FIELD_TYPE_CHASSIS_TYPE = 1
GENERAL_FIELD_TYPE_MODEL = 2
GENERAL_FIELD_TYPE_PART_NUMBER = 3
GENERAL_FIELD_TYPE_SERIAL_NUMBER = 4
GENERAL_FIELD_TYPE_MANUFACTURER = 5
GENERAL_FIELD_TYPE_MANUFACTURE_DATE = 6
GENERAL_FIELD_TYPE_VENDOR = 7
GENERAL_FIELD_TYPE_NAME = 8
GENERAL_FIELD_TYPE_SKU = 9
GENERAL_FIELD_TYPE_VERSION = 10
GENERAL_FIELD_TYPE_ASSET_TAG = 11
GENERAL_FIELD_TYPE_DESCRIPTION = 12
GENERAL_FIELD_TYPE_ENGINEERING_CHANGE_LEVEL = 13
GENERAL_FIELD_TYPE_OTHER_INFORMATION = 14
GENERAL_FIELD_TYPE_VENDOR_IANA = 15

# [DSP0257] Table 6 – OEM FRU Record Field Type Definitions
OEM_FRU_RECORD_VENDOR_IANA = 1


class FRU_Field(Packet):
    """ FRU Field format """
    fields_desc = [
        ByteField("Type", 0),
        ByteField("Length", 0),
        FieldListField(
            "Value",
            [],
            XByteField("", 0x00000000),
            length_from=lambda pkt: pkt.Length,
        )
    ]


class FRU_Record(Packet):
    """ [DSP0257] Table 2 - PLDM FRU Record Data Format """

    fields_desc = [
        ShortField("FRURecordSetIdentifier", 0),
        ByteField("FRURecordType", 0),
        ByteField("NumberOfFRUfields", 0),
        ByteEnumField(
            "EncodingTypeForFRUFields",
            0,
            {
                0: "Unspecified",
                1: "ASCII",
                2: "UTF8",
                3: "UTF16",
                4: "UTF16-LE",
                5: "UTF16-BE",
            }
        ),
        FieldListField(
            "Fields",
            [],
            FRU_Field(),
            count_from=lambda pkt: pkt.NumberOfFRUfields,
        )
    ]


class PLDM_TYPE_4_PAYLOAD(PLDM_PAYLOAD):
    """ Base class for all PLDM Type 4 message payloads """

    name = "PLDM for FRU Payload"
    PldmPayloadType = 0x04


class GetFRUTableMetadata_Request(PLDM_TYPE_4_PAYLOAD):
    """ [DSP0257] Table 9 - GetFRUTableMetadata Request """

    name = "GetFRUTableMetadata Request"
    CommandValue = 0x01


class GetFRUTableMetadata_Response(PLDM_TYPE_4_PAYLOAD):
    """ [DSP0257] Table 9 - GetFRUTableMetadata Response """

    name = "GetFRUTableMetadata Response"
    CommandValue = GetFRUTableMetadata_Request.CommandValue

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0,
            {
                **PLDM_BASE_CODES,
                0x83: "NO_FRU_DATA_STRUCTURE_TABLE_METADATA"
            }
        ),
        ConditionalField(
            ByteField("FRUDATAMajorVersion", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteField("FRUDATAMinorVersion", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            IntField("FRUTableMaximumSize", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            IntField("FRUTableLength", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ShortField("TotalNumberRecordSetIdentifiers", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ShortField("TotalNumberRecords", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XIntField("FRUTableIntegrityChecksum", 0),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetFRURecordTable_Request(PLDM_TYPE_4_PAYLOAD):
    """ [DSP0257] GetFRURecordTable Request """

    name = "GetFRURecordTable Request"
    CommandValue = 0x02

    fields_desc = [
        IntField("DataTransferHandle", 0),
        ByteEnumField(
            "TransferOperationFlag",
            1,
            {
                0: "GetNextPart",
                1: "GetFirstPart"
            }
        )
    ]


class GetFRURecordTable_Response(PLDM_TYPE_4_PAYLOAD):
    """ [DSP0257] GetFRURecordTable Response """

    name = "GetFRURecordTable Response"
    CommandValue = GetFRURecordTable_Request.CommandValue

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_DATA_TRANSFER_HANDLE",
                0x81: "INVALID_TRANSFER_OPERATION_FLAG",
                0x85: "FRU_DATA_STRUCTURE_TABLE_UNAVAILABLE"
            }
        ),
        ConditionalField(
            IntField("NextDataTransferHandle", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteEnumField(
                "TransferFlag",
                5,
                {
                    1: "Start",
                    2: "Middle",
                    4: "End",
                    5: "StartAndEnd",
                }
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField(
                "FRURecordData",
                [],
                XByteField("", 0x00),
                length_from=lambda pkt: pkt.SecurityParameterLength
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SetFRURecordTable_Request(PLDM_TYPE_4_PAYLOAD):
    """ [DSP0257] SetFRURecordTable Request """

    name = "SetFRURecordTable Request"
    CommandValue = 0x03

    fields_desc = [
        XIntField("DataTransferHandle", 0),
        ByteEnumField(
            "TransferFlag",
            5,
            {
                1: "Start",
                2: "Middle",
                4: "End",
                5: "StartAndEnd",
            }
        ),
        FieldListField(
            "FRURecordData",
            [],
            XByteField("", 0x00)
        )
    ]


class SetFRURecordTable_Response(PLDM_TYPE_4_PAYLOAD):
    """ [DSP0257] SetFRURecordTable Response """

    name = "SetFRURecordTable Response"
    CommandValue = SetFRURecordTable_Request.CommandValue

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_DATA_TRANSFER_HANDLE",
                0x82: "INVALID_TRANSFER_FLAG",
                0x84: "INVALID_DATA_INTEGRITY_CHECK"
            }
        ),
        ConditionalField(
            XIntField("NextDataTransferHandle", 0),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetFRURecordByOption_Request(PLDM_TYPE_4_PAYLOAD):
    """ [DSP0257] GetFRURecordByOption Request """

    name = "GetFRURecordByOption Request"
    CommandValue = 0x04

    fields_desc = [
        XIntField("DataTransferHandle", 0),
        XShortField("FRUTableHandle", 0),
        ShortField("RecordSetIdentifier", 0),
        ByteField("RecordType", 0),
        ByteField("FieldType", 0),
        ByteEnumField(
            "TransferOperationFlag",
            1,
            {
                0: "GetNextPart",
                1: "GetFirstPart"
            }
        )
    ]


class GetFRURecordByOption_Response(PLDM_TYPE_4_PAYLOAD):
    """ [DSP0257] GetFRURecordByOption Response """

    name = "GetFRURecordByOption Response"
    CommandValue = GetFRURecordByOption_Request.CommandValue

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_DATA_TRANSFER_HANDLE",
                0x82: "INVALID_TRANSFER_FLAG",
                0x84: "INVALID_DATA_INTEGRITY_CHECK"
            }
        ),
        ConditionalField(
            XIntField("NextDataTransferHandle", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteEnumField(
                "TransferFlag",
                5,
                {
                    1: "Start",
                    2: "Middle",
                    4: "End",
                    5: "StartAndEnd",
                }
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField(
                "FRURecordData",
                [],
                XByteField("", 0x00)
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


### Register for dissection ####
bind_layers(PLDM_HEADER, PLDM_TYPE_4_PAYLOAD, PldmType=0x04)
