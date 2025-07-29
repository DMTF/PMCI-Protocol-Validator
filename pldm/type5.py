# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Contains the PLDM Type 5 (PLDM for Firmware Update) wrappers from DSP 0267
##############################################################################

from scapy.fields import *  # pylint: disable=unused-import, unused-wildcard-import
from scapy.all import bind_layers, Packet

from pldm.dmtf import (
    PLDM_HEADER,
    PLDM_PAYLOAD,
    PLDM_UUID,
    COMPONENT_CLASSIFICATION_VALUES,
    COMPONENT_IDENTIFIER_VALUES,
    APPLY_RESULT_VALUES,
    PLDM_BASE_CODES,
    TransferFlags,
    register_pldm_class,
    StringTypeValues,
    RecordDescriptorTypes,
    ComponentClassificationValues,
    ComponentResponseCodes,
    ComponentCompatibilityResponseCodes,
    TransferResults,
    VerifyResults,
    FDStates,
    AuxStates,
    AuxStatus,
    AuxReasonCodes
)

DSP0267_COMPLIANCE_VERSION = int.from_bytes([1, 1, 0, 0], 'big')


class PLDM_TYPE_5_PAYLOAD(PLDM_PAYLOAD):
    """base class for all PLDM Type 5 Message Payloads"""

    name = "PLDM for Firmware Update Payload"
    PldmPayloadType = 0x05


class RecordDescriptor(Packet):
    """Table 7 in DSP 0267"""

    name = "Descriptor"
    fields_desc = [
        LEShortEnumField("DescriptorType", 0x0000, RecordDescriptorTypes),
        MultipleTypeField(
            [
                (
                    LEShortField("DescriptorLength", 2),
                    lambda pkt: pkt.DescriptorType == 0x0000,
                ),
                (
                    LEShortField("DescriptorLength", 4),
                    lambda pkt: pkt.DescriptorType == 0x00001,
                ),
                (
                    LEShortField("DescriptorLength", 16),
                    lambda pkt: pkt.DescriptorType == 0x00002,
                ),
                (
                    LEShortField("DescriptorLength", 3),
                    lambda pkt: pkt.DescriptorType == 0x00003,
                ),
                (
                    LEShortField("DescriptorLength", 4),
                    lambda pkt: pkt.DescriptorType == 0x00004,
                ),
                (
                    LEShortField("DescriptorLength", 3),
                    lambda pkt: pkt.DescriptorType == 0x00005,
                ),
                (
                    LEShortField("DescriptorLength", 8),
                    lambda pkt: pkt.DescriptorType == 0x00006,
                ),
                (
                    LEShortField("DescriptorLength", 2),
                    lambda pkt: pkt.DescriptorType == 0x00100,
                ),
                (
                    LEShortField("DescriptorLength", 2),
                    lambda pkt: pkt.DescriptorType == 0x00101,
                ),
                (
                    LEShortField("DescriptorLength", 2),
                    lambda pkt: pkt.DescriptorType == 0x00102,
                ),
                (
                    LEShortField("DescriptorLength", 1),
                    lambda pkt: pkt.DescriptorType == 0x00103,
                ),
                (
                    LEShortField("DescriptorLength", 4),
                    lambda pkt: pkt.DescriptorType == 0x00104,
                ),
                (
                    LEShortField("DescriptorLength", 4),
                    lambda pkt: pkt.DescriptorType == 0x00105,
                ),
            ],
            LEShortField(
                "DescriptorLength", 2
            ),  # Default value, used 2 as it is the most common
        ),
        ConditionalField(
            XLEShortField(RecordDescriptorTypes[0x00], 0),
            lambda pkt: pkt.DescriptorType == 0x0000,
        ),
        ConditionalField(
            XLEIntField(RecordDescriptorTypes[0x01], 0),
            lambda pkt: pkt.DescriptorType == 0x0001,
        ),
        ConditionalField(
            PacketField(RecordDescriptorTypes[0x02], PLDM_UUID(), PLDM_UUID),
            lambda pkt: pkt.DescriptorType == 0x0002,
        ),
        ConditionalField(
            XLE3BytesField(RecordDescriptorTypes[0x03], 0),
            lambda pkt: pkt.DescriptorType == 0x0003,
        ),
        ConditionalField(
            XLEIntField(RecordDescriptorTypes[0x04], 0),
            lambda pkt: pkt.DescriptorType == 0x0004,
        ),
        ConditionalField(
            XLE3BytesField(RecordDescriptorTypes[0x05], 0),
            lambda pkt: pkt.DescriptorType == 0x0005,
        ),
        ConditionalField(
            XLELongField(RecordDescriptorTypes[0x06], 0),
            lambda pkt: pkt.DescriptorType == 0x0006,
        ),
        ConditionalField(
            XLEShortField(RecordDescriptorTypes[0x0100], 0),
            lambda pkt: pkt.DescriptorType == 0x0100,
        ),
        ConditionalField(
            XLEShortField(RecordDescriptorTypes[0x0101], 0),
            lambda pkt: pkt.DescriptorType == 0x0101,
        ),
        ConditionalField(
            XLEShortField(RecordDescriptorTypes[0x0102], 0),
            lambda pkt: pkt.DescriptorType == 0x0102,
        ),
        ConditionalField(
            XByteField(RecordDescriptorTypes[0x0103], 0),
            lambda pkt: pkt.DescriptorType == 0x0103,
        ),
        ConditionalField(
            XLEIntField(RecordDescriptorTypes[0x0104], 0),
            lambda pkt: pkt.DescriptorType == 0x0104,
        ),
        ConditionalField(
            XLEIntField(RecordDescriptorTypes[0x0105], 0),
            lambda pkt: pkt.DescriptorType == 0x0105,
        )
    ]

    def extract_padding(self, pld):  # all payloads need to do this
        return ("", pld,)


class ComponentParameterTableEntry(Packet):
    """Table 14 in DSP 0267"""

    name = "Component Parameter Table Entry"

    fields_desc = [
        LEShortEnumField(
            "ComponentClassification", 0x0000, ComponentClassificationValues
        ),
        LEShortField("ComponentIdentifier", 0x0000),
        ByteField("ComponentClassificationIndex", 0x00),
        XLEIntField("ActiveComponentComparisonStamp", 0x00000000),
        ByteEnumField("ActiveComponentVersionStringType", 0, StringTypeValues),
        FieldLenField(
            "ActiveComponentVersionStringLength",
            None,
            "ActiveComponentVersionString",
            "B",
        ),
        StrLenField(
            "ActiveComponentReleaseDate",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            length_from=lambda unused: 8,
        ),
        XLEIntField("PendingComponentComparisonStamp", 0x00000000),
        ByteEnumField("PendingComponentVersionStringType", 0, StringTypeValues),
        FieldLenField(
            "PendingComponentVersionStringLength",
            None,
            "PendingComponentVersionString",
            "B",
        ),
        StrLenField(
            "PendingComponentReleaseDate",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            length_from=lambda unused: 8,
        ),
        # Component Activation Methods
        # byte 0 bit 7
        BitField("ComponentActivationPendingComponentImageSet", 0, 1),
        BitField("ComponentActivationPendingImage", 0, 1),
        BitField("ComponentActivationAcPowerCycle", 0, 1),
        BitField("ComponentActivationDcPowerCycle", 0, 1),
        BitField("ComponentActivationSystemReboot", 0, 1),
        BitField("ComponentActivationMediumSpecificReset", 0, 1),
        BitField("ComponentActivationSelfContained", 0, 1),
        # byte 0 bit 0
        BitField("ComponentActivationAutomatic", 0, 1),
        # byte 1
        BitField("ComponentActivationMethodsReserved_0", 0, 8),
        # Capabilities During Update
        # byte 0 bits 7:3
        BitField("CapabilitiesDuringUpdateReserved_1", 0, 5),
        # byte 0 bit 2
        BitEnumField(
            "CapabilitiesDuringUpdateComponentDowngradeCapability",
            0,
            1,
            {
                0: "Component settings permit a downgrade to older versions",
                1: "Component settings do not allow for a downgrade to an older version component image",
            },
        ),
        # byte 0 bit 1
        BitField("CapabilitiesDuringUpdateReserved_0", 0, 1),
        # byte 0 bit 0
        BitEnumField(
            "CapabilitiesDuringUpdateFirmwareDeviceApplyState",
            0,
            1,
            {
                0: "Firmware Device will execute an operation during the APPLY state",
                1: "Firmware Device performs an 'auto-apply' during transfer phase"
                " and apply step will be completed immediately",
            },
        ),
        # bytes 3:1
        BitField("CapabilitiesDuringUpdateReserved_2", 0, 24),
        StrLenField(
            "ActiveComponentVersionString",
            b"",
            length_from=lambda pkt: pkt.ActiveComponentVersionStringLength,
        ),
        StrLenField(
            "PendingComponentVersionString",
            b"",
            length_from=lambda pkt: pkt.PendingComponentVersionStringLength,
        )
    ]

    def extract_padding(self, pld):  # all payloads need to do this
        return ("", pld,)

#### PLDM Type 5 Message Classes ####
class QueryDeviceIdentifiers_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Query Device Identifiers Request"
    CommandValue = 0x01


class QueryDeviceIdentifiers_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Query Device Identifiers Response"
    CommandValue = 0x01

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            FieldLenField(
                "DeviceIdentifiersLength", None, fmt="<I", length_of="Descriptors"
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldLenField(
                "DescriptorCount", None, fmt="B", count_of="Descriptors"
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            PacketListField(
                "Descriptors",
                None,
                RecordDescriptor,
                count_from=lambda pkt: pkt.DescriptorCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetFirmwareParameters_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Get Firmware Parameters Request"
    CommandValue = 0x2


class GetFirmwareParameters_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Get Firmware Parameters Response"
    CommandValue = 0x02

    class Data(Packet):
        fields_desc = [
            # Capabilities During Update
            # byte 0 bits 7:5
            XBitField("FirmwareDeviceUpdateModeRestrictionsReserved_0", 0, 3),
            # byte 0  bit 4
            BitEnumField(
                "FirmwareDeviceUpdateModeRestrictions",
                0,
                1,
                {
                    0: "No host OS restriction",
                    1: "Firmware Device unable to enter update mode if OS active",
                },
            ),
            # byte 0 bit 3
            BitEnumField(
                "FirmwareDevicePartialUpdates",
                0,
                1,
                {
                    0: "Firmware Device cannot accept a partial update",
                    1: "Firmware Device can support a partial update",
                },
            ),
            # byte 0 bit 2
            BitEnumField(
                "FirmwareDeviceHostFunctionalityDuringUpdate",
                0,
                1,
                {
                    0: "Device host functionality is not reduced during Firmware Update",
                    1: "Device host functionality will be reduced, perhaps becoming inaccessible, during Firmware Update",
                },
            ),
            # byte 0 bit 1
            BitEnumField(
                "ComponentUpdateFailureRetryCapability",
                0,
                1,
                {
                    0: "Device can have component updated again",
                    1: "Device will not be able to update component again",
                },
            ),
            # byte 0 bit 0
            BitEnumField(
                "ComponentUpdateFailureRecoveryCapability",
                0,
                1,
                {
                    0: "Device will revert to previous component image",
                    1: "Device will not revert to previous component image",
                },
            ),
            # byte 1 bit 7:1
            XBitField("GetFirmwareParametersReserved_0", 0, 7),
            # byte 1  bit 0
            BitEnumField(
                "FirmwareDeviceDowngradeRestrictions",
                0,
                1,
                {
                    0: "Firmware Device does not have downgrade restrictions",
                    1: "Firmware Device supports downgrade restrictions",
                },
            ),
            # bytes 3:2
            XBitField("GetFirmwareParametersReserved_1", 0, 16),
            FieldLenField(
                "ComponentCount", None, fmt="<H", count_of="ComponentParameterTable"
            ),
            ByteEnumField("ActiveComponentImageSetVersionStringType", 0, StringTypeValues),
            FieldLenField(
                "ActiveComponentImageSetVersionStringLength",
                None,
                length_of="ActiveComponentImageSetVersionString",
                fmt="B",
            ),
            ByteEnumField("PendingComponentImageSetVersionStringType", 0, StringTypeValues),
            FieldLenField(
                "PendingComponentImageSetVersionStringLength",
                None,
                length_of="PendingComponentImageSetVersionString",
                fmt="B",
            ),
            StrLenField(
                "ActiveComponentImageSetVersionString",
                "",
                length_from=lambda pkt: pkt.ActiveComponentImageSetVersionStringLength,
            ),
            StrLenField(
                "PendingComponentImageSetVersionString",
                "",
                length_from=lambda pkt: pkt.PendingComponentImageSetVersionStringLength,
            ),
            PacketListField(
                "ComponentParameterTable",
                [],
                ComponentParameterTableEntry,
                count_from=lambda pkt: pkt.ComponentCount,
            )
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            PacketField("Parameters", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class QueryDownstreamDevices_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Query Downstream Devices Request"
    CommandValue = 0x03


class QueryDownstreamDevices_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Query Downstream Devices Response"
    CommandValue = 0x03

    class Data(Packet):
        fields_desc = [
            ByteEnumField(
                "DownstreamDeviceUpdateSupported",
                0,
                {
                    0: "The FDP does not support firmware updates but may report inventory information on downstream devices",
                    1: "The FDP supports firmware updates for downstream devices",
                },
            ),
            LEShortField("NumberofDownstreamDevices", 0),
            LEShortField("MaxNumberofDownstreamDevices", 0),
            # byte 0 bits 7-3
            BitField("Reserved_0", 0, 5),
            # byte 0 bit 2
            BitEnumField(
                "FDPSupportsAbilityToUpdateMultipleDownstreamDevicesSimultaneously",
                0,
                1,
                {
                    0: "No support for simultaneous update",
                    1: "FDP supports simultaneous update of multiple downstream devices ",
                },
            ),
            # byte 0 bit 1
            BitEnumField(
                "FDPSupportsDownstreamDevicesDynamicallyRemoved",
                0,
                1,
                {
                    0: "No dynamically removed downstream devices",
                    1: "FDP supports dynamically removed downstream devices",
                },
            ),
            # byte 0 bit 0
            BitEnumField(
                "FDPSupportsDownstreamDevicesDynamicallyAttached",
                0,
                1,
                {
                    0: "No dynamically attached downstream devices",
                    1: "FDP supports dynamically attached downstream devices",
                },
            ),
            # bytes 3:1
            BitField("Reserved_1", 0, 24),
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            PacketField("Parameters", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class QueryDownstreamIdentifiers_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Query Downstream Identifiers Request"
    CommandValue = 0x04

    fields_desc = [
        XLEIntField("DataTransferHandle", 0x00000000),
        ByteEnumField(
            "TransferOperationFlag",
            0x0,
            {
                0x00: "GetNextPart",
                0x01: "GetFirstPart"
            }
        )
    ]


class DownstreamDevice(Packet):
    """DSP0267 -> Table 18"""

    name = "Downstream Device"
    fields_desc = [
        XLEShortField("DownstreamDeviceIndex", 0x0000),
        FieldLenField(
            "DownstreamDescriptorCount",
            None,
            fmt="B",
            count_of="DownstreamDescriptors"
        ),
        PacketListField(
            "DownstreamDescriptors",
            None,
            RecordDescriptor,
            count_from=lambda pkt: pkt.DownstreamDescriptorCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class QueryDownstreamIdentifiers_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Query Downstream Identifiers Response"
    CommandValue = 0x04

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x90: "INVALID_TRANSFER_HANDLE",
                0x91: "INVALID_TRANSFER_OPERATION_FLAG",
            },
        ),

        ConditionalField(
            XLEIntField("NextDataTransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteEnumField("TransferFlag", 0x01, TransferFlags),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            # portion of QueryDownstreamIdentifiers
            FieldLenField(
                "DownstreamDevicesLength",
                None, fmt="<I",
                length_of="DownstreamDevices"
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldLenField(
                "NumberOfDownstreamDevices",
                None, count_of="DownstreamDevices",
                fmt="<H"
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField(
                "DownstreamDevices",
                [],
                PacketField("", DownstreamDevice(), DownstreamDevice),
                count_from=lambda pkt: pkt.NumberOfDownstreamDevices,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetDownstreamFirmwareParameters_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Get Downstream Firmware Parameters Request"
    CommandValue = 0x05

    fields_desc = [
        MultipleTypeField(
            [
                (
                    XLEIntField("DataTransferHandle", None),
                    lambda pkt: pkt.TransferOperationFlag == 0x01,
                ),
                (
                    XLEIntField("DataTransferHandle", 0x00000000),
                    lambda pkt: pkt.TransferOperationFlag != 0x01,
                ),
            ],
            XLEIntField("DataTransferHandle", 0x00000000),
        ),
        XByteEnumField(
            "TransferOperationFlag",
            0x00,
            {
                0x00: "GetNextPart",
                0x01: "GetFirstPart"
            }
        )
    ]


class DownstreamDeviceParameterTableEntry(Packet):
    """DSP0267 -> Table 21"""

    name = "Downstream Device Parameter Table Entry"

    fields_desc = [
        XLEShortField("DownstreamDeviceIndex", 0x0000),
        XLEIntField("ActiveComponentComparisonStamp", 0x00000000),
        ByteEnumField("ActiveComponentVersionStringType", 0, StringTypeValues),
        FieldLenField(
            "ActiveComponentVersionStringLength",
            None,
            "ActiveComponentVersionString",
            "B",
        ),
        StrLenField(
            "ActiveComponentReleaseDate",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            length_from=lambda unused: 8,
        ),
        XLEIntField("PendingComponentComparisonStamp", 0x00000000),
        ByteEnumField("PendingComponentVersionStringType", 0, StringTypeValues),
        FieldLenField(
            "PendingComponentVersionStringLength",
            None,
            "PendingComponentVersionString",
            "B",
        ),
        StrLenField(
            "PendingComponentReleaseDate",
            b"\x00\x00\x00\x00\x00\x00\x00\x00",
            length_from=lambda unused: 8,
        ),
        # Component Activation Methods
        # byte 0 bit 7
        BitField("ComponentActivationMethodsReserved_0", 0, 1),
        BitField("ComponentActivationPendingImage", 0, 1),
        BitField("ComponentActivationAcPowerCycle", 0, 1),
        BitField("ComponentActivationDcPowerCycle", 0, 1),
        BitField("ComponentActivationSystemReboot", 0, 1),
        BitField("ComponentActivationMediumSpecificReset", 0, 1),
        BitField("ComponentActivationSelfContained", 0, 1),
        # byte 0 bit 0
        BitField("ComponentActivationAutomatic", 0, 1),
        # byte 1
        BitField("ComponentActivationMethodsReserved_1", 0, 8),
        # Capabilities During Update
        # byte 0 bits 7:3
        BitField("CapabilitiesDuringUpdateReserved_0", 0, 5),
        # byte 0 bit 2
        BitEnumField(
            "CapabilitiesDuringUpdateComponentDowngradeCapability",
            0,
            1,
            {
                0: "Component settings permit a downgrade to older versions",
                1: "Component settings do not allow for a downgrade to an older version component image",
            },
        ),
        # byte 0 bit 1
        BitEnumField(
            "CapabilitiesDuringUpdateDownstreamDeviceIsUpdateable",
            0,
            1,
            {
                0: "Downstream Device can provide inventory information only",
                1: "Downstream Device can be updated through the FDP",
            },
        ),
        # byte 0 bit 0
        BitEnumField(
            "CapabilitiesDuringUpdateDownstreamDeviceApplyState",
            0,
            1,
            {
                0: "Downstream Device will execute an operation during the APPLY state"
                " which will include migrating the new component image to its final"
                " non-volatile storage destination",
                1: "Downstream Device performs an 'auto-apply' during transfer phase"
                " and apply step will be completed immediately",
            },
        ),
        # bytes 3:1
        BitField("CapabilitiesDuringUpdateReserved_1", 0, 24),
        StrLenField(
            "ActiveComponentVersionString",
            b"",
            length_from=lambda pkt: pkt.ActiveComponentVersionStringLength,
        ),
        StrLenField(
            "PendingComponentVersionString",
            b"",
            length_from=lambda pkt: pkt.PendingComponentVersionStringLength,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class GetDownstreamFirmwareParameters_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Get Downstream Firmware Parameters Response"
    CommandValue = 0x05

    class Data(Packet):
        fields_desc = [
            XLEIntField("NextDataTransferHandle", 0x00000000),
            ByteEnumField("TransferFlag", 0x01, TransferFlags),
            # portion of GetDownstreamFirmwareParameters -> Table 20
            # FDPCapabilitiesDuringUpdate
            # byte 0 bits 7:5
            BitField("FDPCapabilitiesDuringUpdateReserved_1", 0, 3),
            # byte 0 bit 4
            BitEnumField(
                "FDPUpdateModeRestrictions",
                0,
                1,
                {
                    0: "No host OS environment restriction for update mode",
                    1: "Firmware device unable to enter update mode if host OS environment is active",
                },
            ),
            # byte 0 bits 3
            BitField("FDPCapabilitiesDuringUpdateReserved_0", 0, 1),
            # byte 0 bit 2
            BitEnumField(
                "DownstreamDeviceHostFunctionalityDuringFirmwareUpdate",
                0,
                1,
                {
                    0: "Device host functionality is not reduced during Firmware Update",
                    1: "Device host functionality will be reduced, perhaps becoming inaccessible, during Firmware"
                    " Update",
                },
            ),
            # byte 0 bit 1
            BitEnumField(
                "ComponentUpdateFailureRetryCapability",
                0,
                1,
                {
                    0: "Downstream Device can have component updated again without exiting update mode and "
                    " restarting transfer via RequestUpdate command",
                    1: "Downstream Device will not be able to update component again unless it exits update mode"
                    " and the UA sends a new Request Update command",
                },
            ),
            # byte 0 bit 0
            BitEnumField(
                "DownstreamDeviceComponentUpdateFailureRecoveryCapability",
                0,
                1,
                {
                    0: "Downstream Device will revert to previous component image upon a failure, timeout, or"
                    " cancellation of the transfer",
                    1: "Downstream Device will NOT revert to previous component image upon a failure, timeout, or"
                    " cancellation of the transfer",
                },
            ),
            # byte 1 bits 7:1
            BitField("FDPCapabilitiesDuringUpdateReserved_2", 0, 7),
            # byte 1 bits 0 (bit 8)
            BitEnumField(
                "DowngradeRestrictions",
                0,
                1,
                {
                    0: "FDP does not have downgrade restrictions which may prevent a component image"
                    " from being downgraded",
                    1: "FDP supports downgrade restrictions, and each component image will report"
                    " whether a downgrade to an older component image can occur",
                },
            ),
            # bytes 3:2
            BitField("FDPCapabilitiesDuringUpdateReserved_3", 0, 16),
            FieldLenField(
                "DownstreamDeviceCount",
                None,
                count_of="DownstreamDeviceParameterTable",
                fmt="<H",
            ),
            PacketListField(
                "DownstreamDeviceParameterTable",
                [],
                DownstreamDeviceParameterTableEntry,
                count_from=lambda pkt: pkt.DownstreamDeviceCount,
            )
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x90: "INVALID_TRANSFER_HANDLE",
                0x91: "INVALID_TRANSFER_OPERATION_FLAG",
            },
        ),
        ConditionalField(
            PacketField("Parameters", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]

class RequestUpdate_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Request Update Request"
    CommandValue = 0x10

    fields_desc = [
        LEIntField("MaximumTransferSize", 0),
        LEShortField("NumberOfComponents", 0),
        ByteField("MaximumOutstandingTransferRequests", 1),
        LEShortField("PackageDataLength", 0x0000),
        ByteEnumField("ComponentImageSetVersionStringType", 0, StringTypeValues),
        FieldLenField(
            "ComponentImageSetVersionStringLength",
            None,
            "ComponentImageSetVersionString",
            "B",
        ),
        StrLenField(
            "ComponentImageSetVersionString",
            "",
            length_from=lambda pkt: pkt.ComponentImageSetVersionStringLength,
        )
    ]


class RequestUpdate_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Request Update Response"
    CommandValue = 0x10

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x81: "ALREADY_IN_UPDATE_MODE",
                0x8A: "UNABLE_TO_INITIATE_UPDATE",
                0x8E: "RETRY_REQUEST_UPDATE",
            },
        ),
        ConditionalField(
            LEShortField("FirmwareDeviceMetaDataLength", 0x0000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("FDWillSendGetPackageDataCommand", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetPackageData_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Get Package Data Request"
    CommandValue = 0x11

    fields_desc = [
        XLEIntField("DataTransferHandle", 0x00000000),
        ByteEnumField("TransferFlag", 0x01, TransferFlags)
    ]


class GetPackageData_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Get Package Data Response"
    CommandValue = 0x11

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x88: "COMMAND_NOT_EXPECTED",
                0x8F: "NO_PACKAGE_DATA",
                0x90: "INVALID_TRANSFER_HANDLE",
                0x91: "INVALID_TRANSFER_OPERATION_FLAG",
            },
        ),
        ConditionalField(
            XLEIntField("NextDataTransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteEnumField("TransferFlag", 0x01, TransferFlags),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField("PortionOfPackageData", [], XByteField("", 0)),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetDeviceMetaData_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Get Device Meta Data Request"
    CommandValue = 0x12

    fields_desc = [
        XLEIntField("DataTransferHandle", 0x00000000),
        ByteEnumField(
            "TransferOperationFlag",
            0x0,
            {
                0x00: "GetNextPart",
                0x01: "GetFirstPart"
            }
        )
    ]


class GetDeviceMetaData_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Get Device Meta Data Response"
    CommandValue = 0x12

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x84: "INVALID_STATE_FOR_COMMAND",
                0x8D: "NO_DEVICE_METADATA",
                0x90: "INVALID_TRANSFER_HANDLE",
                0x91: "INVALID_TRANSFER_OPERATION_FLAG",
                0x93: "PACKAGE_DATA_ERROR",
            }
        ),
        ConditionalField(
           XLEIntField("NextDataTransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteEnumField("TransferFlag", 0x01, TransferFlags),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField("PortionOfMetaData", [], XByteField("", 0)),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class PassComponentTable_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Pass Component Table Request"
    CommandValue = 0x13

    fields_desc = [
        ByteEnumField("TransferFlag", 0x01, TransferFlags),
        LEShortEnumField(
            "ComponentClassification",
            0x0000,
            {
                **ComponentClassificationValues,
                0xFFFF: "Downstream Device"
            },
        ),
        XLEShortField("ComponentIdentifier", 0x0000),
        XByteField("ComponentClassificationIndex", 0x00),
        LEIntField("ComponentComparisonStamp", 0x00000000),
        ByteEnumField("ComponentVersionStringType", 0, StringTypeValues),
        XByteField("ComponentVersionStringLength", 0x00),
        StrLenField(
            "ComponentVersionString",
            b"",
            length_from=lambda pkt: pkt.ComponentVersionStringLength,
        )
    ]


class PassComponentTable_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Pass Component Table Response"
    CommandValue = 0x13

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "NOT_IN_UPDATE_MODE",
                0x84: "INVALID_STATE_FOR_COMMAND",
            },
        ),
        ConditionalField(
            ByteEnumField(
                "ComponentResponse",
                0,
                {0: "Component can be updated", 1: "Component may be updateable"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteEnumField("ComponentResponseCode", 0x00, ComponentResponseCodes),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class UpdateComponent_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Update Component Request"
    CommandValue = 0x14

    fields_desc = [
        LEShortEnumField(
            "ComponentClassification", 0x0000, COMPONENT_CLASSIFICATION_VALUES
        ),
        XLEShortField("ComponentIdentifier", 0x0000),
        XByteField("ComponentClassificationIndex", 0x00),
        XLEIntField("ComponentComparisonStamp", 0x00000000),
        XLEIntField("ComponentImageSize", 0x00000000),
        # UpdateOptionFlags
        # byte 0 bit 7:1
        BitField("Reserved_0", 0, 7),
        # byte 0 bit 0
        BitField("UpdateOptionFlagsRequestForceUpdate", 0, 1),
        # bytes 3:1
        BitField("Reserved_1", 0, 24),
        ByteEnumField("ComponentVersionStringType", 0, StringTypeValues),
        XByteField("ComponentVersionStringLength", 0x00),
        StrLenField(
            "ComponentVersionString",
            b"",
            length_from=lambda pkt: pkt.ComponentVersionStringLength,
        )
    ]


class UpdateComponent_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Update Component Response"
    CommandValue = 0x14

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {**PLDM_BASE_CODES, 0x80: "NOT_IN_UPDATE_MODE"}
        ),
        ConditionalField(
            ByteEnumField(
                "ComponentCompatibilityResponse",
                0,
                {
                    0: "Component can be updated",
                    1: "Component will not be updated"
                },
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteEnumField(
                "ComponentCompatibilityResponseCode",
                0x00,
                ComponentCompatibilityResponseCodes,
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            # UpdateOptionFlags
            # byte 0 bit 7:1
            BitField("Reserved_0", 0, 7),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            # byte 0 bit 0
            BitField("UpdateOptionFlagsRequestForceUpdate", 0, 1),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            # bytes 3:1
            BitField("Reserved_1", 0, 24),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            LEShortField("EstimatedTimeBeforeSendingRequestFirmwareData", 0x0000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class RequestFirmwareData_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Request Firmware Data Request"
    CommandValue = 0x15

    fields_desc = [
        XLEIntField("Offset", 0x00000000),
        XLEIntField("Length", 0x00000000),
    ]


class RequestFirmwareData_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Request Firmware Data Response"
    CommandValue = 0x15

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x82: "DATA_OUT_OF_RANGE",
                0x83: "INVALID_TRANSFER_LENGTH",
                0x87: "CANCEL_PENDING",
                0x88: "COMMAND_NOT_EXPECTED",
                0x89: "RETRY_REQUEST_FW_DATA",
            },
        ),
        # ComponentImagePortion should added as payload to command
    ]


class TransferComplete_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Transfer Complete Request"
    CommandValue = 0x16

    fields_desc = [
        XByteEnumField("TransferResult", 0x00, TransferResults)
    ]


class TransferComplete_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Transfer Complete Response"
    CommandValue = 0x16

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x88: "COMMAND_NOT_EXPECTED"
            }
        )
    ]


class VerifyComplete_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Verify Complete Request"
    CommandValue = 0x17

    fields_desc = [
        XByteEnumField("VerifyResult", 0x00, VerifyResults)
    ]


class VerifyComplete_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Verify Complete Response"
    CommandValue = 0x17

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES, 0x88: "COMMAND_NOT_EXPECTED"
            }
        )
    ]


class ApplyComplete_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Apply Complete Request"
    CommandValue = 0x18

    fields_desc = [
        XByteEnumField("ApplyResult", 0x00, APPLY_RESULT_VALUES),
        BitField("ComponentActivationMethodsModification", 0, 16)
    ]


class ApplyComplete_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Apply Complete Response"
    CommandValue = 0x18

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES, 0x88: "COMMAND_NOT_EXPECTED"
            }
        )
    ]


class GetMetaData_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Get Meta Data Request"
    CommandValue = 0x19

    fields_desc = [
        XLEIntField("DataTransferHandle", 0x00000000),
        XByteEnumField(
            "TransferOperationFlag", 0x00, {0x00: "GetNextPart", 0x01: "GetFirstPart"}
        )
    ]


class GetMetaData_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Get Meta Data Response"
    CommandValue = 0x19

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x88: "COMMAND_NOT_EXPECTED",
                0x90: "INVALID_TRANSFER_HANDLE",
                0x91: "INVALID_TRANSFER_OPERATION_FLAG",
            },
        ),
        ConditionalField(
        XLEIntField("NextDataTransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
        XByteEnumField("TransferFlag", 0x01, TransferFlags),
            lambda pkt: pkt.CompletionCode == 0
        )
        # PortionOfMetaData should added as payload to command
    ]


class ActivateFirmware_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Activate Firmware Request"
    CommandValue = 0x1A

    fields_desc = [
        ByteField("SelfContainedActivationRequest", 0)
    ]


class ActivateFirmware_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Activate Firmware Response"
    CommandValue = 0x1A

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "NOT_IN_UPDATE_MODE",
                0x84: "INVALID_STATE_FOR_COMMAND",
                0x85: "INCOMPLETE_UPDATE",
                0x8B: "ACTIVATION_NOT_REQUIRED",
                0x8C: "SELF_CONTAINED_ACTIVATION_NOT_PERMITTED",
            },
        ),
        ConditionalField(
            LEShortField("EstimatedTimeForSelfContainedActivation", 0),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetStatus_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Get Status Request"
    CommandValue = 0x1B


class GetStatus_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Get Status Response"
    CommandValue = 0x1B

    class Data(Packet):
        fields_desc = [
            ByteEnumField("CurrentState", 0, FDStates),
            ByteEnumField("PreviousState", 0, FDStates),
            ByteEnumField("AuxState", 0, AuxStates),
            XByteEnumField("AuxStateStatus", 0x00, AuxStatus),
            ByteField("ProgressPercent", 0x00),
            ByteEnumField("ReasonCode", 0, AuxReasonCodes),
            XBitField("UpdateOptionFlagsEnabled", 0, 32)
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            PacketField("Status", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class CancelUpdateComponent_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Cancel Update Component Request"
    CommandValue = 0x1C


class CancelUpdateComponent_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Cancel Update Component Response"
    CommandValue = 0x1C

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "NOT_IN_UPDATE_MODE",
                0x86: "BUSY_IN_BACKGROUND"}
        )
    ]


class CancelUpdate_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Cancel Update Request"
    CommandValue = 0x1D


class CancelUpdate_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Cancel Update Response"
    CommandValue = 0x1D

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "NOT_IN_UPDATE_MODE",
                0x86: "BUSY_IN_BACKGROUND"},
        ),

        ConditionalField(
            ByteField("NonFunctioningComponentIndication", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            BitField("NonFunctioningComponentBitmap", 0, 64),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class ActivatePendingComponentImageSet_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Activate Pending Component Image Set Request"
    CommandValue = 0x1E


class ActivatePendingComponentImageSet_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Activate Pending Component Image Set Response"
    CommandValue = 0x1E

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x84: "INVALID_STATE_FOR_COMMAND",
                0x8B: "ACTIVATION_NOT_REQUIRED",
                0x92: "ACTIVATE_PENDING_IMAGE_NOT_PERMITTED",
            },
        ),
        ConditionalField(
            LEShortField("EstimatedTimeForActivation", 0),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class ActivatePendingComponentImage_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Activate Pending Component Image Request"
    CommandValue = 0x1F

    fields_desc = [
        LEShortEnumField(
            "ComponentClassification", 0x0000, ComponentClassificationValues
        ),
        LEShortField("ComponentIdentifier", 0x0000),
        ByteField("ComponentClassificationIndex", 0x00)
    ]


class ActivatePendingComponentImage_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Activate Pending Component Image Response"
    CommandValue = 0x1F

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x84: "INVALID_STATE_FOR_COMMAND",
                0x8B: "ACTIVATION_NOT_REQUIRED",
                0x92: "ACTIVATE_PENDING_IMAGE_NOT_PERMITTED",
            },
        ),
        ConditionalField(
            LEShortField("EstimatedTimeForActivation", 0),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class RequestDownstreamDeviceUpdate_Request(PLDM_TYPE_5_PAYLOAD):
    name = "Request Downstream Device Update Request"
    CommandValue = 0x20

    fields_desc = [
        XLEIntField("MaximumDownstreamDeviceTransferSize", 0x00000000),
        XByteField("MaximumOutstandingTransferRequests", 0x01),
        XLEShortField("DownstreamDevicePackageDataLength", 0x0000)
    ]


class RequestDownstreamDeviceUpdate_Response(PLDM_TYPE_5_PAYLOAD):
    name = "Request Downstream Device Update Response"
    CommandValue = 0x20

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x81: "ALREADY_IN_UPDATE_MODE",
                0x8A: "UNABLE_TO_INITIATE_UPDATE",
                0x8E: "RETRY_REQUEST_UPDATE",
            },
        ),
        XLEShortField("DownstreamDeviceMetaDataLength", 0x0000),
        XByteField("DDWillSendGetPackageDataCommand", 0x00)
    ]


class TestUnsupportedPldm_Request(PLDM_TYPE_5_PAYLOAD):
    __test__ = False    # pytest: ignore class

    name = "Test Unsupported PLDM Command Request"
    CommandValue = 0xF2


class TestUnsupportedPldm_Response(PLDM_TYPE_5_PAYLOAD):
    __test__ = False    # pytest: ignore class

    name = "Test Unsupported PLDM Command Response"
    CommandValue = 0xf2

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES
            },
        )
    ]


# Register for dissection ####
bind_layers(PLDM_HEADER, PLDM_TYPE_5_PAYLOAD, PldmType=0x05)

# Register Commands/Packets based on Payload Type, Rq/Rs and Command Type
register_pldm_class(QueryDeviceIdentifiers_Request)
register_pldm_class(QueryDeviceIdentifiers_Response)
register_pldm_class(GetFirmwareParameters_Request)
register_pldm_class(GetFirmwareParameters_Response)
register_pldm_class(QueryDownstreamDevices_Request)
register_pldm_class(QueryDownstreamDevices_Response)
register_pldm_class(QueryDownstreamIdentifiers_Request)
register_pldm_class(QueryDownstreamIdentifiers_Response)
register_pldm_class(GetDownstreamFirmwareParameters_Request)
register_pldm_class(GetDownstreamFirmwareParameters_Response)

register_pldm_class(RequestUpdate_Request)
register_pldm_class(RequestUpdate_Response)
register_pldm_class(GetPackageData_Request)
register_pldm_class(GetPackageData_Response)
register_pldm_class(GetDeviceMetaData_Request)
register_pldm_class(GetDeviceMetaData_Response)
register_pldm_class(PassComponentTable_Request)
register_pldm_class(PassComponentTable_Response)
register_pldm_class(UpdateComponent_Request)
register_pldm_class(UpdateComponent_Response)
register_pldm_class(RequestFirmwareData_Request)
register_pldm_class(RequestFirmwareData_Response)
register_pldm_class(TransferComplete_Request)
register_pldm_class(TransferComplete_Response)
register_pldm_class(VerifyComplete_Request)
register_pldm_class(VerifyComplete_Response)
register_pldm_class(ApplyComplete_Request)
register_pldm_class(ApplyComplete_Response)
register_pldm_class(GetMetaData_Request)
register_pldm_class(GetMetaData_Response)

register_pldm_class(ActivateFirmware_Request)
register_pldm_class(ActivateFirmware_Response)
register_pldm_class(GetStatus_Request)
register_pldm_class(GetStatus_Response)
register_pldm_class(CancelUpdateComponent_Request)
register_pldm_class(CancelUpdateComponent_Response)
register_pldm_class(CancelUpdate_Request)
register_pldm_class(CancelUpdate_Response)

register_pldm_class(ActivatePendingComponentImageSet_Request)
register_pldm_class(ActivatePendingComponentImageSet_Response)
register_pldm_class(ActivatePendingComponentImage_Request)
register_pldm_class(ActivatePendingComponentImage_Response)
register_pldm_class(RequestDownstreamDeviceUpdate_Request)
register_pldm_class(RequestDownstreamDeviceUpdate_Response)

register_pldm_class(TestUnsupportedPldm_Request)
register_pldm_class(TestUnsupportedPldm_Response)
