# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Contains the PLDM Type 6 (PLDM for Redfish) wrappers from DSP0218
##############################################################################

from scapy.fields import *    # pylint: disable=unused-import, unused-wildcard-import
from scapy.all import bind_layers, Packet

from pldm.bej_types import *  # pylint: disable=unused-import, unused-wildcard-import
from pldm.dmtf import (
    PLDM_HEADER,
    PLDM_PAYLOAD,
    VAR_STRING,
    register_pldm_class,
    TransferFlags,
    PLDM_BASE_CODES,
    TransferOperation
)

DSP0218_COMPLIANCE_VERSION = int.from_bytes([1, 1, 2, 0], 'big')

class PLDM_TYPE_6_PAYLOAD(PLDM_PAYLOAD):
    """base class for all PLDM Type 6 Message Payloads"""

    name = "Redfish over PLDM"
    PldmPayloadType = 0x06


# DSP0218, Table 3
schemaClass = {
    0: "MAJOR",
    1: "EVENT",
    2: "ANNOTATION",
    3: "COLLECTION_MEMBER_TYPE",
    4: "ERROR",
    5: "REGISTRY",
}

COMPLETION_CODES = {
    **PLDM_BASE_CODES,
    0x80: "ERROR_BAD_CHECKSUM",
    0x81: "ERROR_CANNOT_CREATE_OPERATION",
    0x82: "ERROR_NOT_ALLOWED",
    0x83: "ERROR_WRONG_LOCATION_TYPE",
    0x84: "ERROR_OPERATION_ABANDONED",
    0x85: "ERROR_OPERATION_UNKILLABLE",
    0x86: "ERROR_OPERATION_EXISTS",
    0x87: "ERROR_OPERATION_FAILED",
    0x88: "ERROR_UNEXPECTED",
    0x89: "ERROR_UNSUPPORTED",
    0x90: "ERROR_UNRECOGNIZED_CUSTOM_HEADER",
    0x91: "ERROR_ETAG_MATCH",
    0x92: "ERROR_NO_SUCH_RESOURCE",
    0x93: "ETAG_CALCULATION_ONGOING",
}

OPERATION_STATUS = {
    0: "OPERATION_INACTIVE",
    1: "OPERATION_NEEDS_INPUT",
    2: "OPERATION_TRIGGERED",
    3: "OPERATION_RUNNING",
    4: "OPERATION_HAVE_RESULTS",
    5: "OPERATION_COMPLETED",
    6: "OPERATION_FAILED",
    7: "OPERATION_ABANDONED",
}

OPERATION_TYPE = {
    0: "OPERATION_HEAD",
    1: "OPERATION_READ",
    2: "OPERATION_CREATE",
    3: "OPERATION_DELETE",
    4: "OPERATION_UPDATE",
    5: "OPERATION_REPLACE",
    6: "OPERATION_ACTION",
}


class BejTupleF(Packet):
    name = "BejTupleF"
    fields_desc = [
        BitEnumField("PrincipleDataType", 0, 4, BEJFormatCodes),
        BitEnumField("reserved_flag", 0, 1, FLAG_SET),
        BitEnumField("nullable_property", 0, 1, FLAG_SET),
        BitEnumField("read_only", 0, 1, FLAG_SET),
        BitEnumField("deferred_binding", 0, 1, FLAG_SET)
    ]

    def extract_padding(self, s):
        return ("", s)


class nnint_encoding(Packet):
    """DSP0218, Table 4"""

    name = "nnint"

    fields_desc = [
        XByteField("Length", 0),
        FieldListField(
            "IntegerData",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.Length
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class bejLocator(Packet):
    """DSP0218, Table 4"""

    name = "bejLocator"
    fields_desc = [
        PacketField("Format", nnint_encoding(), nnint_encoding)
    ]

    def extract_padding(self, s):
        return ("", s)


class bejEncoding(Packet):
    name = "bejEncoding"

    fields_desc = [
        XLEIntField("BEJVersion", 0xF1F1F000),  # TODO to check
        XLEShortField("Reserved", 0x00),
        ByteEnumField("SchemaClass", 0, schemaClass),
        # TODO: BaseBejTuple: comment it if want get pure raw data
        PacketField("BejTuple", BejTuple(), BejTuple),
    ]

    def extract_padding(self, s):
        return ("", s)


"""
This really isn't 'required' but will be nice to help dissect the dictionary
received via the MultipartReceive commands. This requires work to implement, as
it does not lend itself well to scapy decoding easily.
"""

class DictionaryEntry(Packet):
    name = "Dictionary Entry"

    """
    This is how it will be represented in scapy - the final binary format will differ,
    the actual Name string will not be part of this Packet 'chunk' will be in another place
    but this was a good way to represent it
    """

    fields_desc = [
        PacketField("Format", BejTupleF(), BejTupleF),
        LEShortField("SequenceNumber", 0),
        LEShortField("ChildPointerOffset", 0),
        LEShortField("ChildCount", 0),
        # TODO: to check NameLengthStr
        ByteField("NameLength", 0),
        FieldLenField("NameLengthStr", None, "Name", "B"),  # length of 'Name'
        LEShortField("NameOffset", None),
        StrLenField(
            "Name", "", length_from=lambda pkt: pkt.NameLengthStr
        )   # Variable len Name
    ]

    __slots__ = ["NameStr", "DictData"]

    def __init__(self, _pkt=b"", *args, **kwargs):
        self.NumVersions = 0
        Packet.__init__(self, _pkt, *args, **kwargs)

    def post_build(self, pkt, pay):
        return pkt + pay


class Dictionary(Packet):
    name = "Redfish over PLDM Dictionary binary format"

    # This is how it will be represented in scapy - the final binary format will differ
    fields_desc = [
        XByteField("VersionTag", 0x00),
        BitField("DictionaryReserved_0", 0, 7),
        BitField("truncation_flag", 0, 1),
        FieldLenField("EntryCount", None, count_of="Entries", fmt="<H"),
        XLEIntField("SchemaVersion", 0x00),
        LEIntField("DictionarySize", None),
        PacketListField(
            "Entries", None, DictionaryEntry, count_from=lambda pkt: pkt.EntryCount
        )
    ]


########## PLDM Type 6 Message Classes ############

#    Discovery and Schema Management Commands
class NegotiateRedfishParameters_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Negotiate Redfish Parameters Request"
    CommandValue = 0x01

    fields_desc = [
        ByteField("MCConcurrencySupport", 0x00),

        # byte 0
        BitField("events_supported", 0, 1),
        BitField("action_supported", 0, 1),
        BitField("replace_supported", 0, 1),
        BitField("update_supported", 0, 1),
        BitField("delete_supported", 0, 1),
        BitField("create_supported", 0, 1),
        BitField("read_supported", 0, 1),
        BitField("head_supported", 0, 1),

        # byte 1
        BitField("NegotiateRedfishParametersReserved_0", 0, 7),
        BitField("bej1_1_supported", 0, 1)
    ]


class NegotiateRedfishParameters_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Negotiate Redfish Parameters Response"
    CommandValue = 0x01

    class Data(Packet):
        fields_desc = [
            ByteField("DeviceConcurrencySupport", 0x00),

            # DeviceCapabilitiesFlags
            BitField("NegotiateRedfishParametersReserved_0", 0, 5),
            BitField("bej1_1_supported", 0, 1),
            BitField("expand_supported", 0, 1),
            BitField("atomic_resource_read", 0, 1),

            # DeviceFeatureSupport
            # byte 0
            BitField("events_supported", 0, 1),
            BitField("action_supported", 0, 1),
            BitField("replace_supported", 0, 1),
            BitField("update_supported", 0, 1),
            BitField("delete_supported", 0, 1),
            BitField("create_supported", 0, 1),
            BitField("read_supported", 0, 1),
            BitField("head_supported", 0, 1),

            # byte 1
            BitField("NegotiateRedfishParametersReserved_1", 0, 8),
            XLEIntField("DeviceConfigurationSignature", 0x00000000),
            PacketField("DeviceProviderName", VAR_STRING(), VAR_STRING)
        ]

        def extract_padding(self, pld):  # all payloads need to do this
            return ("", pld,)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            PacketField("Parameters", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class NegotiateMediumParameters_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Negotiate Medium Parameters Request"
    CommandValue = 0x02

    fields_desc = [
        LEIntField("MCMaximumTransferChunkSizeBytes", 0x00)
    ]


class NegotiateMediumParameters_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Negotiate Medium Parameters Response"
    CommandValue = 0x02

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            LEIntField("DeviceMaximumTransferChunkSizeBytes", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetSchemaDictionary_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Get Schema Dictionary Request"
    CommandValue = 0x03

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        ByteEnumField("RequestedSchemaClass", 0, schemaClass)
    ]


class GetSchemaDictionary_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Get Schema Dictionary Response"
    CommandValue = 0x03

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            XByteField("DictionaryFormat", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
        XLEIntField("TransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetSchemaURI_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Get Schema URI Request"
    CommandValue = 0x04

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        ByteEnumField("RequestedSchemaClass", 0, schemaClass),
        XByteField("OEMExtensionNumber", 0x00)
    ]


class GetSchemaURI_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Get Schema URI Response"
    CommandValue = 0x04

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            FieldLenField("StringFragmentCount", None, fmt="B", count_of="SchemaURIs"),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            PacketListField(
                "SchemaURIs",
                None,
                VAR_STRING,
                count_from=lambda pkt: pkt.StringFragmentCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetResourceETag_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Get Resource ETag Request"
    CommandValue = 0x05

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000)
    ]


class GetResourceETag_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Get Resource ETag Response"
    CommandValue = 0x05

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
        PacketField("ETag", VAR_STRING(), VAR_STRING),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetOEMCount_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Get OEM Count Request"
    CommandValue = 0x06

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        ByteEnumField("RequestedSchemaClass", 0, schemaClass)
    ]


class GetOEMCount_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Get OEM Count Response"
    CommandValue = 0x06

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
        XByteField("OEMCount", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetOEMName_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Get OEM Name Request"
    CommandValue = 0x07

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        ByteEnumField("RequestedSchemaClass", 0, schemaClass),
        XByteField("OEMIndex", 0x00)
    ]


class GetOEMName_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Get OEM Name Response"
    CommandValue = 0x07

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
        PacketField("OEMName", VAR_STRING(), VAR_STRING),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetRegistryCount_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Get Registry Count Request"
    CommandValue = 0x08


class GetRegistryCount_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Get Registry Count Response"
    CommandValue = 0x08

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
        XByteField("RegistryCount", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetRegistryDetails_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Get Registry Details Request"
    CommandValue = 0x09

    fields_desc = [
        XByteField("RegistryIndex", 0x00)
    ]


class GetRegistryDetails_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Get Registry Details Response"
    CommandValue = 0x09

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            PacketField("RegistryPrefix", VAR_STRING(), VAR_STRING),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            PacketField("RegistryURI", VAR_STRING(), VAR_STRING),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("RegistryLanguage", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("VersionCount", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField(
                "RecordData",
                [],
                XLEIntField("", 0x00000000),
                count_from=lambda pkt: pkt.VersionCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SelectRegistryVersion_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Select Registry Version Request"
    CommandValue = 0x0A

    fields_desc = [
        XByteField("RegistryIndex", 0x00),
        XLEIntField("RegistryVersion", 0x00000000)
    ]


class SelectRegistryVersion_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Select Registry Version Response"
    CommandValue = 0x0A

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES)
    ]


class GetMessageRegistry_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Get Message Registry Request"
    CommandValue = 0x0B

    fields_desc = [
        XByteField("RegistryIndex", 0x00)
    ]


class GetMessageRegistry_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Get Message Registry Response"
    CommandValue = 0x0B

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            XByteField("SchemaFormat", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("TransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetSchemaFile_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Get Schema File Request"
    CommandValue = 0x0C

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        ByteEnumField("RequestedSchemaClass", 0, schemaClass),
        XByteField("OEMOffset", 0x00)
    ]


class GetSchemaFile_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Get Schema File Response"
    CommandValue = 0x0C

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            XByteField("SchemaFormat", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("TransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


# RDE Commands
class RDEOperationInit_Request(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Init Request"
    CommandValue = 0x10

    fields_desc = [
        XLEIntField("ResourceID", 0),
        XLEShortField("OperationID", 0x0000),  # MSB is reserved for MC
        ByteEnumField("OperationType", 0, OPERATION_TYPE),

        # OperationFlags
        BitField("Reserved", 0, 4),
        BitField("ExcerptFlag", 0, 1),
        BitField("ContainsCustomRequestParameters", 0, 1),
        BitField("ContainsRequestPayload", 0, 1),
        BitField("LocatorValid", 0, 1),
        XLEIntField("SendDataTransferHandle", 0),
        XByteField("OperationLocatorLength", 0x00),
        LEIntField("RequestPayloadLength", 0),
        # TODO: OperationLocator
        ConditionalField(
            PacketListField("OperationLocator", bejLocator(), bejLocator),
            lambda pkt: pkt.OperationLocatorLength > 0,
        ),
        ConditionalField(
            PacketListField("RequestPayload", bejEncoding(), bejEncoding),
            lambda pkt: pkt.RequestPayloadLength > 0,
        )
    ]


class RDEOperationInit_Response(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Init Response"
    CommandValue = 0x10

    class Data(Packet):
        fields_desc = [
            ByteEnumField("OperationStatus", 0, OPERATION_STATUS),
            ByteField("CompletionPercentage", 0),
            XLEIntField("CompletionTimeSeconds", 0x00000000),

            # OperationExecutionFlags
            BitField("Reserved_1", 0, 4),
            BitField("CacheAllowed", 0, 1),
            BitField("HaveResultPayload", 0, 1),
            BitField("HaveCustomResponseParameters", 0, 1),
            BitField("TaskSpawned", 0, 1),
            XLEIntField("ResultTransferHandle", 0x00000000),

            # PermissionFlags
            BitField("Reserved", 0, 2),
            BitField("HeadAccess", 0, 1),
            BitField("DeleteAccess", 0, 1),
            BitField("CreateAccess", 0, 1),
            BitField("ReplaceAccess", 0, 1),
            BitField("UpdateAccess", 0, 1),
            BitField("ReadAccess", 0, 1),
            XLEIntField("ResponsePayloadLength", 0x00000000),
            PacketField("ETag", VAR_STRING(), VAR_STRING),
            MultipleTypeField(
                [
                    (
                        XByteField("ResponsePayload", 0x00),
                        lambda pkt: pkt.ResponsePayloadLength == 0,
                    ),
                    # null if ResponsePayloadLength == 0
                    (
                        PacketField("ResponsePayload", bejEncoding(), bejEncoding),
                        lambda pkt: pkt.ResponsePayloadLength > 0,
                    ),
                ],
                XByteField("ResponsePayload", 0x00)
            )
        ]

        def extract_padding(self, pld):  # all payloads need to do this
            return ("", pld,)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            PacketField("Parameters", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SupplyCustomRequestParametersETags(Packet):
    name = "ETAGs"

    fields_desc = [
        PacketField("ETag", VAR_STRING(), VAR_STRING)
    ]

    def extract_padding(self, s):
        return ("", s)


class SupplyCustomParameters(Packet):
    name = "Headers"

    fields_desc = [
        PacketField("HeaderName", VAR_STRING(), VAR_STRING),
        PacketField("HeaderParameter", VAR_STRING(), VAR_STRING)
    ]

    def extract_padding(self, s):
        return ("", s)


class SupplyCustomRequestParameters_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Supply Custom Parameters Request"
    CommandValue = 0x11

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        XLEShortField("OperationID", 0x0000),
        XLEShortField("LinkExpand", 0x0000),
        XLEShortField("CollectionSkip", 0x0000),
        XLEShortField("CollectionTop", 0x0000),
        XLEShortField("PaginationOffset", 0x0000),
        ByteEnumField(
            "ETagOperation",
            0,
            {0: "ETAG_IGNORE", 1: "ETAG_IF_MATCH", 2: "ETAG_IF_NONE_MATCH"},
        ),
        # TODO to check
        XByteField("ETagCount", 0x00),
        PacketListField(
            "Etags",
            SupplyCustomRequestParametersETags(),
            SupplyCustomRequestParametersETags,
            count_from=lambda pkt: pkt.ETagCount,
        ),
        # TODO to check
        XByteField("HeaderCount", 0x00),
        PacketListField(
            "Headers",
            SupplyCustomParameters(),
            SupplyCustomParameters,
            count_from=lambda pkt: pkt.HeaderCount,
        )
    ]


class SupplyCustomRequestParameters_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Supply Custom Parameters Response"
    CommandValue = 0x11

    class Data(Packet):
        fields_desc = [
            ByteEnumField("OperationStatus", 0, OPERATION_STATUS),
            ByteField("CompletionPercentage", 0),
            XLEIntField("CompletionTimeSeconds", 0x00000000),

            # OperationExecutionFlags
            BitField("Reserved_1", 0, 4),
            BitField("CacheAllowed", 0, 1),
            BitField("HaveResultPayload", 0, 1),
            BitField("HaveCustomResponseParameters", 0, 1),
            BitField("TaskSpawned", 0, 1),
            XLEIntField("ResultTransferHandle", 0x00000000),

            # PermissionFlags
            BitField("Reserved", 0, 2),
            BitField("HeadAccess", 0, 1),
            BitField("DeleteAccess", 0, 1),
            BitField("CreateAccess", 0, 1),
            BitField("ReplaceAccess", 0, 1),
            BitField("UpdateAccess", 0, 1),
            BitField("ReadAccess", 0, 1),
            XLEIntField("ResponsePayloadLength", 0x00000000),
            PacketField("ETag", VAR_STRING(), VAR_STRING),
            MultipleTypeField(
                [
                    (
                        XByteField("ResponsePayload", 0x00),
                        lambda pkt: pkt.ResponsePayloadLength == 0,
                    ),
                    # null if ResponsePayloadLength == 0
                    (
                        PacketField("ResponsePayload", bejEncoding(), bejEncoding),
                        lambda pkt: pkt.ResponsePayloadLength > 0,
                    ),
                ],
                XByteField("ResponsePayload", 0x00)
            )
        ]

        def extract_padding(self, pld):  # all payloads need to do this
            return ("", pld,)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            PacketField("Parameters", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class RetrieveCustomResponseParameters_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Retrieve Custom Response Parameters Request"
    CommandValue = 0x12

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        XLEShortField("OperationID", 0x0000)
    ]


class RetrieveCustomResponseParameters_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Retrieve Custom Response Parameters Response"
    CommandValue = 0x12

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            XLEIntField("DeferralTimeframe", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("NewResourceID", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("ResponseHeaderCount", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            PacketListField(
                "Headers",
                SupplyCustomParameters(),
                SupplyCustomParameters,
                count_from=lambda pkt: pkt.ResponseHeaderCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class RDEOperationComplete_Request(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Complete Request"
    CommandValue = 0x13

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        XLEShortField("OperationID", 0x0000)
    ]


class RDEOperationComplete_Response(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Complete Response"
    CommandValue = 0x13

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES)
    ]


class RDEOperationStatus_Request(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Status Request"
    CommandValue = 0x14

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        XLEShortField("OperationID", 0x0000)
    ]


class RDEOperationStatus_Response(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Status Response"
    CommandValue = 0x14

    class Data(Packet):
        fields_desc = [
            ByteEnumField("OperationStatus", 0, OPERATION_STATUS),
            ByteField("CompletionPercentage", 0),
            XLEIntField("CompletionTimeSeconds", 0x00000000),

            # OperationExecutionFlags
            BitField("Reserved_1", 0, 4),
            BitField("CacheAllowed", 0, 1),
            BitField("HaveResultPayload", 0, 1),
            BitField("HaveCustomResponseParameters", 0, 1),
            BitField("TaskSpawned", 0, 1),
            XLEIntField("ResultTransferHandle", 0x00000000),

            # PermissionFlags
            BitField("Reserved", 0, 2),
            BitField("HeadAccess", 0, 1),
            BitField("DeleteAccess", 0, 1),
            BitField("CreateAccess", 0, 1),
            BitField("ReplaceAccess", 0, 1),
            BitField("UpdateAccess", 0, 1),
            BitField("ReadAccess", 0, 1),
            XLEIntField("ResponsePayloadLength", 0x00000000),
            PacketField("ETag", VAR_STRING(), VAR_STRING),
            MultipleTypeField(
                [
                    (
                        XByteField("ResponsePayload", 0x00),
                        lambda pkt: pkt.ResponsePayloadLength == 0,
                    ),
                    # null if ResponsePayloadLength == 0
                    (
                        PacketField("ResponsePayload", bejEncoding(), bejEncoding),
                        lambda pkt: pkt.ResponsePayloadLength > 0,
                    ),
                ],
                XByteField("ResponsePayload", 0x00)   # Default field
            )
        ]

        def extract_padding(self, pld):  # all payloads need to do this
            return ("", pld,)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            PacketField("Status", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]

class RDEOperationKill_Request(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Kill Request"
    CommandValue = 0x15

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        XLEShortField("OperationID", 0x0000),
        # KillFlags
        BitField("Reserved", 0, 5),
        BitField("DiscardResults", 0, 1),
        BitField("RunToCompletion", 0, 1),
        BitField("DiscardRecord", 0, 1)
    ]


class RDEOperationKill_Response(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Kill Response"
    CommandValue = 0x15

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES)
    ]


class RDEOperationEnumerate_Request(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Enumerate Request"
    CommandValue = 0x16


class RDEOperationEnumerateFields(Packet):
    name = "RDE Operation Enumerate Fields"
    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        XLEShortField("OperationID", 0x0000),
        ByteEnumField("OperationType", 0, OPERATION_TYPE)
    ]

    def extract_padding(self, s):
        return ("", s)


class RDEOperationEnumerate_Response(PLDM_TYPE_6_PAYLOAD):
    name = "RDE Operation Enumerate Response"
    CommandValue = 0x16

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            XLEShortField("OperationCount", 0x0000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            PacketListField(
                "Resources",
                RDEOperationEnumerateFields(),
                RDEOperationEnumerateFields,
                count_from=lambda pkt: pkt.OperationCount,
            ),
            lambda pkt: pkt.OperationCount != 0x0000 and pkt.CompletionCode == 0
        )
    ]


#    Multipart Transfer Commands
class MultipartSend_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Multipart Send Request"
    CommandValue = 0x30

    fields_desc = [
        XLEIntField("DataTransferHandle", 0x00000000),
        XLEShortField("OperationID", 0x0000),
        ByteEnumField(
            "TransferFlag",
            0,
            {
                0: "Start",
                1: "Middle",
                2: "End",
                3: "StartAndEnd"
            }
        ),
        XLEIntField("NextTransferHandle", 0x00000000),
        FieldLenField("DataLengthBytes", None, "Data", "<I"),
        FieldListField(
            "Data", [], ByteField, count_from=lambda pkt: pkt.DataLengthBytes
        ),
        # Checksum only there if is end of transfer
        ConditionalField(
            XLEIntField("DataIntegrityChecksum", None),
            lambda pkt: pkt.TransferFlag == 0x04 or pkt.TransferFlag == 0x05,
        ),

        # NOTE: if building a packet via Scapy, you must calculate and insert
        # the checksum yourself in the last packet - otherwise this framework
        # would have to keep track of all the the previous data packets created
        # up til the final one.
    ]


class MultipartSend_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Multipart Send Response"
    CommandValue = 0x30

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            ByteEnumField("TransferOperation", 0, TransferOperation),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class MultipartReceive_Request(PLDM_TYPE_6_PAYLOAD):
    name = "Multipart Receive Request"
    CommandValue = 0x31

    fields_desc = [
        XLEIntField("DataTransferHandle", 0x00000000),
        XLEShortField("OperationID", 0x0000),
        ByteEnumField("TransferOperation", 0, TransferOperation)
    ]


class MultipartReceive_Response(PLDM_TYPE_6_PAYLOAD):
    name = "Multipart Receive Response"
    CommandValue = 0x31

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),
        ConditionalField(
            ByteEnumField(
                "TransferFlag", 0, {0: "Start", 1: "Middle", 2: "End", 3: "StartAndEnd"}
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("NextTransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldLenField("DataLengthBytes", None, "Data", "<I"),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField(
                "Data", [], ByteField, count_from=lambda pkt: pkt.DataLengthBytes
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),

        # Checksum only there if is end of transfer
        ConditionalField(
            XLEIntField("DataIntegrityChecksum", None),
            lambda pkt: (pkt.TransferFlag == 0x04 or pkt.TransferFlag == 0x05,) and pkt.CompletionCode == 0
        )

        # NOTE: if building a packet via Scapy, you must calculate and insert
        # the checksum yourself in the last packet - otherwise this framework
        # would have to keep track of all the the previous data packets created
        # up til the final one.
    ]


# Register for simple dissection
bind_layers(PLDM_HEADER, PLDM_TYPE_6_PAYLOAD, PldmType=0x06)


# Register Commands/Packets based on Payload Type, Rq/Rs and Command Type
register_pldm_class(NegotiateRedfishParameters_Request)
register_pldm_class(NegotiateRedfishParameters_Response)
register_pldm_class(NegotiateMediumParameters_Request)
register_pldm_class(NegotiateMediumParameters_Response)
register_pldm_class(GetSchemaDictionary_Request)
register_pldm_class(GetSchemaDictionary_Response)
register_pldm_class(GetSchemaURI_Request)
register_pldm_class(GetSchemaURI_Response)
register_pldm_class(GetResourceETag_Request)
register_pldm_class(GetResourceETag_Response)

register_pldm_class(GetOEMCount_Request)
register_pldm_class(GetOEMCount_Response)
register_pldm_class(GetOEMName_Request)
register_pldm_class(GetOEMName_Response)
register_pldm_class(GetRegistryCount_Request)
register_pldm_class(GetRegistryCount_Response)
register_pldm_class(GetRegistryDetails_Request)
register_pldm_class(GetRegistryDetails_Response)
register_pldm_class(SelectRegistryVersion_Request)
register_pldm_class(SelectRegistryVersion_Response)
register_pldm_class(GetMessageRegistry_Request)
register_pldm_class(GetMessageRegistry_Response)
register_pldm_class(GetSchemaFile_Request)
register_pldm_class(GetSchemaFile_Response)

# RDE Commands
register_pldm_class(RDEOperationInit_Request)
register_pldm_class(RDEOperationInit_Response)
register_pldm_class(SupplyCustomRequestParameters_Request)
register_pldm_class(SupplyCustomRequestParameters_Response)
register_pldm_class(RetrieveCustomResponseParameters_Request)
register_pldm_class(RetrieveCustomResponseParameters_Response)
register_pldm_class(RDEOperationComplete_Request)
register_pldm_class(RDEOperationComplete_Response)
register_pldm_class(RDEOperationStatus_Request)
register_pldm_class(RDEOperationStatus_Response)
register_pldm_class(RDEOperationKill_Request)
register_pldm_class(RDEOperationKill_Response)
register_pldm_class(RDEOperationEnumerate_Request)
register_pldm_class(RDEOperationEnumerate_Response)

# Multipart Transfer Commands
register_pldm_class(MultipartSend_Request)
register_pldm_class(MultipartSend_Response)
register_pldm_class(MultipartReceive_Request)
register_pldm_class(MultipartReceive_Response)
