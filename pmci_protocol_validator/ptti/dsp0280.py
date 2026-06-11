# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
DSP0280 v1.1.0 packet definitions

File : dsp0280.py

Brief : Defines Scapy classes for DSP0280 v1.1.0 requests and responses.
"""

from scapy.fields import *
from scapy.packet import Packet
from pmci_protocol_validator.pldm.dsp0240_base import PLDM_HEADER


DSP0280_COMPLIANCE_VERSION = int.from_bytes([1, 1, 0, 0], 'big')
VERSION_COMPLIANCE = 0x11   # Compliant to spec DSP0280 version 1.1

PROTOCOL_TYPE = {
    0x00: "MCTP Control",
    0x01: "Platform Level Data Model",
    0x02: "NC-SI over MCTP",
    0x7E: "Vendor Defined - PCI",
    0x7F: "Vendor Defined - IANA",
    0xF1: "PTTI Vendor Defined Admin",
    0xFF: "PTTI Admin"
}

COMMAND_CODES = {
    0x00: "Connect",
    0x01: "Disconnect",
    0x02: "Query Admin Messages",
    0x10: "Query Capabilities",
    0x11: "Query Status",
    0x12: "Query System Inventory",
    0x13: "Query Partial System Inventory",
    0x20: "Configure Test Service",
    0x21: "Configure Device Under Test",
    0x22: "Register to Protocol",
    0x23: "Register Async Message Recipient",
    0x30: "Log Event"
}

MESSAGE_RESPONSE_CODES = {
    0x00: "SUCCESS",
    0x01: "TIMEOUT",
    0x02: "INVALID_PROTOCOL",
    0x03: "TRANSPORT_ERROR",
    0x04: "PHYSICAL_ERROR",
    0x05: "AUTHENTICATION_ERROR",
    0x06: "PRIVILEGE_ERROR",
    0x07: "INTEGRITY_CHECK_ERROR",
    0x08: "INCOMPATIBLE_VERSION",
    0x09: "INVALID_DUT_CONNECTION_ID",
    0x0A: "OUTSTANDING_MESSAGE",
    0x0B: "INVALID_PARAMETER",
    0x0C: "INSUFFICIENT_RESOURCES",
    0x0D: "COMMAND_NOT_SUPPORTED",
    0x0E: "PARAMETER_NOT_SUPPORTED",
    0x0F: "DUT_IN_USE",
    0x10: "INVALID_PROTOCOL_TYPE",
    0x11: "INVALID_FLAGS",
    0x12: "INVALID_TEST_CLIENT_ID",
    0x13: "INVALID_TRANSFER_LENGTH",
    0x14: "INVALID_COMMAND_CODE",
    0x7F: "UNSPECIFIED_ERROR",
    0xD0: "MISSING_API_FUNCTION",
    0xD1: "INVALID_POINTER",
    0xD2: "BUFFER_TOO_SMALL",
    0xD3: "INVALID_RESPONSE_PARMS"
}

# Dictionary of registered PTTI command and responses handlers
DMTF_PTTI_CLASSES = {}


def register_ptti_handler(cls, protocol=0xFF):
    """Helper function to register PTTI handlers"""

    cls.CommandValue
    Name = cls.__name__

    if "_Request" in Name:
        RequestFlag = 0

    elif "_Response" in Name:
        RequestFlag = 1

    else:
        assert False, "Class must be _Request or _Response: {} {}".format(hex(cls.CommandValue), Name)

    # Unique key is combination of requestFlag & CommandCode
    key = (RequestFlag << 8) + cls.CommandValue

    if key in DMTF_PTTI_CLASSES:
        assert False, "Duplicate Command: {} from {}".format(hex(cls.CommandValue), Name)

    DMTF_PTTI_CLASSES[key] = cls
    return


class TestServiceWrapper(Packet):
    """DSP0280 v1.1.0 Test Service Wrapper"""

    __test__ = False    # pytest: ignore class
    name = "PTTI Test Service Wrapper"

    fields_desc = [
        XByteField("Version", VERSION_COMPLIANCE),
        XByteEnumField("ProtocolType", 0xFF, PROTOCOL_TYPE),
        BitField("Reserved_0", 0x00, 6),
        BitEnumField(
            "Direction",
            0,
            2,
            {
                0: "TC to TS Request",
                1: "TS to TC Response",
                2: "TS to TC Request",
                3: "TC to TS Response"
            },
        ),
        BitField("Reserved_1", 0x00, 8),
        XLEIntField("TestClientID", 0x00000000),
        LEShortField("TransferLength", 0x0000),
        NBytesField("Reserved_2", 0, 6)
    ]

    def guess_payload_class(self, payload):
        """Determine payload class type """

        if self.ProtocolType == 0xF1:
            if self.Direction == 0:
                return VendorDefinedAdmin_Request
            else:
                return VendorDefinedAdmin_Response

        elif self.ProtocolType == 0xFF:
            key = (self.Direction << 8) + int(payload[0])

            if key in DMTF_PTTI_CLASSES:
                return DMTF_PTTI_CLASSES[key]

        else:
            if self.Direction == 0:
                return TestMessage_Request
            else:
                return TestMessage_Response

        return None

    def post_build(self, p, pay):
        """ Insert the payload length in the TSW """

        return p[:8] + struct.pack("<H", len(pay)) + p[10:] + pay


class Connect_Request(Packet):
    """DSP0280 Connect Request"""

    name = "PTTI Connect Request"
    CommandValue = 0x00

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        FieldLenField(
            "SecurityParameterLength",
            None,
            length_of="SecurityParameter",
            fmt="<I"
        ),
        XStrLenField(
            "SecurityParameter",
            b"",
            length_from=lambda pkt: pkt.SecurityParameterLength
        )
    ]


class Connect_Response(Packet):
    """DSP0280 Connect Response"""

    name = "PTTI Connect Response"
    CommandValue = Connect_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),

        ConditionalField(
            XByteField("TestServiceVersion", VERSION_COMPLIANCE),
            lambda pkt: pkt.ResponseCode == 0
        ),
        ConditionalField(
            XLEIntField("TestClientID", 0x00000000),
            lambda pkt: pkt.ResponseCode == 0
        )
    ]


class Disconnect_Request(Packet):
    """DSP0280 Disconnect Request"""

    name = "PTTI Disconnect Request"
    CommandValue = 0x01

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES)
    ]


class Disconnect_Response(Packet):
    """DSP0280 Disconnect Response"""

    name = "PTTI Disconnect Response"
    CommandValue = Disconnect_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES)
    ]


class QueryAdminMessages_Request(Packet):
    """DSP0280 Query Admin Messages Request"""

    name = "PTTI Query Admin Messages Request"
    CommandValue = 0x02

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES)
    ]


class QueryAdminMessages_Response(Packet):
    """DSP0280 Query Admin Messages Response"""

    name = "PTTI Query Admin Messages Response"
    CommandValue = QueryAdminMessages_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),
        StrFixedLenField("SupportedAdminMessages", b"", length=32)
    ]


class QueryCapabilities_Request(Packet):
    """DSP0280 Query Capabilities Request"""

    name = "PTTI Query Capabilities Request"
    CommandValue = 0x10

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES)
    ]


class TestServiceCapabilityEntry(Packet):
    """DSP0280 Test Service Capabilities table entry format"""

    __test__ = False    # pytest: ignore class
    name = "Test Service Capability Entry"

    fields_desc = [
        XLEShortField("CapabilityID", 0x0000),
        XLEIntField("CapabilityValue", 0x00000000)
    ]

    def extract_padding(self, s):
        return ("", s,)


class QueryCapabilities_Response(Packet):
    """DSP0280 Query Capabilities Response"""

    name = "PTTI Query Capabilities Response"
    CommandValue = QueryCapabilities_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),

        ConditionalField(
            XByteField("Reserved", 0x00),
            lambda pkt: pkt.ResponseCode == 0x0000
        ),
        ConditionalField(
            FieldLenField(
                "NumberOfCapabilitiesFields",
                None,
                count_of="TestServiceCapabilities",
                fmt="<H"
            ),
            lambda pkt: pkt.ResponseCode == 0
        ),
        ConditionalField(
            PacketListField(
                "TestServiceCapabilities",
                [],
                TestServiceCapabilityEntry,
                count_from=lambda pkt: pkt.NumberOfCapabilitiesFields
            ),
            lambda pkt: pkt.ResponseCode == 0
        )
    ]


class QueryStatus_Request(Packet):
    """DSP0280 Query Status Request"""

    name = "PTTI Query Status Request"
    CommandValue = 0x11

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        ByteEnumField(
            "QueryType",
            0,
            {
                0: "Ping",
                1: "Device List"
            }
        )
    ]


class QueryStatusDeviceData(Packet):
    """DSP0280 Query Status Device Data"""

    name = "Query Status Device Data"
    fields_desc = [
        ByteField("DeviceRegisteredProtocol", 0),
        ByteField("DeviceRegisteredProtocolType", 0),
        ByteField("AsyncRegisteredProtocolType", 0)
    ]

    def extract_padding(self, s):
        return ("", s,)


class QueryStatusDeviceEntry(Packet):
    """DSP0280 Query Status Device Entry"""

    fields_desc = [
        XLEIntField("DUTConnectionID", 0x00000000),
        FieldLenField(
            "DeviceRegisteredProtocolTypeCount",
            0,
            count_of="DeviceData",
            fmt="B"
       ),
        PacketListField(
            "DeviceData",
            [],
            QueryStatusDeviceData,
            count_from=lambda pkt: pkt.DeviceRegisteredProtocolTypeCount
        )
    ]

    def extract_padding(self, s):
        return ("", s,)


class QueryStatus_Response(Packet):
    """DSP0280 Query Status Response"""

    name = "PTTI Query Status Response"
    CommandValue = QueryStatus_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),

        ConditionalField(
            ByteEnumField(
                "QueryType",
                0,
                {
                    0: "Ping",
                    1: "Device List"
                }
            ),
            lambda pkt: pkt.ResponseCode == 0
        ),
        ConditionalField(
            LEIntField("QueryResponseDataLength", 0),
            lambda pkt: pkt.ResponseCode == 0
        ),
        ConditionalField(
            FieldLenField(
                "DeviceCount",
                0,
                count_of=lambda pkt: pkt.QueryStatusDeviceData,
                fmt="B"
            ),
            lambda pkt: pkt.QueryType == 1 and pkt.ResponseCode == 0
        ),
        ConditionalField(
            PacketListField(
                "QueryStatusDeviceData",
                [],
                QueryStatusDeviceEntry,
                count_from=lambda pkt: pkt.DeviceCount
            ),
            lambda pkt: pkt.QueryType == 1 and pkt.ResponseCode == 0 and pkt.DeviceCount > 0
        )
    ]


class QuerySystemInventory_Request(Packet):
    """DSP0280 Query System Inventory Request"""

    name = "PTTI Query System Inventory Request"
    CommandValue = 0x12

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES)
    ]


class QuerySystemInventory_Response(Packet):
    """DSP0280 Query System Inventory Response"""

    name = "PTTI Query System Inventory Response"
    CommandValue = QuerySystemInventory_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),

        ConditionalField(
            StrField("SystemInventory", None),
            lambda pkt: pkt.ResponseCode == 0
        )
    ]


class QueryPartialSystemInventory_Request(Packet):
    """DSP0280 Query Partial System Inventory Request"""

    name = "PTTI Query Partial System Inventory Request"
    CommandValue = 0x13

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        LEIntField("FragmentHandle", 0),
    ]


class QueryPartialSystemInventory_Response(Packet):
    """DSP0280 Query Partial System Inventory Response"""

    name = "PTTI Query Partial System Inventory Response"
    CommandValue = QueryPartialSystemInventory_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),

        ConditionalField(
            LEIntField("NextFragmentHandle", 0),
            lambda pkt: pkt.ResponseCode == 0
        ),
        ConditionalField(
            LEShortField("FragmentLength", 0),
            lambda pkt: pkt.ResponseCode == 0
        ),
        ConditionalField(
            StrField("SystemInventory", None),
            lambda pkt: pkt.ResponseCode == 0
        )
    ]


class ConfigureTestService_Request(Packet):
    """DSP0280 Configure Test Service Request"""

    name = "PTTI Configure Test Service Request"
    CommandValue = 0x20

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        FieldLenField(
            "NumberOfCapabilitiesFields",
            None,
            count_of="TestServiceCapabilities",
            fmt="<H"
        ),
        PacketListField(
            "TestServiceCapabilities",
            [],
            TestServiceCapabilityEntry,
            count_from=lambda pkt: pkt.NumberOfCapabilitiesFields,
        )
    ]


class ConfigureTestService_Response(Packet):
    """DSP0280 Configure Test Service Response"""

    name = "PTTI Configure Test Service Response"
    CommandValue = ConfigureTestService_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES)
    ]


class ConfigureDeviceUnderTest_Request(Packet):
    """DSP0280 Configure Device Under Test Request"""

    name = "PTTI Configure Device Under Test Request"
    CommandValue = 0x21

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XLEIntField("TargetIdentifier", 0x00000000),
        FieldLenField(
            "IdentifierCount",
            0,
            "IdentifierList",
            "B",
        ),
        FieldListField(
            "IdentifierList",
            [],
            XLEIntField("", 0x00000000),
            count_from=lambda pkt: pkt.IdentifierCount
        )
    ]


class ConfigureDeviceUnderTest_Response(Packet):
    """DSP0280 Configure Device Under Test Response"""

    name = "PTTI Configure Device Under Test Response"
    CommandValue = ConfigureDeviceUnderTest_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),


        ConditionalField(
            XLEIntField("DUTConnectionID", 0x00000000),
            lambda pkt: pkt.ResponseCode == 0
        ),
        ConditionalField(
            FieldLenField(
                "IdentifierCount",
                0,
                "IdentifierList",
                "B",
            ),
            lambda pkt: pkt.ResponseCode == 0
        ),
        ConditionalField(
            FieldListField(
                "IdentifierList",
                [],
                XLEIntField("", 0x00000000),
                count_from=lambda pkt: pkt.IdentifierCount
            ),
            lambda pkt: pkt.ResponseCode == 0
        )
    ]


class RegisterToProtocol_Request(Packet):
    """DSP0280 Register to Protocol Request"""

    name = "PTTI Register To Protocol Request"
    CommandValue = 0x22

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        ByteEnumField("ProtocolType", 0, PROTOCOL_TYPE),
        XLEIntField("DUTConnectionID", 0x00000000),
        FieldLenField(
            "TypeCount",
            0,
            "TypeList",
            fmt="B",
        ),
        FieldListField(
            "TypeList",
            [],
            ByteField("", 0x00),
            count_from=lambda pkt: pkt.TypeCount
        )
    ]


class RegisterToProtocol_Response(Packet):
    """DSP0280 Register to Protocol Response"""

    name = "PTTI Register To Protocol Response"
    CommandValue = RegisterToProtocol_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),

        ConditionalField(
            XLEIntField("DUTConnectionID", 0x00000000),
            lambda pkt: pkt.ResponseCode == 0
        )
    ]


class RegisterAsyncMessageRecipient_Request(Packet):
    """DSP0280 Register Async Message Recipient Request"""

    name = "PTTI Register Async Message Recipient Request"
    CommandValue = 0x23

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        ByteEnumField("ProtocolType", 0, PROTOCOL_TYPE),
        XLEIntField("DUTConnectionID", 0x00000000),
        FieldLenField(
            "TypeCount",
            0,
            "TypesList",
            fmt="B",
        ),
        FieldListField(
            "TypeList",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.TypeCount
        )
    ]


class RegisterAsyncMessageRecipient_Response(Packet):
    """DSP0280 Register Async Message Recipient Response"""

    name = "PTTI Register Async Message Recipient Response"
    CommandValue = RegisterAsyncMessageRecipient_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),

        ConditionalField(
            XLEIntField("DUTConnectionID", 0x00000000),
            lambda pkt: pkt.ResponseCode == 0
        )
    ]


class LogEvent_Request(Packet):
    """DSP0280 Log Event Request"""

    name = "PTTI Log Event Request"
    CommandValue = 0x30

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        ByteEnumField(
            "ReasonCode",
            0,
            {
                1: "CorruptMessage",
                2: "ClientTimeout",
                3: "WatchdogTimeout",
            }
        ),
        ByteEnumField(
            "LogDataFormat",
            0,
            {
                0: "Binary",
                1: "ASCII",
                2: "UTF8",
                3: "UTF-16",
                4: "UTF-16LE",
                5: "UTF-16BE",
            }
        ),
        FieldLenField(
            "LogDataLength",
            0,
            "LogData",
            "<I",
        ),
        FieldListField(
            "LogData",
            [],
            XByteField("", 0x00),
            length_from=lambda pkt: pkt.LogDataLength
        )
    ]


class LogEvent_Response(Packet):
    """DSP0280 Log Event Response"""

    name = "PTTI Log Event Response"
    CommandValue = LogEvent_Request.CommandValue

    fields_desc = [
        XByteEnumField("CommandCode", CommandValue, COMMAND_CODES),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),
    ]


class VendorDefinedAdmin_Request(Packet):
    """DSP0280 Vendor Defined Admin Request"""

    name = "PTTI Vendor Defined Admin Request"
    CommandValue = 0xF1

    fields_desc = [
        XLEIntField("IANA", 0x00000000)
    ]


class VendorDefinedAdmin_Response(Packet):
    """DSP0280 Vendor Defined Admin Response"""

    name = "PTTI Vendor Defined Admin Response"
    CommandValue = VendorDefinedAdmin_Request.CommandValue

    fields_desc = [
        XLEIntField("IANA", 0x00000000),
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),
    ]


class TestMessage_Request(Packet):
    """DSP0280 Test Messages Request"""
    __test__ = False    # pytest: ignore class

    name = "PTTI Test Message Request"
    CommandValue = 0xF7

    fields_desc = [
        XLEIntField("DUTConnectionID", 0x00000000),
        XLEIntField("MaximumWaitTime", 0),
    ]

    def guess_payload_class(self, payload):
        """ Determine payload class for protocol test message requests. """

        tsw = getattr(self, "underlayer", None)
        while tsw is not None and not isinstance(tsw, TestServiceWrapper):
            tsw = getattr(tsw, "underlayer", None)

        # Decode PLDM when carried inside a PTTI TestMessage.
        if tsw is not None and tsw.ProtocolType == 0x01:
            return PLDM_HEADER

        return None


class TestMessage_Response(Packet):
    """DSP0280 Test Messages Response"""
    __test__ = False    # pytest: ignore class

    name = "PTTI Test Message Response"
    CommandValue = TestMessage_Request.CommandValue

    fields_desc = [
        XByteEnumField("ResponseCode", 0x00, MESSAGE_RESPONSE_CODES),

        ConditionalField(
            XLEIntField("DUTConnectionID", 0x00000000),
            lambda pkt: pkt.ResponseCode == 0
        ),
        ConditionalField(
            XLEIntField("ElapsedTime", 0),
            lambda pkt: pkt.ResponseCode == 0
        )
    ]

    def guess_payload_class(self, payload):
        """ Determine payload class for protocol test message responses. """

        tsw = getattr(self, "underlayer", None)
        while tsw is not None and not isinstance(tsw, TestServiceWrapper):
            tsw = getattr(tsw, "underlayer", None)

        # Decode PLDM when carried inside a PTTI TestMessage.
        if tsw is not None and tsw.ProtocolType == 0x01:
            return PLDM_HEADER

        return None


# Register command and response handlers
register_ptti_handler(Connect_Request)
register_ptti_handler(Connect_Response)
register_ptti_handler(Disconnect_Request)
register_ptti_handler(Disconnect_Response)
register_ptti_handler(QueryAdminMessages_Request)
register_ptti_handler(QueryAdminMessages_Response)
register_ptti_handler(QueryCapabilities_Request)
register_ptti_handler(QueryCapabilities_Response)
register_ptti_handler(QueryStatus_Request)
register_ptti_handler(QueryStatus_Response)
register_ptti_handler(QuerySystemInventory_Request)
register_ptti_handler(QuerySystemInventory_Response)
register_ptti_handler(QueryPartialSystemInventory_Request)
register_ptti_handler(QueryPartialSystemInventory_Response)
register_ptti_handler(ConfigureTestService_Request)
register_ptti_handler(ConfigureTestService_Response)
register_ptti_handler(ConfigureDeviceUnderTest_Request)
register_ptti_handler(ConfigureDeviceUnderTest_Response)
register_ptti_handler(RegisterToProtocol_Request)
register_ptti_handler(RegisterToProtocol_Response)
register_ptti_handler(RegisterAsyncMessageRecipient_Request)
register_ptti_handler(RegisterAsyncMessageRecipient_Response)
register_ptti_handler(LogEvent_Request)
register_ptti_handler(LogEvent_Response)
register_ptti_handler(VendorDefinedAdmin_Request)
register_ptti_handler(VendorDefinedAdmin_Response)
register_ptti_handler(TestMessage_Request)
register_ptti_handler(TestMessage_Response)
