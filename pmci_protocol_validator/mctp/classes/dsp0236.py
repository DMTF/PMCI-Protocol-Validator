# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Wrapper for MCTP Header based on DSP0236 and the MCTP Control commands

File : dsp0236.py

Brief : Wrapper for MCTP Header based on DSP0236 and the MCTP Control commands
"""

import struct
from scapy.all import *
from scapy.fields import *
from scapy.packet import Packet

from pmci_protocol_validator.ncsi.classes.dsp0222 import NCSI_HEADER, validateRegisteredClass
from pmci_protocol_validator.pldm.classes.dsp0240 import PLDM_HEADER
from pmci_protocol_validator.mctp.classes.dsp0239 import MCTP_MESSAGE_TYPES

DSP0236_COMPLIANCE_VERSION = int.from_bytes([1, 3, 1, 0], 'big')

DMTF_MCTP_COMMANDS = {}     # Dictionary of the MCTP Command for DMTF commands

COMPLETION_CODES = {
    0x00: "SUCCESS",
    0x01: "ERROR",
    0x02: "ERROR_INVALID_DATA",
    0x03: "ERROR_INVALID_LENGTH",
    0x04: "ERROR_NOT_READY",
    0x05: "ERROR_UNSUPPORTED_CMD",
}


def register_mctp_control_class(cls):
    """helper to register a MCTP_CONTROL_PAYLOAD class. If the class
    name contains '_Request' then it will be registered as a Request
    otherwise as a Response
    """
    CommandVal = cls.CommandValue
    Name = cls.__name__

    if "_Request" in Name:
        rqBit = 1

    elif "_Response" in Name:
        rqBit = 0

    else:
        assert False, "MCTP Control classes must be _Request or _Response: {} {}".format(
            hex(CommandVal), Name
        )

    # Unique key is Rq bit, Payload Type and Command combination
    key = (rqBit << 8) + CommandVal
    if key in DMTF_MCTP_COMMANDS:
        assert False, "Duplicate MCTP Command: {} from {}".format(hex(CommandVal), Name)

    DMTF_MCTP_COMMANDS[key] = cls

    # quick check to make sure it is a valid packet
    validateRegisteredClass(cls)


class MCTP_MESSAGE_TYPE(Packet):
    """DSP0236 MCTP message type"""

    name = "MCTP Message Type"

    fields_desc = [
        BitEnumField("IntegrityCheck", 0, 1, {0: "Disabled", 1: "Enabled"}),
        BitEnumField("MessageType", 0, 7, MCTP_MESSAGE_TYPES)
    ]


class MCTP_HEADER(Packet):
    """DSP0236 MCTP Header Layer"""

    name = "MCTP Header"

    fields_desc = [
        BitField("MctpHeaderReserved_1", 0x0, 4),
        BitField("HeaderVersion", 0x1, 4),
        XByteField("DestinationEID", 0x00),
        XByteField("SourceEID", 0x00),
        XBitField("SOM", 1, 1),
        XBitField("EOM", 1, 1),
        XBitField("PacketSequenceNumber", 0, 2),
        XBitField("TagOwner", 1, 1),
        XBitField("MessageTag", 0, 3)
    ]


class MCTP_COMMAND_HEADER(Packet):
    """DSP0236 MCTP Control Packet Header"""

    PayloadType = 0x00  # all control commands are MCTP Message type 0
    name = "MCTP Control Header"

    fields_desc = [
        BitField("Request", 0x0, 1),
        BitField("Datagram", 0x0, 1),
        BitField("MctpControlReserved_1", 0x0, 1),
        BitField("InstanceID", 0x0, 5),
        XByteField("CommandCode", 0x00)  # set by CommandValue in payload class
    ]

    def _updateCommandAndRq(self, pkt):
        """Some of the fields in the MCTP Control header need to be filled
        out based upon the information that comes from the payload
        such as if it is a request, Payload Type and the command
        """
        if (
            "_Request" in type(self.payload).__name__
        ):  # does class have _Request in name
            rqBit = 1
        else:
            rqBit = 0
        self.Request = rqBit

        (currVal,) = struct.unpack("B", bytes([pkt[0]]))
        rqBit = rqBit << 7
        currVal = currVal & 0x7F  # clear Rq bit
        firstByte = currVal + rqBit  # only twiddle rqbit, if set
        encodedFirstByte = struct.pack("B", firstByte)

        self.CommandCode = self.payload.CommandValue
        encodedCommand = struct.pack("B", self.payload.CommandValue)

        return encodedFirstByte + encodedCommand

    def guess_payload_class(self, payload):
        """not 1 key to differentiate payloads, so this routine
        is called to make more complicted determination
        """
        key = (
            self.Request << 8
        ) + self.CommandCode  # watch the order of operations

        # now go look in registered commands
        if key in DMTF_MCTP_COMMANDS:
            return DMTF_MCTP_COMMANDS[key]

        # not there (which should not happen) so call default
        return Packet.get_payload_class(self, payload)

    def post_build(self, pkt, pay):
        """called by SCAPY framework, this is where
        the command is retrieved from the payload and put
        into the header
        """
        pkt = self._updateCommandAndRq(pkt)

        return pkt + pay


class MCTP_COMMAND(Packet):
    pass


class PhysicalAddressPCIe(Packet):
    """PCIe VDM physical address fields"""

    name = "PCIe VDM physical address fields"
    fields_desc = [
        XByteField("BDFBusNumber", 0x00),
        BitField("BDFFunctionNumber", 0, 3),
        BitField("BDFDeviceNumber", 0, 5),
        XByteField("ARIBusNumber", 0x00),
        XByteField("ARIFunctionNumber", 0x00)
    ]


class MCTP_UUID(Packet):
    """UUID format. This is the PLDM V1.0 format per DSP0236."""

    name = "UUID"
    UUID_NODE_LEN = 6
    fields_desc = [
        XIntField("TimeLow", 0x00000000),
        XShortField("TimeMid", 0x0000),
        XShortField("TimeHighAndVersion", 0x0000),
        XByteField("ClockSeqHighAndReserved", 0x00),
        XByteField("ClockSeqLow", 0x00),
        scapy.layers.l2.DestMACField(
            "Node"
        )  # it may not be a MAC, but is 6 bytes so this works well
    ]

    def extract_padding(self, s):
        return ("", s)


class SetEndpointID_Request(MCTP_COMMAND):
    """DSP0236 Set Endpoint ID Request"""

    name = "Set Endpoint ID Request"
    CommandValue = 0x01

    fields_desc = [
        BitField("SetEndpointID_Reserved_1", 0, 6),
        BitEnumField(
            "Operation",
            0,
            2,
            {0: "SetEID", 1: "ForceEID", 2: "ResetEID", 3: "SetDiscoveredFlag"},
        ),
        XByteField("EndpointID", 0x00)
    ]


class SetEndpointID_Response(MCTP_COMMAND):
    """DSP0236 Set Endpoint ID Response"""

    name = "Set Endpoint ID Response"
    CommandValue = 0x01

    class Data(Packet):
        fields_desc = [
            BitField("SetEndpointID_Reserved_1", 0, 2),
            BitEnumField(
                "AssignmentStatus",
                0,
                2,
                {
                    0: "EidAssignmentAccepted",
                    1: "EidAssignmentRejected",
                    2: "Reserved",
                    3: "Reserved",
                },
            ),
            BitField("SetEndpointID_Reserved_2", 0, 2),
            BitEnumField(
                "AllocationStatus",
                0,
                2,
                {
                    0: "Device does not use EID Pool",
                    1: "Endpoint requires EID Pool allocation",
                    2: "Endpoint uses an EID pool and has already received an allocation for that pool",
                    3: "Reserved",
                },
            ),
            XByteField("EidSetting", 0x00),
            XByteField("EidPoolSize", 0x00)
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            PacketField("ResponseData", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetEndpointID_Request(MCTP_COMMAND):
    """DSP0236 Get Endpoint ID Request"""

    name = "Get Endpoint ID Request"
    CommandValue = 0x02


class GetEndpointID_Response(MCTP_COMMAND):
    """DSP0236 Get Endpoint ID Response"""

    name = "Get Endpoint ID Response"
    CommandValue = 0x02

    class Data(Packet):
        fields_desc = [
            XByteField("EndpointID", 0x00),
            BitField("GetEndpointID_Reserved_1", 0, 2),
            BitEnumField(
                "EndpointType",
                0,
                2,
                {
                    0: "Simple Endpoint",
                    1: "Bus owner/bridge",
                    2: "Reserved",
                    3: "Reserved"},
            ),
            BitField("GetEndpointID_Reserved_2", 0, 2),
            BitEnumField(
                "EndpointIdType",
                0,
                2,
                {
                    0: "Dynamic EID",
                    1: "Only Static EID Supported",
                    2: "Static EID Supported - present EID matches Static",
                    3: "Static EID Supported - present EID does not match Static",
                },
            ),
            XByteField("MediumSpecificInformation", 0x00)
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            PacketField("ResponseData", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetEndpointUUID_Request(MCTP_COMMAND):
    """DSP0236 Get Endpoint UUID Request"""

    name = "Get Endpoint UUID Request"
    CommandValue = 0x03


class GetEndpointUUID_Response(MCTP_COMMAND):
    """DSP0236 Get Endpoint UUID Response"""

    name = "Get Endpoint UUID Response"
    CommandValue = 0x03

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            PacketField("UUID", MCTP_UUID(), MCTP_UUID),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetMCTPVersionSupport_Request(MCTP_COMMAND):
    """DSP0236 Get MCTP Version Support Request"""

    name = "Get MCTP Version Support Request"
    CommandValue = 0x04

    fields_desc = [
        XByteEnumField(
            "MessageTypeNumber",
            0x00,
            {
                0xFF: "Return MCTP base specification version information",
                0x7E: "Unspecified. Support of this command for vendor-defined message types is vendor implementation-specific and considered outside the scope of this specification",
                0x7F: "Unspecified. Support of this command for vendor-defined message types is vendor implementation-specific and considered outside the scope of this specification",
                0x00: "Return MCTP control protocol message version information",
                0x01: "return version of DSP0241",
                0x02: "return version of DSP0261",
                0x03: "return version of DSP0261",
            },
        )
    ]


class VersionNumberEntry(Packet):
    """MCTP Version Number Entry"""

    name = "Version number Entry"

    fields_desc = [
        XByteField("MajorVersionNumber", 0x00),
        XByteField("MinorVersionNumber", 0x00),
        XByteField("UpdateVersionNumber", 0x00),
        XByteField("AlphaByte", 0x00)
    ]

    def extract_padding(self, s):
        return ("", s)


class GetMCTPVersionSupport_Response(MCTP_COMMAND):
    """DSP0236 Get MCTP Version Support Response"""

    name = "Get MCTP Version Support Response"
    CommandValue = 0x04

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            ByteField("VersionNumberEntryCount", 0),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            PacketListField(
                "VersionNumberEntries",
                VersionNumberEntry(),
                VersionNumberEntry,
                count_from=lambda pkt: pkt.VersionNumberEntryCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetMessageTypeSupport_Request(MCTP_COMMAND):
    """DSP0236 Get Message Type Support Request"""

    name = "Get Message Type Support Request"
    CommandValue = 0x05


class GetMessageTypeSupport_Response(MCTP_COMMAND):
    """DSP0236 Get Message Type Support Response"""

    name = "Get Message Type Support Response"
    CommandValue = 0x05

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            XByteField("MCTPMessageTypeCount", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            FieldListField(
                "ListOfMessageTypes",
                [],
                XByteField("", 0x00),
                count_from=lambda pkt: pkt.MCTPMessageTypeCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetVendorDefinedMessageSupport_Request(MCTP_COMMAND):
    """DSP0236 Get Vendor Defined Message Support Request"""

    name = "Get Vendor Defined Message Support Request"
    CommandValue = 0x06

    fields_desc = [
        XByteField("VendorIDSetSelector", 0x00)
    ]


class GetVendorDefinedMessageSupport_Response(MCTP_COMMAND):
    """DSP0236 Get Vendor Defined Message Support Response"""

    name = "Get Vendor Defined Message Support Response"
    CommandValue = 0x06

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            XByteField("VendorIDSetSelector", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            XByteField("VendorID", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            XShortField("PCIVendorID", 0x0000),
            lambda pkt: pkt.CompletionCode == 0 and pkt.VendorID == 0x00
        ),

        ConditionalField(
            XIntField("IANAEnterpriseNumber", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0 and pkt.VendorID == 0x01
        ),

        ConditionalField(
            XShortField("VendorSpecific", 0x0000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class ResolveEndpointID_Request(MCTP_COMMAND):
    """DSP0236 Resolve Endpoint ID Request"""

    name = "Resolve Endpoint ID Request"
    CommandValue = 0x07

    fields_desc = [
        XByteField("TargetEndpointID", 0x00)
    ]


class ResolveEndpointID_Response(MCTP_COMMAND):
    """DSP0236 Resolve Endpoint ID Response"""

    name = "Resolve Endpoint ID Response"
    CommandValue = 0x07

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            XByteField("BridgeEndpointID", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            MultipleTypeField(
                [
                    (
                        XByteField("PhysicalAddress", 0x00),
                        lambda pkt: hasattr(pkt.underlayer, "MessageType")
                        and pkt.underlayer.MessageType == 0x01,
                    ),
                    (
                        PacketListField(
                            "PhysicalAddress",
                            PhysicalAddressPCIe(),
                            PhysicalAddressPCIe
                        ),
                        lambda pkt: hasattr(pkt.underlayer, "MessageType")
                        and pkt.underlayer.MessageType == 0x02,
                    ),
                ],
                XByteField("PhysicalAddress", 0x00),  # Default field
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class AllocateEndpointIDs_Request(MCTP_COMMAND):
    """DSP0236 Allocate Endpoint ID Request)"""

    name = "Allocate Endpoint ID Request"
    CommandValue = 0x08

    fields_desc = [
        BitField("OperationFlags_0", 0, 6),
        BitEnumField(
            "OperationFlags_1",
            0,
            2,
            {
                0b00: "Allocate EIDs",
                0b01: "Force Allocation",
                0b10: "Get allocation information",
                0b11: "Reserved",
            },
        ),
        XByteField("NumberOfEndpointIDs", 0x00),
        XByteField("StartingEndpointID", 0x00)
    ]


class AllocateEndpointIDs_Response(MCTP_COMMAND):
    """DSP0236 Allocate Endpoint ID Response"""

    name = "Allocate Endpoint ID Response"
    CommandValue = 0x08

    class Data(Packet):
        fields_desc = [
            BitField("Reserved", 0, 6),
            BitEnumField(
                "Allocations",
                0,
                2,
                {
                    0b00: "Allocation was accepted",
                    0b01: "Allocation was rejected",
                    0b10: "Reserved",
                    0b11: "Reserved",
                },
            ),
            XByteField("EndpointIDPoolSize", 0x00),
            XByteField("FirstEndpointID", 0x00)
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            PacketField("ResponseData", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class RoutingInformationFields(Packet):
    """"DSP0236 Fields for Routing Information entries"""

    name = "Fields for entries"

    fields_desc = [
        BitField("Reserved", 0, 4),
        BitEnumField(
            "EntryType",
            0,
            4,
            {
                0b00: "entry corresponds to a single endpoint that is not serving as an MCTP bridge",
                0b01: "entry reflects an EID range for a bridge where the starting EID is the EID of the bridge itself and additional EIDs in the range are routed by the bridge",
                0b10: "entry is for a single endpoint that is serving as an MCTP bridge",
                0b11: "entry is an EID range for a bridge, but does not include the EID of the bridge itself",
            },
        ),
        XByteField("SiezeOfEIDRange", 0x00),
        XByteField("FirstEIDinEIDRange", 0x00),
        MultipleTypeField(
            [
                (
                    XByteField("PhysicalAddress", 0x00),
                    lambda pkt: hasattr(pkt.underlayer, "MessageType")
                    and pkt.underlayer.MessageType == 0x01,
                ),
                (
                    PacketListField(
                        "PhysicalAddress",
                        PhysicalAddressPCIe(),
                        PhysicalAddressPCIe
                    ),
                    lambda pkt: hasattr(pkt.underlayer, "MessageType")
                    and pkt.underlayer.MessageType == 0x02,
                ),
            ],
            XByteField("PhysicalAddress", 0x00),  # Default field
        )
    ]


class RoutingInformationUpdate_Request(MCTP_COMMAND):
    """DSP0236 Routing Information Update Request"""

    name = "Routing Information Update Request"
    CommandValue = 0x09

    fields_desc = [
        XByteField("CountOfUpdatedEntries", 0x00),
        PacketListField(
            "UpdatedEntries",
            RoutingInformationFields(),
            RoutingInformationFields,
            count_from=lambda pkt: pkt.CountOfUpdatedEntries,
        )
    ]


class RoutingInformationUpdate_Response(MCTP_COMMAND):
    """DSP0236 Routing Information Update Response"""

    name = "Routing Information Update Response"
    CommandValue = 0x09

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES)
    ]


class GetRoutingTableEntries_Request(MCTP_COMMAND):
    """DSP0236 Get Routing Table Entries Request"""

    name = "Get Routing Table Entries Request"
    CommandValue = 0x0A

    fields_desc = [
        XByteField("EntryHandle", 0x00)
    ]


class RoutingTableEntry(Packet):
    """DSP0236 Routing Table Entry"""

    name = "Routing Table Entry fields"

    fields_desc = [
        XByteField("SizeOfEID", 0x00),
        XByteField("StartingEID", 0x00),
        BitEnumField(
            "EntryType",
            0,
            2,
            {
                0b00: "entry corresponds to a single endpoint that does not operate as an MCTP bridge",
                0b01: "entry reflects an EID range for a bridge where the starting EID is the EID of the bridge itself "
                "and additional EIDs in the range are routed by the bridge",
                0b10: "entry is for a single endpoint that serves as an MCTP bridge",
                0b11: "entry is an EID range for a bridge, but does not include the EID of the bridge itself",
            },
        ),
        BitEnumField(
            "DynamicStaticEntry",
            0,
            1,
            {0: "Entry was dynamically created", 1: "Entry was statically configured"},
        ),
        BitField("PortNumber", 0, 5),
        XByteField("PhysicalTransportBindingIdentifier", 0x00),
        XByteField("PhysicalMediaTypeIdentifier", 0x00),
        XByteField("PhysicalAddressSize", 0x00),
        MultipleTypeField(
            [
                (
                    XByteField("PhysicalAddress", 0x00),
                    lambda pkt: hasattr(pkt.underlayer, "MessageType")
                    and pkt.underlayer.MessageType == 0x01,
                ),
                (
                    PacketListField(
                        "PhysicalAddress",
                        PhysicalAddressPCIe(),
                        PhysicalAddressPCIe
                    ),
                    lambda pkt: hasattr(pkt.underlayer, "MessageType")
                    and pkt.underlayer.MessageType == 0x02,
                ),
            ],
            XByteField("PhysicalAddress", 0x00),  # Default field
        )
    ]


class GetRoutingTableEntries_Response(MCTP_COMMAND):
    """DSP0236 Get Routing Table Entries Response"""

    name = "Get Routing Table Entries Response"
    CommandValue = 0x0A

    class Data(Packet):
        fields_desc = [
            XByteField("NextEntryHandle", 0x00),
            XByteField("NumberOfRoutingTableEntries", 0x00),
            PacketListField(
                "RoutingTableEntries",
                RoutingTableEntry(),
                RoutingTableEntry,
                count_from=lambda pkt: pkt.NumberOfRoutingTableEntries,
            )
    ]

    def extract_padding(self, s):
        return ("", s)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            PacketField("ResponseData", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]



class PrepareForEndpointDiscovery_Request(MCTP_COMMAND):
    """DSP0236 Prepare For Endpoint Discovery Request"""

    name = "Prepare For Endpoint Discovery Request"
    CommandValue = 0x0B


class PrepareForEndpointDiscovery_Response(MCTP_COMMAND):
    """DSP0236 Prepare For Endpoint Discovery Response"""

    name = "Prepare For Endpoint Discovery Response"
    CommandValue = 0x0B

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES)
    ]


class EndpointDiscovery_Request(MCTP_COMMAND):
    """DSP0236 Endpoint Discovery Request"""

    name = "Endpoint Discovery Request"
    CommandValue = 0x0C


class EndpointDiscovery_Response(MCTP_COMMAND):
    """DSP0236 Endpoint Discovery Response"""

    name = "Endpoint Discovery Response"
    CommandValue = 0x0C

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES)
    ]


class DiscoveryNotify_Request(MCTP_COMMAND):
    """DSP0236 Discovery Notify Request)"""

    name = "Discovery Notify Request"
    CommandValue = 0x0D


class DiscoveryNotify_Response(MCTP_COMMAND):
    """DSP0236 Discovery Notify Response"""

    name = "Discovery Notify Response"
    CommandValue = 0x0D

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES)
    ]


class GetNetworkID_Request(MCTP_COMMAND):
    """DSP0236 Get Network ID Request"""

    name = "Get Network ID Request"
    CommandValue = 0x0E


class GetNetworkID_Response(MCTP_COMMAND):
    """DSP0236 Get Network ID Response"""

    name = "Get Network ID Response"
    CommandValue = 0x0E

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            PacketField("NetworkIDBytes", MCTP_UUID(), MCTP_UUID),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class QueryHop_Request(MCTP_COMMAND):
    """DSP0236 Query Hop Request"""

    name = "Query Hop Request"
    CommandValue = 0x0F

    fields_desc = [
        XByteField("TargetEndpointID", 0x00),
        XByteField("MessageType", 0x00)
    ]


class QueryHop_Response(MCTP_COMMAND):
    """DSP0236 Query Hop Response"""

    name = "Query Hop Response"
    CommandValue = 0x0F

    class Data(Packet):
        fields_desc = [
            XByteField("EIDOfTheNextBridge", 0x00),
            XByteField("MessageType", 0x00),
            XShortField("MaximumSupportedIncomingTransmission", 0x0000),
            XShortField("MaximumSupportedOutgoingTransmission", 0x0000)
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            PacketField("ResponseData", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]

class ResolveUUID_Request(MCTP_COMMAND):
    """DSP0236 Resolve UUID Request"""

    name = "Resolve UUID Request"
    CommandValue = 0x10

    fields_desc = [
        XIntField("RequestedUUID_0", 0x00000000),
        XIntField("RequestedUUID_1", 0x00000000),
        XIntField("RequestedUUID_2", 0x00000000),
        XIntField("RequestedUUID_3", 0x00000000),
        XByteField("EntryHandle", 0x00)
    ]


class ResolveUUIDMessageEntry(Packet):
    """DSP0236 Resolve UUID Message Entry"""

    name = "Resolve UUID Message Entry"

    fields_desc = [
        XByteField("EID", 0x00),
        XByteField("PhysicalTransportBindingIdentifier", 0x00),
        XByteField("PhysicalMediaTypeIdentifier", 0x00),
        XByteField("PhysicalAddressSize", 0x00),
        MultipleTypeField(
            [
                (
                    XByteField("PhysicalAddress", 0x00),
                    lambda pkt: hasattr(pkt.underlayer, "MessageType")
                    and pkt.underlayer.MessageType == 0x01,
                ),
                (
                    PacketListField(
                        "PhysicalAddress",
                        PhysicalAddressPCIe(),
                        PhysicalAddressPCIe
                    ),
                    lambda pkt: hasattr(pkt.underlayer, "MessageType")
                    and pkt.underlayer.MessageType == 0x02,
                ),
            ],
            XByteField("PhysicalAddress", 0x00),  # Default field
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class ResolveUUID_Response(MCTP_COMMAND):
    """DSP0236 Resolve UUID Response"""

    name = "Resolve UUID Response"
    CommandValue = 0x10

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            XByteField("NextEntryHandle", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            XByteField("NumberOfEIDEntries", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            PacketListField(
                "ResolveUUIDMessageEntries",
                ResolveUUIDMessageEntry(),
                ResolveUUIDMessageEntry,
                count_from=lambda pkt: pkt.NumberOfEIDEntries,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class QueryRateLimit_Request(MCTP_COMMAND):
    """DSP0236 Query Rate Limit Request"""

    name = "Query Rate Limit Request"
    CommandValue = 0x11


class QueryRateLimit_Response(MCTP_COMMAND):
    """DSP0236 Query Rate Limit Response"""

    name = "Query Rate Limit Response"
    CommandValue = 0x11

    class Data(Packet):
        fields_desc = [
            XIntField("ReceiveBufferSizesInBytes", 0x00000000),
            XIntField("ReceiveDataRateLimit", 0x00000000),
            XIntField("MaximumSupportedRateLimit", 0x00000000),
            XIntField("MinimumSupportedRateLimit", 0x00000000),
            X3BytesField("MaximumSupportedBurstSize", 0x000000),
            X3BytesField("MaximalBurstSizeAllowed", 0x000000),
            XIntField("EIDMaximalTransmitDataRateLimit", 0x00000000),
            BitField("Reserved", 0, 6),
            BitEnumField(
                "TransmitRateLimitingOperationCapability",
                0,
                1,
                {
                    0: "Transmit Rate limiting on this EID is applied to requested and nonrequested messages together",
                    1: "Transmit Rate limiting on this EID is applied only to non-requested messages",
                },
            ),
            BitEnumField(
                "RateLimitingSupportOnEID",
                0,
                1,
                {
                    0: "Transmit Rate limiting is not supported",
                    1: "Transmit Rate limiting is supported",
                },
            )
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            PacketField("ResponseData", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]

class TXRateLimit_Request(MCTP_COMMAND):
    """DSP0236 TX Rate Limit Request"""

    name = "TX Rate Limit Request"
    CommandValue = 0x12

    fields_desc = [
        XIntField("EIDTransmitMaximalBurstSizeInMCTPPackets", 0x00000000),
        XIntField("EIDMaximalTransmitDataRateLimit", 0x00000000)
    ]


class TXRateLimit_Response(MCTP_COMMAND):
    """DSP0236 TX Rate Limit Response"""

    name = "TX Rate Limit Response"
    CommandValue = 0x12

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            XIntField("EIDTransmitMaximalBurstSizeInMCTPPackets", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            XIntField("EIDMaximalTransmitDataRateLimit", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class UpdateRateLimit_Request(MCTP_COMMAND):
    """DSP0236 Update Rate Limit Request"""

    name = "Update Rate Limit Request"
    CommandValue = 0x13

    fields_desc = [
        XIntField("EIDTransmitMaximalBurstSizeInMCTPPackets", 0x00000000),
        XIntField("EIDMaximalTransmitDataRateLimit", 0x00000000)
    ]


class UpdateRateLimit_Response(MCTP_COMMAND):
    """DSP0236 Update Rate Limit Response"""

    name = "Update Rate Limit Response"
    CommandValue = 0x13

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES)
    ]


class QuerySupportedInterfaces_Request(MCTP_COMMAND):
    """DSP0236 Query Supported Interfaces Request"""

    name = "Query Supported Interfaces Request"
    CommandValue = 0x14


class SupportedInterfacesFields(Packet):
    """Fields for supported Interfaces"""

    name = "Fields for supported Interfaces"

    fields_desc = [
        XByteField("InterfaceType", 0x00),
        XByteField("InterfaceEID", 0x00)
    ]


class QuerySupportedInterfaces_Response(MCTP_COMMAND):
    """DSP0236 Query Supported Interfaces Response"""

    name = "Query Supported Interfaces Response"
    CommandValue = 0x14

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES),

        ConditionalField(
            XByteField("SupportedInterfacesCount", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            PacketListField(
                "SupportedInterfacesEntries",
                SupportedInterfacesFields(),
                SupportedInterfacesFields,
                count_from=lambda pkt: pkt.SupportedInterfacesCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class TestUnsupportedMctp_Request(MCTP_COMMAND):
    """Unsupported MCTP Command Request packet for testing"""

    __test__ = False    # pytest: ignore class
    name = "Unsupported MCTP Command Request"
    CommandValue = 0xF2


class TestUnsupportedMctp_Response(MCTP_COMMAND):
    """Unsupported MCTP Command Request packet for testing"""

    __test__ = False    # pytest: ignore class
    name = "Test Unsupported MCTP Command Response"
    CommandValue = 0xF2

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, COMPLETION_CODES)
    ]


# Register packet classes
# Cannot do a simple Scapy 'bind' because request/response depends on
# more than one simple parameter.
register_mctp_control_class(SetEndpointID_Request)
register_mctp_control_class(SetEndpointID_Response)
register_mctp_control_class(GetEndpointID_Request)
register_mctp_control_class(GetEndpointID_Response)
register_mctp_control_class(GetEndpointUUID_Request)
register_mctp_control_class(GetEndpointUUID_Response)
register_mctp_control_class(GetMCTPVersionSupport_Request)
register_mctp_control_class(GetMCTPVersionSupport_Response)
register_mctp_control_class(GetMessageTypeSupport_Request)
register_mctp_control_class(GetMessageTypeSupport_Response)
register_mctp_control_class(GetVendorDefinedMessageSupport_Request)
register_mctp_control_class(GetVendorDefinedMessageSupport_Response)
register_mctp_control_class(ResolveEndpointID_Request)
register_mctp_control_class(ResolveEndpointID_Response)
register_mctp_control_class(AllocateEndpointIDs_Request)
register_mctp_control_class(AllocateEndpointIDs_Response)
register_mctp_control_class(RoutingInformationUpdate_Request)
register_mctp_control_class(RoutingInformationUpdate_Response)
register_mctp_control_class(GetRoutingTableEntries_Request)
register_mctp_control_class(GetRoutingTableEntries_Response)
register_mctp_control_class(PrepareForEndpointDiscovery_Request)
register_mctp_control_class(PrepareForEndpointDiscovery_Response)
register_mctp_control_class(EndpointDiscovery_Request)
register_mctp_control_class(EndpointDiscovery_Response)
register_mctp_control_class(DiscoveryNotify_Request)
register_mctp_control_class(DiscoveryNotify_Response)
register_mctp_control_class(GetNetworkID_Request)
register_mctp_control_class(GetNetworkID_Response)
register_mctp_control_class(QueryHop_Request)
register_mctp_control_class(QueryHop_Response)
register_mctp_control_class(ResolveUUID_Request)
register_mctp_control_class(ResolveUUID_Response)
register_mctp_control_class(QueryRateLimit_Request)
register_mctp_control_class(QueryRateLimit_Response)
register_mctp_control_class(TXRateLimit_Request)
register_mctp_control_class(TXRateLimit_Response)
register_mctp_control_class(UpdateRateLimit_Request)
register_mctp_control_class(UpdateRateLimit_Response)
register_mctp_control_class(QuerySupportedInterfaces_Request)
register_mctp_control_class(QuerySupportedInterfaces_Response)
register_mctp_control_class(TestUnsupportedMctp_Request)
register_mctp_control_class(TestUnsupportedMctp_Response)

# Do Scapy simple binding
bind_layers(MCTP_HEADER, MCTP_MESSAGE_TYPE)
bind_layers(MCTP_MESSAGE_TYPE, MCTP_COMMAND_HEADER, MessageType=0x00)
bind_layers(MCTP_MESSAGE_TYPE, PLDM_HEADER, MessageType=0x01)
bind_layers(MCTP_MESSAGE_TYPE, NCSI_HEADER, MessageType=0x02)
