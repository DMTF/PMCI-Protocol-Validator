# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
PLDM Type 2 (PLDM for Platform Monitoring and Control) Scapy classes

File : dsp0248.py

Brief : PLDM Type 2 (PLDM for Platform Monitoring and Control) Scapy classes
"""

from scapy.fields import *
from scapy.all import bind_layers
from scapy.packet import Packet

from pmci_protocol_validator.pldm.classes.dsp0248_pdrs import PDR_HEADER
from pmci_protocol_validator.pldm.classes.dsp0240_base import (
    PLDM_HEADER,
    PLDM_PAYLOAD,
    PLDM_UUID,
    PLDM_TIMESTAMP104,
    PLDM_BASE_CODES,
    register_pldm_class,
    TransferFlagsPldm2,
)

DSP0248_COMPLIANCE_VERSION = int.from_bytes([1, 2, 2, 0], 'big')


class PLDM_TYPE_2_PAYLOAD(PLDM_PAYLOAD):
    name = "PLDM for Platform Monitoring and Control Payload"
    PldmPayloadType = 0x02

    states = {
        0: "Unknown",
        1: "Normal",
        2: "Warning",
        3: "Critical",
        4: "Fatal",
        5: "LowerWarning",
        6: "LowerCritical",
        7: "LowerFatal",
        8: "UpperWarning",
        9: "UpperCritical",
        10: "UpperFatal",
    }

    dataSize = {
        0: "uint8",
        1: "sint8",
        2: "uint16",
        3: "sint16",
        4: "uint32",
        5: "sint32",
    }

    eventMessage = {
        0: "noChange",
        1: "disableEvents",
        2: "enableEvents",
        3: "enableOpEventsOnly",
        4: "enableStateEventsOnly",
    }

    sensorOperationalState = {
        0: "enabled",
        1: "disabled",
        2: "unavailable",
        3: "statusUnknown",
        4: "failed",
        5: "initializing",
        6: "shuttingDown",
        7: "inTest",
    }

    effecterOperationalState = {
        0: "enabled-updatePending",
        1: "enabled-noUpdatePending",
        2: "disabled",
        3: "unavailable",
        4: "statusUnknown",
        5: "failed",
        6: "initializing",
        7: "shuttingDown",
        8: "inTest",
    }

    TransportProtocolTypesValues = {
        0x00: "MCTP",
        0x01: "NC-SI/RBT",
        0xFF: "Vendor Specific",
    }

    LogOperationStatus = {
        0: "loggingDisabled",
        1: "enabledReady",
        2: "clearInProgress",
        3: "enabledFull",
        4: "failedLoggingDisabled",
        5: "failedDisabled",
        6: "corrupted",
    }

    PldmEventTypes = {
        0x00: "sesnsorEvent",
        0x01: "effecterEvent",
        0x02: "redfishTaskExecutedEvent",
        0x03: "redfishMessageEvent",
        0x04: "pldmPDRRepositoryChgEvent",
        0x05: "pldmMessagePollEvent",
        0x06: "heartbeatTimerElapsedEvent",
        0xFF: "reserved",
    }

    _reserved_dict = {key: "reserved" for key in [hex(i) for i in range(7, 240)]}
    _oemEvent_dict = {key: "oemEvent" for key in [hex(i) for i in range(240, 255)]}
    PldmEventTypes.update({key: value for (key, value) in _reserved_dict.items()})
    PldmEventTypes.update({key: value for (key, value) in _oemEvent_dict.items()})
    _transportProtocolValues_dict = {
        key: "INVALID_PROTOCOL_TYPE" for key in [hex(i) for i in range(2, 255)]
    }
    TransportProtocolTypesValues.update(
        {key: value for (key, value) in _transportProtocolValues_dict.items()}
    )

    LogClearingPolicy = {0: "fillAndStop", 1: "FIFO", 2: "clearOnAge"}

    # DSP0218, Table 3
    schemaClass = {
        0: "MAJOR",
        1: "EVENT",
        2: "ANNOTATION",
        3: "COLLECTION_MEMBER_TYPE",
        4: "ERROR",
        5: "REGISTRY",
    }

    wildcards_enum = {
        0: "parameter value in findParameters is ignored",
        1: "parameter value in findParameters must be matched",
    }


########## PLDM Type 2 Message Classes ############

class GetTerminusUID_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get Terminus UID Request"
    CommandValue = 0x03


class GetTerminusUID_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get Terminus UID Response"
    CommandValue = 0x03
    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            PacketField("UUID", PLDM_UUID(), PLDM_UUID),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SetEventReceiver_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set Event Receiver Request"
    CommandValue = 0x04

    fields_desc = [
        ByteEnumField(
            "EventMessageGlobalEnable",
            0,
            {
                0: "disable",
                1: "enableAsync",
                2: "enablePolling",
                3: "enableAsyncKeepAlive",
            },
        ),
        XByteEnumField(
            "TransportProtocolType",
            0x00,
            PLDM_TYPE_2_PAYLOAD.TransportProtocolTypesValues,
        ),
        ConditionalField(
            XByteField("EventReceiverAddressInfo", 0x00),
            lambda pkt: pkt.TransportProtocolType in [0x00, 0x01],
        ),
        ConditionalField(
            XLEIntField("IANAEnterpriseNumber", 0x00000000),
            lambda pkt: pkt.TransportProtocolType == 0xFF,
        ),
        XLEShortField("HeartbeatTimer", 0x0000)
    ]


class SetEventReceiver_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Send Event Receiver Response"
    CommandValue = 0x04

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_PROTOCOL_TYPE",
                0x81: "ENABLE_METHOD_NOT_SUPPORTED",
                0x82: "HEARTBEAT_FREQUENCY_TOO_HIGH",
            },
        )
    ]


class GetEventReceiver_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get Event Receiver Request"
    CommandValue = 0x05


class GetEventReceiver_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get Event Receiver Response"
    CommandValue = 0x05

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),

        ConditionalField(
            XByteEnumField(
                "TransportProtocolType",
                0x00,
                PLDM_TYPE_2_PAYLOAD.TransportProtocolTypesValues,
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),

        ConditionalField(
            XByteField("EventReceiverAddressInfo", 0x00),
            lambda pkt: pkt.CompletionCode == 0 and pkt.TransportProtocolType in [0x00, 0x01],
        ),
        ConditionalField(
            XLEIntField("IANAEnterpriseNumber", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0 and pkt.TransportProtocolType == 0xFF,
        )
    ]


class SensorOpState(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 19"""

    name = "SensorOpState"
    fields_desc = [
        ByteEnumField(
            "PresentOpState", 0x00, PLDM_TYPE_2_PAYLOAD.sensorOperationalState
        ),
        ByteEnumField(
            "PreviousOpState", 0x00, PLDM_TYPE_2_PAYLOAD.sensorOperationalState
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class StateSensorState(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 19"""

    name = "StateSensorState"
    fields_desc = [
        XByteField("SensorOffset", 0x00),
        ByteEnumField("EventState", 0x00, PLDM_TYPE_2_PAYLOAD.states),
        ByteEnumField("PreviousEventState", 0x00, PLDM_TYPE_2_PAYLOAD.states),
    ]

    def extract_padding(self, s):
        return ("", s)


class NumericSensorState(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 19"""

    name = "NumericSensorState"
    fields_desc = [
        ByteEnumField("EventState", 0x00, PLDM_TYPE_2_PAYLOAD.states),
        ByteEnumField("PreviousEventState", 0x00, PLDM_TYPE_2_PAYLOAD.states),
        ByteEnumField("SensorDataSize", 0x00, PLDM_TYPE_2_PAYLOAD.dataSize),
        MultipleTypeField(
            [
                (
                    XByteField("PresentReading", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("PresentReading", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("PresentReading", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("PresentReading", 0x00),  # Default field
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class SensorEventData(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 19"""

    name = "SensorEventData"
    fields_desc = [
        XLEShortField("SensorID", 0x0000),
        ByteEnumField(
            "SensorEventClass",
            0x00,
            {0: "sensorOpState", 1: "stateSensorState", 2: "numericSensorState"},
        ),
        ConditionalField(
            PacketField(
                "SensorOpState",
                SensorOpState(),
                SensorOpState),
                lambda pkt: pkt.SensorEventClass == 0x00,
        ),  # sensorOpState events
        ConditionalField(
            PacketField(
                "StateSensorState",
                StateSensorState(),
                StateSensorState),
                lambda pkt: pkt.SensorEventClass == 0x01,
        ),  # stateSensorState events
        ConditionalField(
            PacketField(
                "NumericSensorState",
                NumericSensorState(),
                NumericSensorState),
                lambda pkt: pkt.SensorEventClass == 0x02,
        )   # stateSensorState events
    ]

    def extract_padding(self, s):
        return ("", s,)


class EffecterOpState(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 20"""

    name = "EffecterOpState"
    fields_desc = [
        ByteEnumField(
            "PresentOpState", 0x00, PLDM_TYPE_2_PAYLOAD.sensorOperationalState
        ),
        ByteEnumField(
            "PreviousOpState", 0x00, PLDM_TYPE_2_PAYLOAD.sensorOperationalState
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class EffecterEventData(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 20"""

    name = "EffecterEventData"

    fields_desc = [
        XLEShortField("EffecterID", 0x0000),
        ByteEnumField(
            "EffecterEventClass",
            0,
            {
                0: "effecterOpState",
            },
        ),
        ConditionalField(
            PacketField(
                "EffecterOpState",
                EffecterOpState(),
                EffecterOpState),
                lambda pkt: pkt.EffecterEventClass == 0x00,
        )  # effecterEventClass events
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishTaskExecutedEventData(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 21"""

    name = "RedfishTaskExecutedEventData"
    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        XLEShortField("OperationID", 0x0000),
    ]

    def extract_padding(self, s):
        return ("", s)


class PldmMessagePollEventData(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 25"""

    name = "PldmMessagePollEventData"
    fields_desc = [
        XByteField("FormatVersion", 0x00),
        XLEShortField("EventID", 0x0000),
        XLEIntField("DataTransferHandle", 0x00000000)
    ]

    def extract_padding(self, s):
        return ("", s)


class HeartbeatTimerElapsedEventData(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 26"""

    name = "HeartbeatTimerElapsedEventData"
    fields_desc = [
        XByteField("FormatVersion", 0x01),
        XByteField("SequenceNumber", 0x00)
    ]

    def extract_padding(self, s):
        return ("", s)


class bejEncoding(Packet):
    name = "bejEncoding"
    fields_desc = [
        XLEIntField("BEJVersion", 0xF1F1F000),
        XLEShortField("Reserved", 0x00),
        ByteEnumField("SchemaClass", 0, PLDM_TYPE_2_PAYLOAD.schemaClass)
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishMessageEventDataResources(Packet):

    name = "Redfish Message Event Data Resources"

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        ByteEnumField(
            "EventSeverity",
            0x00,
            {
                0: "OK",
                1: "Warning",
                2: "Critical",
            },
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishMessageEventData(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 22"""

    name = "RedfishMessageEventData"
    fields_desc = [
        XByteField("EventCount", 0x00),
        XLEShortField("EventDataLength", 0x0000),
        PacketListField(
            "Resources",
            RedfishMessageEventDataResources(),
            RedfishMessageEventDataResources,
            count_from=lambda pkt: pkt.EventCount,
        ),
        PacketField("EventData", bejEncoding(), bejEncoding)
    ]

    def extract_padding(self, s):
        return ("", s)


class ChangeRecord(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 24"""

    name = "ChangeRecord"
    fields_desc = [
        ByteEnumField(
            "EventDataOperation",
            0x00,
            {
                0: "refreshAllRecords",
                1: "recordsDeleted",
                2: "recordsAdded",
                3: "recordsModified",
            },
        ),
        FieldLenField("NumberOfChangeEntries", None, count_of="ChangeEntry", fmt="B"),
        FieldListField(
            "ChangeEntry",
            [],
            XLEIntField("", 0x00000000),
            count_from=lambda pkt: pkt.NumberOfChangeEntries,
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class PldmPDRRepositoryChgEventData(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 23"""

    name = "PldmPDRRepositoryChgEventData"
    fields_desc = [
        ByteEnumField(
            "EventDataFormat",
            0x00,
            {
                0: "refreshEntireRepository",
                1: "formatIsPDRTypes",
                2: "formatIsPDRHandles",
            },
        ),
        FieldLenField("NumberOfChangeRecords", None, count_of="ChangeRecord", fmt="B"),
        FieldListField(
            "ChangeRecord",
            [],
            PacketField("", ChangeRecord(), ChangeRecord),
            count_from=lambda pkt: pkt.NumberOfChangeRecords,
        ),
    ]

    def extract_padding(self, s):
         return ("", s)


class OemEventData(Packet):
    """This is the OEM event data format. It is NOT define by DMTF."""

    name = "OemEventData"
    fields_desc = []

    def extract_padding(self, s):
        return ("", s)


class PlatformEventMessage_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Platform Event Message Request"
    CommandValue = 0x0A

    fields_desc = [
        XByteField("FormatVersion", 0x01),
        XByteField("TID", 0x00),
        XByteEnumField(
            "EventClass",
            0x00,
            PLDM_TYPE_2_PAYLOAD.PldmEventTypes
        ),
        ConditionalField(
            PacketField(
                "SensorEventData",
                SensorEventData(),
                SensorEventData),
                lambda pkt: pkt.EventClass == 0x00,
        ),  # sensors event data
        ConditionalField(
            PacketField(
                "EffecterEventData",
                EffecterEventData(),
                EffecterEventData),
                lambda pkt: pkt.EventClass == 0x01,
        ),  # effecter event data
        ConditionalField(
            PacketField(
                "RedfishTaskExecutedEventData",
                RedfishTaskExecutedEventData(),
                RedfishTaskExecutedEventData,
            ),
            lambda pkt: pkt.EventClass == 0x02,
        ),  # redfish task executed event data
        ConditionalField(
            PacketField(
                "RedfishMessageEventData",
                RedfishMessageEventData(),
                RedfishMessageEventData,
            ),
            lambda pkt: pkt.EventClass == 0x03,
        ),  # redfish message  event data
        ConditionalField(
            PacketField(
                "PldmPDRRepositoryChgEventData",
                PldmPDRRepositoryChgEventData(),
                PldmPDRRepositoryChgEventData,
            ),
            lambda pkt: pkt.EventClass == 0x04,
        ),  # pldm PDR repository changes event data
        ConditionalField(
            PacketField(
                "PldmMessagePollEventData",
                PldmMessagePollEventData(),
                PldmMessagePollEventData,
            ),
            lambda pkt: pkt.EventClass == 0x05,
        ),  # pldm message poll  event data
        ConditionalField(
            PacketField(
                "HeartbeatTimerElapsedEventData",
                HeartbeatTimerElapsedEventData(),
                HeartbeatTimerElapsedEventData,
            ),
            lambda pkt: pkt.EventClass == 0x06,
        ),  # heartbeat timer elapsed  event data
        ConditionalField(
            PacketField("OemEventData", OemEventData(), OemEventData),
            lambda pkt: pkt.EventClass in range(0xF0, 0xFE + 1),
        ),  # OEM  event data
    ]


class PlatformEventMessage_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Platform Event Message Response"
    CommandValue = 0x0A

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {**PLDM_BASE_CODES, 0x81: "UNSUPPORTED_EVENT_FORMAT_VERSION"},
        ),
        ConditionalField(
            ByteEnumField(
                "Status",
                0,
                {
                    0: "noLogging",
                    1: "loggingDisabled",
                    2: "logFull",
                    3: "acceptedForLogging",
                    4: "logged",
                    5: "loggingRejected",
                },
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class PollForPlatformEventMessage_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Poll For Platform Event Message Request"
    CommandValue = 0x0B

    fields_desc = [
        XByteField("FormatVersion", 0x01),
        ByteEnumField(
            "TransferOperationFlag",
            0x01,
            {0x00: "GetNextPart", 0x01: "GetFirstPart", 0x02: "AcknowledgementOnly"},
        ),
        XLEIntField("DataTransferHandle", 0x00000000),
        XLEShortField("EventIDToAcknowledge", 0x0000)
    ]


class PollForPlatformEventMessage_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Poll For Platform Event Message Request"
    CommandValue = 0x0B

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x81: "UNSUPPORTED_EVENT_FORMAT_VERSION",
                0x82: "EVENT_ID_NOT_VALID",
            },
        ),
        ConditionalField(
            XByteField("TID", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEShortField("EventID", 0x0000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("NextDataTransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteEnumField("TransferFlag", 0x01, TransferFlagsPldm2),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteEnumField("EventClass", 0x00, PLDM_TYPE_2_PAYLOAD.PldmEventTypes),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("EventDataSize", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            PacketField("SensorEventData", SensorEventData(), SensorEventData),
            lambda pkt: pkt.EventClass == 0x00 and pkt.CompletionCode == 0
        ),  # sensors event data
        ConditionalField(
            PacketField("EffecterEventData", EffecterEventData(), EffecterEventData),
            lambda pkt: pkt.EventClass == 0x01 and pkt.CompletionCode == 0
        ),  # effecter event data
        ConditionalField(
            PacketField(
                "RedfishTaskExecutedEventData",
                RedfishTaskExecutedEventData(),
                RedfishTaskExecutedEventData,
            ),
            lambda pkt: pkt.EventClass == 0x02 and pkt.CompletionCode == 0
        ),  # redfish task executed event data
        ConditionalField(
            PacketField(
                "RedfishMessageEventData",
                RedfishMessageEventData(),
                RedfishMessageEventData,
            ),
            lambda pkt: pkt.EventClass == 0x03 and pkt.CompletionCode == 0
        ),  # redfish message  event data
        ConditionalField(
            PacketField(
                "PldmPDRRepositoryChgEventData",
                PldmPDRRepositoryChgEventData(),
                PldmPDRRepositoryChgEventData,
            ),
            lambda pkt: pkt.EventClass == 0x04 and pkt.CompletionCode == 0
        ),  # pldm PDR repository changes event data
        ConditionalField(
            PacketField(
                "PldmMessagePollEventData",
                PldmMessagePollEventData(),
                PldmMessagePollEventData,
            ),
            lambda pkt: pkt.EventClass == 0x05 and pkt.CompletionCode == 0
        ),  # pldm message poll  event data
        ConditionalField(
            PacketField(
                "HeartbeatTimerElapsedEventData",
                HeartbeatTimerElapsedEventData(),
                HeartbeatTimerElapsedEventData,
            ),
            lambda pkt: pkt.EventClass == 0x06 and pkt.CompletionCode == 0
        ),  # heartbeat timer elapsed  event data
        ConditionalField(
            PacketField("OemEventData", OemEventData(), OemEventData),
            lambda pkt: pkt.EventClass in range(0xF0, 0xFE + 1) and pkt.CompletionCode == 0
        ),  # OEM  event data
        ConditionalField(
            XLEIntField("EventDataIntegrityChecksum", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class EventMessageSupported_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Event Message Supported Request"
    CommandValue = 0x0C

    fields_desc = [
        XByteField("FormatVersion", 0x01),
    ]


class EventMessageSupported_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Event Message Supported Response"
    CommandValue = 0x0C

    class Data(Packet):
        fields_desc = [
            ByteEnumField(
                "synchronyConfiguration",
                0x00,
                {
                    0x00: "NOT_CONFIGURED",
                    0x01: "ASYNCHRONOUS_MESSAGING",
                    0x02: "SYNCHRONOUS_MESSAGING",
                    0x03: "ASYNCHRONOUS_WITH_HEARTBEAT",
                },
            ),
            BitField("Reserved_2", 0, 4),
            BitField("AsynchronousMessagingWithHeartbeat", 0, 1),
            BitField("SynchronousMessaging", 0, 1),
            BitField("AsynchronousMessagingNoHeartbeat", 0, 1),
            BitField("Reserved_1", 0, 1),
            XByteField("NumberEventClassReturned", 0x00),
            FieldListField(
                "EventClass",
                None,
                XByteField("", 0x00),
                count_from=lambda pkt: pkt.NumberEventClassReturned,
            )
        ]

        def extract_padding(self, pld):
            return ("", pld,)

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x81: "UNSUPPORTED_EVENT_FORMAT_VERSION",
            },
        ),
        ConditionalField(
            PacketField("ResponseData", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class EventMessageBufferSize_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Event Message Buffer Size Request"
    CommandValue = 0x0D

    fields_desc = [
        XLEShortField("EventReceiverMaxBufferSize", 0x0000),
    ]


class EventMessageBufferSize_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Event Message Buffer Size Response"
    CommandValue = 0x0D

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),


        ConditionalField(
            XLEShortField("TerminusMaxBufferSize", 0x0000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SetNumericSensorEnable_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set Numeric Sensor Enable Request"
    CommandValue = 0x10

    fields_desc = [
        XLEShortField("SensorID", 0x0000),
        ByteEnumField(
            "SensorOperationalState", 0, PLDM_TYPE_2_PAYLOAD.sensorOperationalState
        ),
        ByteEnumField("SensorEventMessageEnable", 0, PLDM_TYPE_2_PAYLOAD.eventMessage),
    ]


class SetNumericSensorEnable_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set Numeric Sensor Enable Response"
    CommandValue = 0x10

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_SENSOR_ID",
                0x81: "INVALID_SENSOR_OPERATIONAL_STATE",
                0x82: "EVENT_GENERATION_NOT_SUPPORTED",
            },
        )
    ]


class GetSensorReading_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get Sensor Reading Request"
    CommandValue = 0x11

    fields_desc = [
        XLEShortField("SensorID", 0x0000),
        XByteField(
            "RearmEventState", 0x00
        )   # 0x00 = False, any non-zero value means True
    ]


class GetSensorReading_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get Sensor Reading Response"
    CommandValue = 0x11

    class Data(Packet):
        fields_desc = [
            ByteEnumField("SensorDataSize", 1, PLDM_TYPE_2_PAYLOAD.dataSize),
            ByteEnumField(
                "SensorOperationalState", 0, PLDM_TYPE_2_PAYLOAD.sensorOperationalState
            ),
            ByteEnumField(
                "SensorEventMessageEnable",
                0,
                {
                    0: "noEventGeneration",
                    1: "eventsDisabled",
                    2: "eventsEnabled",
                    3: "opEventsOnlyEnabled",
                    4: "stateEventsOnlyEnabled",
                },
            ),
            ByteEnumField("PresentState", 0, PLDM_TYPE_2_PAYLOAD.states),
            ByteEnumField("PreviousState", 0, PLDM_TYPE_2_PAYLOAD.states),
            ByteEnumField("EventState", 0, PLDM_TYPE_2_PAYLOAD.states),
            MultipleTypeField(
                [
                    (
                        XByteField("PresentReading", 0x00),
                        lambda pkt: pkt.SensorDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("PresentReading", 0x0000),
                        lambda pkt: pkt.SensorDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("PresentReading", 0x00000000),
                        lambda pkt: pkt.SensorDataSize in [4, 5],
                    ),
                ],
                XByteField("PresentReading", 0x00),  # Default field
            )
        ]

        def extract_padding(self, pld):
            return ("", pld,)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),

        ConditionalField(
            PacketField("SensorData", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetSensorThresholds_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get Sensor Thresholds Request"
    CommandValue = 0x12

    fields_desc = [
        XLEShortField("SensorID", 0x0000)
    ]


class GetSensorThresholds_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get Sensor Thresholds Response"
    CommandValue = 0x12

    class Data(Packet):
        fields_desc = [
            ByteEnumField("SensorDataSize", 0, PLDM_TYPE_2_PAYLOAD.dataSize),
            MultipleTypeField(
                [
                    (
                        XByteField("UpperThresholdWarning", 0x00),
                        lambda pkt: pkt.SensorDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("UpperThresholdWarning", 0x0000),
                        lambda pkt: pkt.SensorDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("UpperThresholdWarning", 0x00000000),
                        lambda pkt: pkt.SensorDataSize in [4, 5],
                    ),
                ],
                XByteField("UpperThresholdWarning", 0x00),  # Default field
            ),
            MultipleTypeField(
                [
                    (
                        XByteField("UpperThresholdCritical", 0x00),
                        lambda pkt: pkt.SensorDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("UpperThresholdCritical", 0x0000),
                        lambda pkt: pkt.SensorDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("UpperThresholdCritical", 0x00000000),
                        lambda pkt: pkt.SensorDataSize in [4, 5],
                    ),
                ],
                XByteField("UpperThresholdCritical", 0x00),  # Default field
            ),
            MultipleTypeField(
                [
                    (
                        XByteField("UpperThresholdFatal", 0x00),
                        lambda pkt: pkt.SensorDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("UpperThresholdFatal", 0x0000),
                        lambda pkt: pkt.SensorDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("UpperThresholdFatal", 0x00000000),
                        lambda pkt: pkt.SensorDataSize in [4, 5],
                    ),
                ],
                XByteField("UpperThresholdFatal", 0x00),  # Default field
            ),
            MultipleTypeField(
                [
                    (
                        XByteField("LowerThresholdWarning", 0x00),
                        lambda pkt: pkt.SensorDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("LowerThresholdWarning", 0x0000),
                        lambda pkt: pkt.SensorDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("LowerThresholdWarning", 0x00000000),
                        lambda pkt: pkt.SensorDataSize in [4, 5],
                    ),
                ],
                XByteField("LowerThresholdWarning", 0x00),  # Default field
            ),
            MultipleTypeField(
                [
                    (
                        XByteField("LowerThresholdCritical", 0x00),
                        lambda pkt: pkt.SensorDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("LowerThresholdCritical", 0x0000),
                        lambda pkt: pkt.SensorDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("LowerThresholdCritical", 0x00000000),
                        lambda pkt: pkt.SensorDataSize in [4, 5],
                    ),
                ],
                XByteField("LowerThresholdCritical", 0x00),  # Default field
            ),
            MultipleTypeField(
                [
                    (
                        XByteField("LowerThresholdFatal", 0x00),
                        lambda pkt: pkt.SensorDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("LowerThresholdFatal", 0x0000),
                        lambda pkt: pkt.SensorDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("LowerThresholdFatal", 0x00000000),
                        lambda pkt: pkt.SensorDataSize in [4, 5],
                    ),
                ],
                XByteField("LowerThresholdFatal", 0x00),  # Default field
            )
        ]

        def extract_padding(self, pld):
            return ("", pld,)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            PacketField("ThresholdData", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SetSensorThresholds_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set Sensor Thresholds Request"
    CommandValue = 0x13

    fields_desc = [
        XLEShortField("SensorID", 0x0000),
        ByteEnumField("SensorDataSize", 0, PLDM_TYPE_2_PAYLOAD.dataSize),
        MultipleTypeField(
            [
                (
                    XByteField("UpperThresholdWarning", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("UpperThresholdWarning", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("UpperThresholdWarning", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("UpperThresholdWarning", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("UpperThresholdCritical", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("UpperThresholdCritical", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("UpperThresholdCritical", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("UpperThresholdCritical", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("UpperThresholdFatal", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("UpperThresholdFatal", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("UpperThresholdFatal", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("UpperThresholdFatal", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("LowerThresholdWarning", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("LowerThresholdWarning", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("LowerThresholdWarning", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("LowerThresholdWarning", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("LowerThresholdCritical", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("LowerThresholdCritical", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("LowerThresholdCritical", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("LowerThresholdCritical", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("LowerThresholdFatal", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("LowerThresholdFatal", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("LowerThresholdFatal", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("LowerThresholdFatal", 0x00),  # Default field
        ),
    ]


class SetSensorThresholds_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set Sensor Thresholds Response"
    CommandValue = 0x13

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_SENSOR_ID"}
        )
    ]


class RestoreSensorThresholds_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Restore Sensor Thresholds Request"
    CommandValue = 0x14
    fields_desc = [XLEShortField("SensorID", 0x0000)]


class RestoreSensorThresholds_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Restore Sensor Thresholds Response"
    CommandValue = 0x14

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_SENSOR_ID"}
        )
    ]


class GetSensorHysteresis_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get Sensor Hysteresis Request"
    CommandValue = 0x15

    fields_desc = [
        XLEShortField("SensorID", 0x0000)
    ]


class GetSensorHysteresis_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get Sensor Hysteresis Response"
    CommandValue = 0x15

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_SENSOR_ID"}
        ),
        ConditionalField(
            ByteEnumField("SensorDataSize", 0, PLDM_TYPE_2_PAYLOAD.dataSize),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            MultipleTypeField(
                [
                    (
                        XByteField("HysteresisValue", 0x00),
                        lambda pkt: pkt.SensorDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("HysteresisValue", 0x0000),
                        lambda pkt: pkt.SensorDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("HysteresisValue", 0x00000000),
                        lambda pkt: pkt.SensorDataSize in [4, 5],
                    ),
                ],
                XByteField("HysteresisValue", 0x00),  # Default field
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SetSensorHysteresis_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set Sensor Hysteresis Request"
    CommandValue = 0x16

    fields_desc = [
        XLEShortField("SensorID", 0x0000),
        ByteEnumField("SensorDataSize", 0, PLDM_TYPE_2_PAYLOAD.dataSize),
        MultipleTypeField(
            [
                (
                    XByteField("HysteresisValue", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("HysteresisValue", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("HysteresisValue", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("HysteresisValue", 0x00),  # Default field
        )
    ]


class SetSensorHysteresis_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set Sensor Hysteresis Response"
    CommandValue = 0x16
    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_SENSOR_ID"}
        )
    ]


class InitNumericSensor_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Init Numeric Sensor Request"
    CommandValue = 0x17
    fields_desc = [
        XLEShortField("SensorID", 0x0000),
        ByteEnumField(
            "SensorOperationalState", 0, {0: "enabled", 1: "disabled", 2: "unavailable"}
        ),
        ByteEnumField("SensorPresentState", 0, PLDM_TYPE_2_PAYLOAD.states),
        XByteEnumField(
            "EventMsgEnable",
            0x00,
            {
                0x00: "enableEventMessages",
                0x01: "disableEventMessages",
                0xFF: "noChange",
            },
        ),
        XByteField(
            "SetNumericReading", 0x00
        )   # True directs receiver to accept the following numericReadingSetting
            # numericReadingSetting[] (DSP0248 - Table 36)
    ]


class InitNumericSensor_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Init Numeric Sensor Response"
    CommandValue = 0x17

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_SENSOR_ID"}
        )
    ]

### State Sensor commands ###

class SetStateSensorField(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 39"""

    name = "Set State Sensor Operational Field"

    fields_desc = [
        ByteEnumField(
            "SensorOperationalState",
            0,
            {
                0: "enabled",
                1: "disabled",
                2: "unavailable"
            }
        ),
        ByteEnumField("EventMessageEnable", 0, PLDM_TYPE_2_PAYLOAD.eventMessage)
    ]

    def extract_padding(self, s):
        return ("", s)


class SetStateSensorEnables_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set State Sensor Enables Request"
    CommandValue = 0x20

    fields_desc = [
        XLEShortField("SensorID", 0x0000),
        FieldLenField(
            "CompositeSensorCount", None, count_of="SensorInformation", fmt="B"
        ),  # Values from 0x01 to 0x08
        FieldListField(
            "SensorInformation",
            [],
            PacketField("", SetStateSensorField(), SetStateSensorField),
            count_from=lambda pkt: pkt.CompositeSensorCount,
        )
    ]


class SetStateSensorEnables_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set State Sensor Enables Request"
    CommandValue = 0x20

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_SENSOR_ID",
                0x82: "EVENT_GENERATION_NOT_SUPPORTED",
            }
        )
    ]


class GetStateSensorReadings_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get State Sensor Readings"
    CommandValue = 0x21

    fields_desc = [
        XLEShortField("SensorID", 0x0000),
        BitEnumField(
            "SensorRearm",
            0,
            8,
            {
                0: "do not re-arm sensor",
                1: "re-arm sensor"
            },
        ),
        XByteField("Reserved", 0x00),
    ]


class GetStateSensorField(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 41"""

    name = "Get State Sensor Reading Field"

    fields_desc = [
        ByteEnumField(
            "SensorOperationalState",
            0x00,
            PLDM_TYPE_2_PAYLOAD.sensorOperationalState
        ),
        XByteField("PresentState", 0x00),
        XByteField("PreviousState", 0x00),
        XByteField("EventState", 0x00)
    ]

    def extract_padding(self, s):
        return ("", s)


class GetStateSensorReadings_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get State Sensor Readings Response"
    CommandValue = 0x21

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_SENSOR_ID"}
        ),
        ConditionalField(
            XByteField("CompositeSensorCount", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            PacketListField(
                "SensorReadingStateFields",
                GetStateSensorField(),
                GetStateSensorField,
                count_from=lambda pkt: pkt.CompositeSensorCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
    ]


class InitStateSensorField(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 43"""

    name = "Init State Sensor Operational Field"

    fields_desc = [
        XByteEnumField(
            "SensorOperationalState",
            0,
            {
                0: "enabled",
                1: "disabled",
                2: "unavailable"
            }
        ),
        XByteField("SensorPresentState", 0x00),
        XByteEnumField(
            "EventMsgEnable",
            0x00,
            {0x00: "enableEvents", 0x01: "disableEvents", 0xFF: "noChange"},
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class InitStateSensor_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Init State Sensor Request"
    CommandValue = 0x22

    fields_desc = [
        XLEShortField("SensorID", 0x0000),
        # FieldLenField("CompositeSensorCount", None, count_of="InitField", fmt="B"),
        # FieldListField("InitField", [], PacketField("", InitStateSensorField(), InitStateSensorField),
        #               count_from=lambda pkt: pkt.CompositeSensorCount),
        XByteField("CompositeSensorCount", 0x00),
        PacketListField(
            "InitField",
            InitStateSensorField(),
            InitStateSensorField,
            count_from=lambda pkt: pkt.CompositeSensorCount,
        )
    ]


class InitStateSensor_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Init State Sensor Response"
    CommandValue = 0x22

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_SENSOR_ID",
                0x81: "UNSUPPORTED_SENSOR_STATE",
            }
        )
    ]

### PLDM Effecter commands ###

class SetNumericEffecterEnable_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set Numeric Effecter Enable Request"
    CommandValue = 0x30

    fields_desc = [
        XLEShortField("EffecterID", 0x0000),
        ByteEnumField(
            "EffecterOperationalState",
            0,
            {0: "enabled", 2: "disabled", 3: "unavailable"},
        ),
    ]


class SetNumericEffecterEnable_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set Numeric Effecter Enable Response"
    CommandValue = 0x30

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_EFFECTER_ID"}
        )
    ]


class SetNumericEffecterValue_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set Numeric Effecter Value Request"
    CommandValue = 0x31

    fields_desc = [
        XLEShortField("EffecterID", 0x0000),
        ByteEnumField("EffecterDataSize", 0, PLDM_TYPE_2_PAYLOAD.dataSize),
        MultipleTypeField(
            [
                (
                    XByteField("EffecterValue", 0x00),
                    lambda pkt: pkt.EffecterDataSize in [0, 1],
                ),
                (
                    XLEShortField("EffecterValue", 0x0000),
                    lambda pkt: pkt.EffecterDataSize in [2, 3],
                ),
                (
                    XLEIntField("EffecterValue", 0x00000000),
                    lambda pkt: pkt.EffecterDataSize in [4, 5],
                ),
            ],
            XByteField("EffecterValue", 0x00),  # Default field
        )
    ]


class SetNumericEffecterValue_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set Numeric Effecter Value Response"
    CommandValue = 0x31

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_EFFECTER_ID"}
        )
    ]


class GetNumericEffecterValue_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get Numeric Effecter Value Request"
    CommandValue = 0x32

    fields_desc = [
        XLEShortField("EffecterID", 0x0000)
    ]


class GetNumericEffecterValue_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get Numeric Effecter Value Response"
    CommandValue = 0x32

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_EFFECTER_ID"}
        ),
        ConditionalField(
            ByteEnumField("EffecterDataSize", 0, PLDM_TYPE_2_PAYLOAD.dataSize),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteEnumField(
                "EffecterOperationalState", 0, PLDM_TYPE_2_PAYLOAD.effecterOperationalState
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            MultipleTypeField(
                [
                    (
                        XByteField("pendingValue", 0x00),
                        lambda pkt: pkt.EffecterDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("pendingValue", 0x0000),
                        lambda pkt: pkt.EffecterDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("pendingValue", 0x00000000),
                        lambda pkt: pkt.EffecterDataSize in [4, 5],
                    ),
                ],
                XByteField("pendingValue", 0x00),  # Default field
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            MultipleTypeField(
                [
                    (
                        XByteField("presentValue", 0x00),
                        lambda pkt: pkt.EffecterDataSize in [0, 1],
                    ),
                    (
                        XLEShortField("presentValue", 0x0000),
                        lambda pkt: pkt.EffecterDataSize in [2, 3],
                    ),
                    (
                        XLEIntField("presentValue", 0x00000000),
                        lambda pkt: pkt.EffecterDataSize in [4, 5],
                    ),
                ],
                XByteField("presentValue", 0x00),  # Default field
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SetStateEffecterField(Packet):
    """this is the PLDM V1.2 format, per DSP0248 -> Table 49"""

    name = "Init State Sensor Operational Field"

    fields_desc = [
        ByteEnumField(
            "EffecterOperationalState",
            0,
            {0: "enabled", 2: "disabled", 3: "unavailable"},
        ),
        XByteEnumField(
            "EventMsgEnable",
            0x00,
            {0x00: "enableEvents", 0x01: "disableEvents", 0xFF: "noChange"},
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class SetStateEffecterEnables_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set State Effecter Enables Request"
    CommandValue = 0x38

    fields_desc = [
        XLEShortField("EffecterID", 0x0000),
        XByteField("CompositeEffecterCount", 0x01),
        PacketListField(
            "InitField",
            SetStateEffecterField(),
            SetStateEffecterField,
            count_from=lambda pkt: pkt.CompositeEffecterCount,
        )
    ]


class SetStateEffecterEnables_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set State Effecter Enables Response"
    CommandValue = 0x38

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_EFFECTER_ID"}
        )
    ]


class SetStateEffecterStates_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set State Effecter States Request"
    CommandValue = 0x39

    fields_desc = [
        XLEShortField("EffecterID", 0x0000),
        XByteField("CompositeEffecterCount", 0x01),  # Values from 0x01 to 0x08
        XByteEnumField(
            "SetRequest", 0, {0: "noChange", 1: "requestSet"}
        ),
        XByteField(
            "EffecterState", 0x00
        ),  # Values dependent on effecter state set (DSP0249)
    ]


class SetStateEffecterStates_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set State Effecter States Response"
    CommandValue = 0x39

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_EFFECTER_ID",
                0x81: "INVALID_STATE_VALUE",
                0x82: "UNSUPPORTED_EFFECTERSTATE",
            },
        )
    ]


class GetStateEffecterStates_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get State Effecter States Request"
    CommandValue = 0x3A

    fields_desc = [
        XLEShortField("EffecterID", 0x0000)
    ]


class GetStateEffecterStatesFields(Packet):
    name = "Get State Effecter States Fields"

    fields_desc = [
        ByteEnumField(
            "EffecterOperationalState",
            0,
            PLDM_TYPE_2_PAYLOAD.effecterOperationalState
        ),
        XByteField("PendingState", 0x00),  # See DSP0249
        XByteField("PresentState", 0x00),  # See DSP0249
    ]


class GetStateEffecterStates_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get State Effecter States Response"
    CommandValue = 0x3A

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_EFFECTER_ID"}
        ),

        ConditionalField(
            XByteField("CompositeEffecterCount", 0x01),  # Values from 0x01 to 0x08
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            PacketListField(
                "StateFields",
                GetStateEffecterStatesFields(),
                GetStateEffecterStatesFields,
                count_from=lambda pkt: pkt.CompositeEffecterCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


### PDR Repository commands ###

class GetPDRRepositoryInfo_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get PDR Repository Info Request"
    CommandValue = 0x50


class GetPDRRepositoryInfo_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get PDR Repository Info Response"
    CommandValue = 0x50

    class Data(Packet):
        fields_desc = [
           ByteEnumField(
                "RepositoryState", 0, {0: "available", 1: "updateInProgress", 2: "failed"}
            ),
            PacketField("UpdateTime", PLDM_TIMESTAMP104(), PLDM_TIMESTAMP104),
            PacketField("OEMUpdateTime", PLDM_TIMESTAMP104(), PLDM_TIMESTAMP104),
            XLEIntField("RecordCount", 0x00000000),
            XLEIntField("RepositorySize", 0x00000000),
            XLEIntField("LargestRecordSize", 0x00000000),
            XByteField(
                "DataTransferHandleTimeout", 0x01
            )   # 0x00=no timeout 0x01=default min timeout, 0xFF = timeout > 254sec
        ]

        def extract_padding(self, pld):
            return ("", pld,)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            PacketField("RepoInfo", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetPDR_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get PDR Request"
    CommandValue = 0x51

    fields_desc = [
        XLEIntField(
            "RecordHandle", 0x00000000
        ),  # special value: {0x0000_0000 = Get first PDR in the repository}
        XLEIntField("DataTransferHandle", 0x00000000),
        # special value: {use 0x0000_0000 if the transferOperationFlag is
        # GetFirstPart}
        XByteEnumField(
            "TransferOperationFlag", 0x00, {0x00: "GetNextPart", 0x01: "GetFirstPart"}
        ),
        XLEShortField("RequestCount", 0x0000),
        XLEShortField("RecordChangeNumber", 0x0000)
    ]


class GetPDR_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get PDR Response"
    CommandValue = 0x51

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_DATA_TRANSFER_HANDLE",
                0x81: "INVALID_TRANSFER_OPERATION_FLAG",
                0x82: "INVALID_RECORD_HANDLE",
                0x83: "INVALID_RECORD_CHANGE_NUMBER",
                0x84: "TRANSFER_TIMEOUT",
                0x85: "REPOSITORY_UPDATE_IN_PROGRESS",
            },
        ),

        ConditionalField(
            XLEIntField("NextRecordHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField("NextDataTransferHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteEnumField("TransferFlag", 0x01, TransferFlagsPldm2),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEShortField("ResponseCount", 0x0000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            PacketField("PDR", PDR_HEADER(), PDR_HEADER),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("TransferCRC", 0x00),
            lambda pkt: pkt.TransferFlag == 0x04 and pkt.CompletionCode == 0
        )
    ]


class FindPDR_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Find PDR Request"
    CommandValue = 0x52

    fields_desc = [
        XLEIntField(
            "FindHandle", 0x00000000
        ),  # special values: {use 0x0000_0000 if the findOperation is
        # findFirst,0xFFFF_FFFF = reserved}
        XByteEnumField(
            "FindOperationFlag", 0x00, {0x00: "findNext", 0x01: "findFirst"}
        ),
        XLEShortField("RequestCount", 0x0000),
        XLEShortField("PDRType", 0x0000),  # 0x0000 = match any PDRType
        XByteField("ParameterFormatNumber", 0x00),  # Table 71 DSP0248
        BitEnumField("Wildcard_8", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_7", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_6", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_5", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_4", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_3", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_2", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_1", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_16", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_15", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_14", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_13", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_12", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_11", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_10", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        BitEnumField("Wildcard_9", 0, 1, PLDM_TYPE_2_PAYLOAD.wildcards_enum),
        # findParameters values
    ]


class FindPDR_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Find PDR Response"
    CommandValue = 0x52

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x80: "INVALID_FIND_HANDLE",
                0x81: "INVALID_FIND_OPERATION_FLAG",
                0x82: "INVALID_PDR_TYPE",
                0x83: "INVALID_PARAMETER_FORMAT_NUMBER",
                0x84: "INVALID_FIND_PARAMETERS",
                0x85: "REPOSITORY_UPDATE_IN_PROGRESS",
            },
        ),
        ConditionalField(
            XLEIntField("NextFindHandle", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEIntField(
                "NextDataTransferHandle", 0x00000000
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteEnumField("TransferFlag", 0x01, TransferFlagsPldm2),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XLEShortField(
                "ResponseCount", 0x0000
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField(
                "RecordData",
                [],
                XByteField("", 0x00),
                count_from=lambda pkt: pkt.ResponseCount,
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class RunInitAgent_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Run Init Agent Request"
    CommandValue = 0x58

    fields_desc = [
        XByteEnumField(
            "InitConditionEmulation",
            0x00,
            {
                0x00: "InitializationAgentRestart",
                0x01: "PLDMSubsystemPowerUp",
                0x02: "SystemHardReset",
                0x03: "SystemWarmReset",
                0x04: "PLDMTerminusOnline",
            },
        ),
        XByteField("TID", 0x00)
    ]


class RunInitAgent_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Run Init Agent response"
    CommandValue = 0x58

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES)
    ]


class GetPDRRepositorySignature_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get PDR Repository Signature Request"
    CommandValue = 0x53

class GetPDRRepositorySignature_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get PDR Repository Signature Response"
    CommandValue = 0x53

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            XLEIntField("PdrRepositorySignature", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetPLDMEventLogInfo_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get PLDM Event Log Info Request"
    CommandValue = 0x40


class GetPLDMEventLogInfo_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get PLDM Event Log Info Response"
    CommandValue = 0x40

    class Data(Packet):
        fields_desc = [
            ByteEnumField(
                "LogOperationalStatus", 0, PLDM_TYPE_2_PAYLOAD.LogOperationStatus
            ),
            ByteEnumField(
                "ActiveLogClearingPolicy", 0, PLDM_TYPE_2_PAYLOAD.LogClearingPolicy
            ),
            LEIntField("EntryCount", 0),
            XByteField("StoragePercentUsed", 0x00),  # special value 0xFF = unspecified
            XByteField("PercentWear", 0x00),  # special value 0xFF = unspecified
            SignedIntField(
                "MostRecentAddTimestampUTCOffset", 0x00
            ),  # special value 0xFF = unspecified
            StrLenField(
                "MostRecentAddTimestampSeconds",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                length_from=lambda unused: 10,
            ),
            XByteField(
                "MostRecentAddTimestamp100s", 0x00
            ),  # special value 0xFF = unspecified
            XByteField(
                "MostRecentEraseTimestampUTCOffset", 0x00
            ),  # special value 0xFF = unspecified
            StrLenField(
                "MostRecentEraseTimestampSeconds",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                length_from=lambda unused: 10,
            ),
            XByteField(
                "MostRecentEraseTimestamp100s", 0x00
            ),  # special value 0xFF = unspecified
        ]

        def extract_padding(self, pld):
            return ("", pld,)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),

        ConditionalField(
            PacketField("EventLogInfo", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class EnablePLDMEventLogging_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Enable PLDM Event Logging Request"
    CommandValue = 0x41
    fields_desc = [
        ByteEnumField("EnableLogging", 0, {0: "disableLogging", 1: "enableLogging"})
    ]


class EnablePLDMEventLogging_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Enable PLDM Event Logging Response"
    CommandValue = 0x41

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            EnumField("LogOperationalStatus", 0, PLDM_TYPE_2_PAYLOAD.LogOperationStatus),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class ClearPLDMEventLog_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Clear PLDM Event Log Request"
    CommandValue = 0x42


class ClearPLDMEventLog_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Clear PLDM Event Log Response"
    CommandValue = 0x42

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            EnumField(
                "LogOperationalStatus",
                0,
                PLDM_TYPE_2_PAYLOAD.LogOperationStatus
            ),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class GetPLDMEventLogTimestamp_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get PLDM Event Log Timestamp Request"
    CommandValue = 0x43


class GetPLDMEventLogTimestamp_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get PLDM Event Log Timestamp Response"
    CommandValue = 0x43

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            XByteField("EntryTimestampUTCOffset", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            StrLenField(
                "EntryTimestampSeconds",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                length_from=lambda unused: 10,
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("EntryTimestamp100s", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SetPLDMEventLogTimestamp_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set PLDM Event Log Timestamp Response"
    CommandValue = 0x44

    fields_desc = [
        XByteField("EntryTimestampUTCOffset", 0x00),
        StrLenField(
            "EntryTimestampSeconds",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            length_from=lambda unused: 10,
        ),
        XByteField("EntryTimestamp100s", 0x00),
        ByteEnumField("LogUpdateEvent", 0, {0: "noEvent", 1: "logEvent"})
    ]


class SetPLDMEventLogTimestamp_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set PLDM Event Log Timestamp Response"
    CommandValue = 0x44

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            XByteField("EntryTimestampUTCOffset", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            StrLenField(
                "EntryTimestampSeconds",
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                length_from=lambda unused: 10,
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("EntryTimestamp100s", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("TimestampResolution", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class ReadPLDMEventLog_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Read PLDM Event Log Response"
    CommandValue = 0x45

    fields_desc = [
        XLEIntField("EntryID", 0x00000000),
        XByteEnumField(
            "TransferOperationFlag",
            0x00,
            {
                0x00: "GetNextPart",
                0x01: "GetFirstPart"
            }
        ),
    ]


class ReadPLDMEventLog_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Read PLDM Event Log Response"
    CommandValue = 0x45

    fields_desc = [
        XByteEnumField(
            "CompletionCode",
            0x00,
            {
                **PLDM_BASE_CODES,
                0x81: "INVALID_TRANSFER_OPERATION_FLAG",
                0x82: "INVALID_ENTRY_ID",
            },
        ),
        ConditionalField(
            XLEIntField("NextEntryID", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            ByteEnumField(
                "SplitEntry",
                0,
                {
                    0: "full",
                    1: "firstFragment",
                    2: "middleFragment",
                    3: "lastFragment"},
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("TransferredDataSize", 0x00),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            FieldListField(
                "TransferredEntryData",
                [],
                XByteField("", 0x00),
                count_from=lambda pkt: pkt.TransferredDataSize,
            ),
            lambda pkt: pkt.CompletionCode == 0
        ),
        ConditionalField(
            XByteField("TransferCRC", 0x00), lambda pkt: pkt.SplitEntry == 3 and pkt.CompletionCode == 0
        )
    ]


class GetPLDMEventLogPolicyInfo_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Get PLDM Event Log Policy Info Response"
    CommandValue = 0x46

    fields_desc = [
        EnumField("LogClearingPolicy", 0, PLDM_TYPE_2_PAYLOAD.LogClearingPolicy)
    ]


class GetPLDMEventLogPolicyInfo_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Get PLDM Event Log Policy Info Response"
    CommandValue = 0x46

    class Data(Packet):
        fields_desc = [
            BitField("Reserved", 0, 3),
            BitEnumField(
                "MPercentageConfgurable",
                0,
                2,
                {
                    0: "M and MPercentage are not configurable",
                    1: "M is configurable",
                    2: "MPercentage is configurable",
                    3: "reserved",
                }
            ),
            BitEnumField(
                "NPercentageConfgurable",
                0,
                2,
                {
                    0: "N and NPercentage are not configurable",
                    1: "N is configurable",
                    2: "NPercentage is configurable",
                    3: "reserved",
                }
            ),
            BitEnumField(
                "AgePercentageConfgurable",
                0,
                1,
                {
                    0: "Age is not configurable",
                    1: "Age is configurable",
                },
            ),
            XLEIntField("NMin", 0x00000000),  # special value 0x00000000
            XLEIntField("NMax", 0x00000000),  # special value 0x00000000
            XByteField("NPercentageMin", 0x00),  # special value 0x00
            XByteField("NPercentageMax", 0x00),  # special value 0x00
            XLEIntField("MMin", 0x00000000),  # special value 0x00000000
            XLEIntField("MMax", 0x00000000),  # special value 0x00000000
            XByteField("MPercentageMin", 0x00),  # special value 0x00
            XByteField("MPercentageMax", 0x00),  # special value 0x00
            XLEIntField("AgeMin", 0x00000000),  # special value 0x00000000
            XLEIntField("AgeMax", 0x00000000),  # special value 0x00000000
        ]

        def extract_padding(self, pld):
            return ("", pld,)

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES),
        ConditionalField(
            PacketField("LogInfo", Data(), Data),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


class SetPLDMEventLogPolicy_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Set PLDM Event Log Policy Request"
    CommandValue = 0x47

    fields_desc = [
        ByteEnumField("LogClearingPolicy", 0, PLDM_TYPE_2_PAYLOAD.LogClearingPolicy),
        ByteEnumField(
            "SetOperation", 0, {0: "ConfigureOnly", 1: "SetOnly", 2: "ConfigureAndSet"}
        ),
        XLEIntField("N", 0x00000000),       # special value 0x00000000
        XByteField("NPercentage", 0x00),    # special value 0x00
        XLEIntField("M", 0x00000000),       # special value 0x00000000
        XByteField("MPercentage", 0x00),    # special value 0x00
        XLEIntField("Age", 0x00000000),     # special value 0x00000000
    ]


class SetPLDMEventLogPolicy_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Set PLDM Event Log Policy Response"
    CommandValue = 0x47

    fields_desc = [
        XByteEnumField("CompletionCode", 0x00, PLDM_BASE_CODES)
    ]


class FindPLDMEventLogEntry_Request(PLDM_TYPE_2_PAYLOAD):
    name = "Find PLDM Event Log Entry Request"
    CommandValue = 0x48

    fields_desc = [
        ByteEnumField(
            "SearchType",
            0,
            {0: "newerThan", 1: "olderThan", 2: "offsetFromStart", 3: "offsetFromEnd"},
        ),
        XLEIntField("StartingPoint", 0x00000000),
        XByteField(
            "CompareTimestampUTCOffset", 0x00
        ),  # special value 0xFF = unspecified
        StrLenField(
            "CompareTimestampSeconds",
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            length_from=lambda unused: 10,
        ),
        XByteField("CompareTimestamp100s", 0x00)
    ]


class FindPLDMEventLogEntry_Response(PLDM_TYPE_2_PAYLOAD):
    name = "Find PLDM Event Log Entry Response"
    CommandValue = 0x48

    fields_desc = [
        XByteEnumField(
            "CompletionCode", 0x00, {**PLDM_BASE_CODES, 0x80: "INVALID_SEARCH_TYPE"}
        ),
        ConditionalField(
            XLEIntField("EntryID", 0x00000000),
            lambda pkt: pkt.CompletionCode == 0
        )
    ]


#### Register for SCAPY dissection ####
bind_layers(PLDM_HEADER, PLDM_TYPE_2_PAYLOAD, PldmType=0x02)

register_pldm_class(GetTerminusUID_Request)
register_pldm_class(GetTerminusUID_Response)
register_pldm_class(SetEventReceiver_Request)
register_pldm_class(SetEventReceiver_Response)
register_pldm_class(GetEventReceiver_Request)
register_pldm_class(GetEventReceiver_Response)
register_pldm_class(PlatformEventMessage_Request)
register_pldm_class(PlatformEventMessage_Response)
register_pldm_class(PollForPlatformEventMessage_Request)
register_pldm_class(PollForPlatformEventMessage_Response)
register_pldm_class(EventMessageSupported_Request)
register_pldm_class(EventMessageSupported_Response)
register_pldm_class(EventMessageBufferSize_Request)
register_pldm_class(EventMessageBufferSize_Response)
register_pldm_class(SetNumericSensorEnable_Request)
register_pldm_class(SetNumericSensorEnable_Response)
register_pldm_class(GetSensorReading_Request)
register_pldm_class(GetSensorReading_Response)
register_pldm_class(GetSensorThresholds_Request)
register_pldm_class(GetSensorThresholds_Response)
register_pldm_class(SetSensorThresholds_Request)
register_pldm_class(SetSensorThresholds_Response)
register_pldm_class(RestoreSensorThresholds_Request)
register_pldm_class(RestoreSensorThresholds_Response)
register_pldm_class(GetSensorHysteresis_Request)
register_pldm_class(GetSensorHysteresis_Response)
register_pldm_class(SetSensorHysteresis_Request)
register_pldm_class(SetSensorHysteresis_Response)
register_pldm_class(InitNumericSensor_Request)
register_pldm_class(InitNumericSensor_Response)
register_pldm_class(SetStateSensorEnables_Request)
register_pldm_class(SetStateSensorEnables_Response)
register_pldm_class(GetStateSensorReadings_Request)
register_pldm_class(GetStateSensorReadings_Response)
register_pldm_class(InitStateSensor_Request)
register_pldm_class(InitStateSensor_Response)
register_pldm_class(SetNumericEffecterEnable_Request)
register_pldm_class(SetNumericEffecterEnable_Response)
register_pldm_class(SetNumericEffecterValue_Request)
register_pldm_class(SetNumericEffecterValue_Response)
register_pldm_class(GetNumericEffecterValue_Request)
register_pldm_class(GetNumericEffecterValue_Response)
register_pldm_class(SetStateEffecterEnables_Request)
register_pldm_class(SetStateEffecterEnables_Response)
register_pldm_class(SetStateEffecterStates_Request)
register_pldm_class(SetStateEffecterStates_Response)
register_pldm_class(GetStateEffecterStates_Request)
register_pldm_class(GetStateEffecterStates_Response)
register_pldm_class(GetPLDMEventLogInfo_Request)
register_pldm_class(GetPLDMEventLogInfo_Response)
register_pldm_class(EnablePLDMEventLogging_Request)
register_pldm_class(EnablePLDMEventLogging_Response)
register_pldm_class(ClearPLDMEventLog_Request)
register_pldm_class(ClearPLDMEventLog_Response)
register_pldm_class(GetPLDMEventLogTimestamp_Request)
register_pldm_class(GetPLDMEventLogTimestamp_Response)
register_pldm_class(SetPLDMEventLogTimestamp_Request)
register_pldm_class(SetPLDMEventLogTimestamp_Response)
register_pldm_class(ReadPLDMEventLog_Request)
register_pldm_class(ReadPLDMEventLog_Response)
register_pldm_class(GetPLDMEventLogPolicyInfo_Request)
register_pldm_class(GetPLDMEventLogPolicyInfo_Response)
register_pldm_class(SetPLDMEventLogPolicy_Request)
register_pldm_class(SetPLDMEventLogPolicy_Response)
register_pldm_class(FindPLDMEventLogEntry_Request)
register_pldm_class(FindPLDMEventLogEntry_Response)
register_pldm_class(GetPDRRepositoryInfo_Request)
register_pldm_class(GetPDRRepositoryInfo_Response)
register_pldm_class(GetPDR_Request)
register_pldm_class(GetPDR_Response)
register_pldm_class(FindPDR_Request)
register_pldm_class(FindPDR_Response)
register_pldm_class(RunInitAgent_Request)
register_pldm_class(RunInitAgent_Response)
register_pldm_class(GetPDRRepositorySignature_Request)
register_pldm_class(GetPDRRepositorySignature_Response)
