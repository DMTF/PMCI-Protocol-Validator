# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
PLDM Type 2 (PLDM for Platform Monitoring and Control) Scapy classes

File : test_dsp0248.py

Brief : PLDM Type 2 (PLDM for Platform Monitoring and Control) Scapy classes
"""

import pytest
from pmci_protocol_validator.pldm.dsp0248 import *


@pytest.mark.parametrize("class_type", PLDM_TYPE_2_PAYLOAD())
def test_PLDM_TYPE_2_PAYLOAD_class(class_type):
    """Verify PLDM_TYPE_2_PAYLOAD class initialization"""

    assert (class_type.PldmPayloadType == 0x02), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetTerminusUID_Request())
def test_GetTerminusUID_Request(class_type):
    """Verify GetTerminusUID_Request initialization"""

    assert (class_type.CommandValue == 0x03), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetTerminusUID_Response())
def test_GetTerminusUID_Response(class_type):
    """Verify GetTerminusUID_Response initialization"""

    assert (class_type.CommandValue == GetTerminusUID_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.UUID is not None)
    return


@pytest.mark.parametrize("class_type", SetEventReceiver_Request())
def test_SetEventReceiver_Request(class_type):
    "Verify SetEventReceiver_Request initialization"

    assert (class_type.CommandValue == 0x04), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.EventMessageGlobalEnable == 0)
    assert (class_type.TransportProtocolType == 0)
    assert (class_type.HeartbeatTimer == 0)
    return


@pytest.mark.parametrize("class_type", SetEventReceiver_Response())
def test_SetEventReceiver_Response(class_type):
    """Verify SetEventReceiver_Response initialization"""

    assert (class_type.CommandValue == SetEventReceiver_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetEventReceiver_Request())
def test_GetEventReceiver_Request(class_type):
    "Verify GetEventReceiver_Request initialization"

    assert (class_type.CommandValue == 5), "Incorrect command code"
    return


@pytest.mark.parametrize("class_type", GetEventReceiver_Response())
def test_GetEventReceiver_Response(class_type):
    """Verify GetEventReceiver_Response initialization"""

    assert (class_type.CommandValue == GetEventReceiver_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.CompletionCode == 0)
    assert (class_type.TransportProtocolType == 0)
    return


@pytest.mark.parametrize("class_type", SensorOpState())
def test_SensorOpState(class_type):
    "Verify SensorOpState initialization"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.PresentOpState == 0)
    assert (class_type.PreviousOpState == 0)
    return


@pytest.mark.parametrize("class_type", StateSensorState())
def test_StateSensorState(class_type):
    """Verify StateSensorState initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.SensorOffset == 0)
    assert (class_type.EventState == 0)
    assert (class_type.PreviousEventState == 0)
    return


@pytest.mark.parametrize("class_type", NumericSensorState())
def test_NumericSensorState(class_type):
    """Verify NumericSensorState initialization"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.EventState == 0)
    assert (class_type.PreviousEventState == 0)
    assert (class_type.SensorDataSize == 0)
    assert (class_type.PresentReading == 0)
    return


@pytest.mark.parametrize("class_type", SensorEventData())
def test_SensorEventData(class_type):
    """Verify SensorEventData initialization"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    assert (class_type.SensorEventClass == 0)
    return


@pytest.mark.parametrize("class_type", EffecterOpState())
def test_EffecterOpState(class_type):
    """Verify EffecterOpState initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.PresentOpState == 0)
    assert (class_type.PreviousOpState == 0)
    return


@pytest.mark.parametrize("class_type", EffecterEventData())
def test_EffecterEventData(class_type):
    """Verify EffecterEventData initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.EffecterID == 0)
    assert (class_type.EffecterEventClass == 0)
    return


@pytest.mark.parametrize("class_type", RedfishTaskExecutedEventData())
def test_RedfishTaskExecutedEventData(class_type):
    """Verify RedfishTaskExecutedEventData initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.OperationID == 0)
    return


@pytest.mark.parametrize("class_type", PldmMessagePollEventData())
def test_PldmMessagePollEventData(class_type):
    """Verify PldmMessagePollEventData initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.FormatVersion == 0)
    assert (class_type.EventID == 0)
    assert (class_type.DataTransferHandle == 0)
    return


@pytest.mark.parametrize("class_type", HeartbeatTimerElapsedEventData())
def test_HeartbeatTimerElapsedEventData(class_type):
    """Verify HeartbeatTimerElapsedEventData initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.FormatVersion == 1)
    assert (class_type.SequenceNumber == 0)
    return


@pytest.mark.parametrize("class_type", bejEncoding())
def test_bejEncoding(class_type):
    """Verify bejEncoding initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.BEJVersion == 0xF1F1F000)
    assert (class_type.Reserved == 0)
    assert (class_type.SchemaClass == 0)
    return


@pytest.mark.parametrize("class_type", RedfishMessageEventDataResources())
def test_RedfishMessageEventDataResources(class_type):
    """Verify RedfishMessageEventDataResources initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.EventSeverity == 0)
    return


@pytest.mark.parametrize("class_type", RedfishMessageEventData())
def test_RedfishMessageEventData(class_type):
    """Verify RedfishMessageEventData initialization"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.EventCount == 0)
    assert (class_type.EventDataLength == 0)
    assert (class_type.EventData is not None)
    return


@pytest.mark.parametrize("class_type", ChangeRecord())
def test_ChangeRecord(class_type):
    """Verify ChangeRecord initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.EventDataOperation == 0)
    assert (class_type.NumberOfChangeEntries is None)
    assert (class_type.ChangeEntry == [])
    return


@pytest.mark.parametrize("class_type", PldmPDRRepositoryChgEventData())
def test_PldmPDRRepositoryChgEventData(class_type):
    """Verify PldmPDRRepositoryChgEventData initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.EventDataFormat == 0)
    assert (class_type.NumberOfChangeRecords is None)
    assert (class_type.ChangeRecord == [])
    return


@pytest.mark.parametrize("class_type", PlatformEventMessage_Request())
def test_PlatformEventMessage_Request(class_type):
    """Verify PlatformEventMessage_Request initialization"""

    assert (class_type.CommandValue == 0x0A), "Incorrect command code"
    assert (len(class_type.fields_desc) == 11), "Incorrect number of fields"

    assert (class_type.FormatVersion == 1)
    assert (class_type.TID == 0)
    assert (class_type.EventClass == 0)
    return


@pytest.mark.parametrize("class_type", PlatformEventMessage_Response())
def test_PlatformEventMessage_Response(class_type):
    """Verify PlatformEventMessage_Response initialization"""

    assert (class_type.CommandValue == PlatformEventMessage_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.Status == 0)
    return


@pytest.mark.parametrize("class_type", PollForPlatformEventMessage_Request())
def test_PollForPlatformEventMessage_Request(class_type):
    """Verify PollForPlatformEventMessage_Request initialization"""

    assert (class_type.CommandValue == 0x0B), "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.FormatVersion == 1)
    assert (class_type.TransferOperationFlag == 1)
    assert (class_type.DataTransferHandle == 0)
    assert (class_type.EventIDToAcknowledge == 0)
    return


@pytest.mark.parametrize("class_type", PollForPlatformEventMessage_Response())
def test_PollForPlatformEventMessage_Response(class_type):
    """Verify PollForPlatformEventMessage_Response initialization"""

    assert (class_type.CommandValue == PollForPlatformEventMessage_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 16), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.TID == 0)
    assert (class_type.EventID == 0)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 1)
    assert (class_type.EventClass == 0)
    assert (class_type.EventDataSize == 0)
    assert (class_type.EventDataIntegrityChecksum == 0)
    return


@pytest.mark.parametrize("class_type", EventMessageSupported_Request())
def test_EventMessageSupported_Request(class_type):
    """Verify EventMessageSupported_Request initialization"""

    assert (class_type.CommandValue == 0x0C), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.FormatVersion == 1)
    return


@pytest.mark.parametrize("class_type", EventMessageSupported_Response.Data())
def test_EventMessageSupportedData(class_type):
    """Verify EventMessageSupported_Response initialization"""

    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"
    assert (class_type.synchronyConfiguration == 0)
    assert (class_type.Reserved_2 == 0)
    assert (class_type.AsynchronousMessagingWithHeartbeat == 0)
    assert (class_type.SynchronousMessaging == 0)
    assert (class_type.AsynchronousMessagingNoHeartbeat == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.NumberEventClassReturned == 0)
    assert (class_type.EventClass == [])
    return


@pytest.mark.parametrize("class_type", EventMessageSupported_Response())
def test_EventMessageSupported_Response(class_type):
    """Verify EventMessageSupported_Response initialization"""

    assert (class_type.CommandValue == EventMessageSupported_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.ResponseData is not None)
    return


@pytest.mark.parametrize("class_type", EventMessageBufferSize_Request())
def test_EventMessageBufferSize_Request(class_type):
    """Verify EventMessageBufferSize_Request initialization"""

    assert (class_type.CommandValue == 0x0D), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.EventReceiverMaxBufferSize == 0)
    return


@pytest.mark.parametrize("class_type", EventMessageBufferSize_Response())
def test_EventMessageBufferSize_Response(class_type):
    """Verify EventMessageBufferSize_Response initialization"""

    assert (class_type.CommandValue == EventMessageBufferSize_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.TerminusMaxBufferSize == 0)
    return


@pytest.mark.parametrize("class_type", SetNumericSensorEnable_Request())
def test_SetNumericSensorEnable_Request(class_type):
    """Verify SetNumericSensorEnable_Request initialization"""

    assert (class_type.CommandValue == 0x10), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    assert (class_type.SensorOperationalState == 0)
    assert (class_type.SensorEventMessageEnable == 0)
    return


@pytest.mark.parametrize("class_type", SetNumericSensorEnable_Response())
def test_SetNumericSensorEnable_Response(class_type):
    """Verify SetNumericSensorEnable_Response initialization"""

    assert (class_type.CommandValue == SetNumericSensorEnable_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetSensorReading_Request())
def test_GetSensorReading_Request(class_type):
    """Verify GetSensorReading_Request initialization"""

    assert (class_type.CommandValue == 0x11), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    assert (class_type.RearmEventState == 0)
    return


@pytest.mark.parametrize("class_type", GetSensorReading_Response.Data())
def test_GetSensorReadingData(class_type):
    """Verify GetSensorReading_Response data structure"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"
    assert (class_type.SensorDataSize == 1)
    assert (class_type.SensorOperationalState == 0)
    assert (class_type.SensorEventMessageEnable == 0)
    assert (class_type.PresentState == 0)
    assert (class_type.PreviousState == 0)
    assert (class_type.EventState == 0)
    assert (class_type.PresentReading == 0)
    return


@pytest.mark.parametrize("class_type", GetSensorReading_Response())
def test_GetSensorReading_Response(class_type):
    """Verify GetSensorReading_Response initialization"""

    assert (class_type.CommandValue == GetSensorReading_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.SensorData is not None)
    return


@pytest.mark.parametrize("class_type", GetSensorThresholds_Request())
def test_GetSensorThresholds_Request(class_type):
    """Verify GetSensorThresholds_Request initialization"""

    assert (class_type.CommandValue == 0x12), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    return


@pytest.mark.parametrize("class_type", GetSensorThresholds_Response.Data())
def test_GetSensorThresholdsData(class_type):
    """Verify GetSensorThresholds_Response initialization"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"
    assert (class_type.SensorDataSize == 0)
    assert (class_type.UpperThresholdWarning == 0)
    assert (class_type.UpperThresholdCritical == 0)
    assert (class_type.UpperThresholdFatal == 0)
    assert (class_type.LowerThresholdWarning == 0)
    assert (class_type.LowerThresholdCritical == 0)
    assert (class_type.LowerThresholdFatal == 0)
    return


@pytest.mark.parametrize("class_type", GetSensorThresholds_Response())
def test_GetSensorThresholds_Response(class_type):
    """Verify GetSensorThresholds_Response initialization"""

    assert (class_type.CommandValue == GetSensorThresholds_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.ThresholdData is not None)
    return


@pytest.mark.parametrize("class_type", SetSensorThresholds_Request())
def test_SetSensorThresholds_Request(class_type):
    """Verify SetSensorThresholds_Request initialization"""

    assert (class_type.CommandValue == 0x13), "Incorrect command code"
    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    assert (class_type.SensorDataSize == 0)
    assert (class_type.UpperThresholdWarning == 0)
    assert (class_type.UpperThresholdCritical == 0)
    assert (class_type.UpperThresholdFatal == 0)
    assert (class_type.LowerThresholdWarning == 0)
    assert (class_type.LowerThresholdCritical == 0)
    assert (class_type.LowerThresholdFatal == 0)
    return


@pytest.mark.parametrize("class_type", SetSensorThresholds_Response())
def test_SetSensorThresholds_Response(class_type):
    """Verify SetSensorThresholds_Response initialization"""

    assert (class_type.CommandValue == SetSensorThresholds_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", RestoreSensorThresholds_Request())
def test_RestoreSensorThresholds_Request(class_type):
    """Verify RestoreSensorThresholds_Request initialization"""

    assert (class_type.CommandValue == 0x14), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    return


@pytest.mark.parametrize("class_type", RestoreSensorThresholds_Response())
def test_RestoreSensorThresholds_Response(class_type):
    """Verify RestoreSensorThresholds_Response initialization"""

    assert (class_type.CommandValue == RestoreSensorThresholds_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetSensorHysteresis_Request())
def test_GetSensorHysteresis_Request(class_type):
    """Verify GetSensorHysteresis_Request initialization"""

    assert (class_type.CommandValue == 0x15), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    return


@pytest.mark.parametrize("class_type", GetSensorHysteresis_Response())
def test_GetSensorHysteresis_Response(class_type):
    """Verify GetSensorHysteresis_Response initialization"""

    assert (class_type.CommandValue == GetSensorHysteresis_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.SensorDataSize == 0)
    assert (class_type.HysteresisValue == 0)
    return


@pytest.mark.parametrize("class_type", SetSensorHysteresis_Request())
def test_SetSensorHysteresis_Request(class_type):
    """Verify SetSensorHysteresis_Request initialization"""

    assert (class_type.CommandValue == 0x16), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    assert (class_type.SensorDataSize == 0)
    assert (class_type.HysteresisValue == 0)
    return


@pytest.mark.parametrize("class_type", SetSensorHysteresis_Response())
def test_SetSensorHysteresis_Response(class_type):
    """Verify SetSensorHysteresis_Response initialization"""

    assert (class_type.CommandValue == SetSensorHysteresis_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", InitNumericSensor_Request())
def test_InitNumericSensor_Request(class_type):
    """Verify InitNumericSensor_Request initialization"""

    assert (class_type.CommandValue == 0x17), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    assert (class_type.SensorOperationalState == 0)
    assert (class_type.SensorPresentState == 0)
    assert (class_type.EventMsgEnable == 0)
    assert (class_type.SetNumericReading == 0)
    return


@pytest.mark.parametrize("class_type", InitNumericSensor_Response())
def test_InitNumericSensor_Response(class_type):
    """Verify InitNumericSensor_Response initialization"""

    assert (class_type.CommandValue == InitNumericSensor_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", SetStateSensorField())
def test_SetStateSensorField(class_type):
    """Verify SetStateSensorField initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.SensorOperationalState == 0)
    assert (class_type.EventMessageEnable == 0)
    return


@pytest.mark.parametrize("class_type", SetStateSensorEnables_Request())
def test_SetStateSensorEnables_Request(class_type):
    """Verify SetStateSensorEnables_Request initialization"""

    assert (class_type.CommandValue == 0x20), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    assert (class_type.CompositeSensorCount is None)
    assert (class_type.SensorInformation == [])
    return


@pytest.mark.parametrize("class_type", SetStateSensorEnables_Response())
def test_SetStateSensorEnables_Response(class_type):
    """Verify SetStateSensorEnables_Response initialization"""

    assert (class_type.CommandValue == SetStateSensorEnables_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetStateSensorReadings_Request())
def test_GetStateSensorReadings_Request(class_type):
    """Verify GetStateSensorReadings_Request initialization"""

    assert (class_type.CommandValue == 0x21), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    assert (class_type.SensorRearm == 0)
    assert (class_type.Reserved == 0)
    return


@pytest.mark.parametrize("class_type", GetStateSensorField())
def test_GetStateSensorField(class_type):
    """Verify GetStateSensorField initialization"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.SensorOperationalState == 0)
    assert (class_type.PresentState == 0)
    assert (class_type.PreviousState == 0)
    assert (class_type.EventState == 0)
    return


@pytest.mark.parametrize("class_type", GetStateSensorReadings_Response())
def test_GetStateSensorReadings_Response(class_type):
    """Verify GetStateSensorReadings_Response initialization"""

    assert (class_type.CommandValue == GetStateSensorReadings_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.CompositeSensorCount == 0)
    assert (class_type.SensorReadingStateFields is not None)
    return


@pytest.mark.parametrize("class_type", InitStateSensorField())
def test_InitStateSensorField(class_type):
    """Verify InitStateSensorField initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.SensorOperationalState == 0)
    assert (class_type.SensorPresentState == 0)
    assert (class_type.EventMsgEnable == 0)
    return


@pytest.mark.parametrize("class_type", InitStateSensor_Request())
def test_InitStateSensor_Request(class_type):
    """Verify InitStateSensor_Request initialization"""

    assert (class_type.CommandValue == 0x22), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.SensorID == 0)
    assert (class_type.CompositeSensorCount == 0)
    assert (class_type.InitField is not None)
    return


@pytest.mark.parametrize("class_type", InitStateSensor_Response())
def test_InitStateSensor_Response(class_type):
    """Verify InitStateSensor_Response initialization"""

    assert (class_type.CommandValue == InitStateSensor_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", SetNumericEffecterEnable_Request())
def test_SetNumericEffecterEnable_Request(class_type):
    """Verify SetNumericEffecterEnable_Request initialization"""

    assert (class_type.CommandValue == 0x30), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.EffecterID == 0)
    assert (class_type.EffecterOperationalState == 0)
    return


@pytest.mark.parametrize("class_type", SetNumericEffecterEnable_Response())
def test_SetNumericEffecterEnable_Response(class_type):
    """Verify SetNumericEffecterEnable_Response initialization"""

    assert (class_type.CommandValue == SetNumericEffecterEnable_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", SetNumericEffecterValue_Request())
def test_SetNumericEffecterValue_Request(class_type):
    """Verify SetNumericEffecterValue_Request initialization"""

    assert (class_type.CommandValue == 0x31), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.EffecterID == 0)
    assert (class_type.EffecterDataSize == 0)
    assert (class_type.EffecterValue == 0)
    return


@pytest.mark.parametrize("class_type", SetNumericEffecterValue_Response())
def test_SetNumericEffecterValue_Response(class_type):
    """Verify SetNumericEffecterValue_Response initialization"""

    assert (class_type.CommandValue == SetNumericEffecterValue_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetNumericEffecterValue_Request())
def test_GetNumericEffecterValue_Request(class_type):
    """Verify GetNumericEffecterValue_Request initialization"""

    assert (class_type.CommandValue == 0x32), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.EffecterID == 0)
    return


@pytest.mark.parametrize("class_type", GetNumericEffecterValue_Response())
def test_GetNumericEffecterValue_Response(class_type):
    """Verify GetNumericEffecterValue_Response initialization"""

    assert (class_type.CommandValue == GetNumericEffecterValue_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.EffecterDataSize == 0)
    assert (class_type.EffecterOperationalState == 0)
    assert (class_type.pendingValue == 0)
    assert (class_type.presentValue == 0)
    return


@pytest.mark.parametrize("class_type", SetStateEffecterField())
def test_SetStateEffecterField(class_type):
    """Verify SetStateEffecterField initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.EffecterOperationalState == 0)
    assert (class_type.EventMsgEnable == 0)
    return


@pytest.mark.parametrize("class_type", SetStateEffecterEnables_Request())
def test_SetStateEffecterEnables_Request(class_type):
    "Verify SetStateEffecterEnables_Request initialization"

    assert (class_type.CommandValue == 0x38), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.EffecterID == 0)
    assert (class_type.CompositeEffecterCount == 1)
    assert (class_type.InitField is not None)
    return


@pytest.mark.parametrize("class_type", SetStateEffecterEnables_Response())
def test_SetStateEffecterEnables_Response(class_type):
    """Verify SetStateEffecterEnables_Response initialization"""

    assert (class_type.CommandValue == SetStateEffecterEnables_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", SetStateEffecterStates_Request())
def test_SetStateEffecterStates_Request(class_type):
    """Verify SetStateEffecterStates_Request initialization"""

    assert (class_type.CommandValue == 0x39), "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.EffecterID == 0)
    assert (class_type.CompositeEffecterCount == 1)
    assert (class_type.SetRequest == 0)
    assert (class_type.EffecterState == 0)
    return


@pytest.mark.parametrize("class_type", SetStateEffecterStates_Response())
def test_SetStateEffecterStates_Response(class_type):
    """Verify SetStateEffecterStates_Response initialization"""

    assert (class_type.CommandValue == SetStateEffecterStates_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetStateEffecterStates_Request())
def test_GetStateEffecterStates_Request(class_type):
    """Verify GetStateEffecterStates_Request initialization"""

    assert (class_type.CommandValue == 0x3A), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.EffecterID == 0)
    return


@pytest.mark.parametrize("class_type", GetStateEffecterStatesFields())
def test_GetStateEffecterStatesFields(class_type):
    """Verify GetStateEffecterStatesFields initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.EffecterOperationalState == 0)
    assert (class_type.PendingState == 0)
    assert (class_type.PresentState == 0)
    return


@pytest.mark.parametrize("class_type", GetStateEffecterStates_Response())
def test_GetStateEffecterStates_Response(class_type):
    """Verify GetStateEffecterStates_Response initialization"""

    assert (class_type.CommandValue == GetStateEffecterStates_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.CompositeEffecterCount == 1)
    assert (class_type.StateFields is not None)
    return


@pytest.mark.parametrize("class_type", GetPDRRepositoryInfo_Request())
def test_GetPDRRepositoryInfo_Request(class_type):
    """Verify GetPDRRepositoryInfo_Request initialization"""

    assert (class_type.CommandValue == 0x50), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetPDRRepositoryInfo_Response.Data())
def test_GetPDRRepositoryInfo(class_type):
    """Verify GetPDRRepositoryInfo_Response initialization"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"
    assert (class_type.RepositoryState == 0)
    assert (class_type.UpdateTime is not None)
    assert (class_type.OEMUpdateTime is not None)
    assert (class_type.RecordCount == 0)
    assert (class_type.RepositorySize == 0)
    assert (class_type.LargestRecordSize == 0)
    assert (class_type.DataTransferHandleTimeout == 1)
    return


@pytest.mark.parametrize("class_type", GetPDRRepositoryInfo_Response())
def test_GetPDRRepositoryInfo_Response(class_type):
    """Verify GetPDRRepositoryInfo_Response initialization"""

    assert (class_type.CommandValue == GetPDRRepositoryInfo_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.RepoInfo is not None)
    return


@pytest.mark.parametrize("class_type", GetPDR_Request())
def test_GetPDR_Request(class_type):
    """Verify GetPDR_Request initialization"""

    assert (class_type.CommandValue == 0x51), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.RecordHandle == 0)
    assert (class_type.DataTransferHandle == 0)
    assert (class_type.TransferOperationFlag == 0)
    assert (class_type.RequestCount == 0)
    assert (class_type.RecordChangeNumber == 0)
    return


@pytest.mark.parametrize("class_type", GetPDR_Response())
def test_GetPDR_Response(class_type):
    """Verify GetPDR_Response initialization"""

    assert (class_type.CommandValue == GetPDR_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NextRecordHandle == 0)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 1)
    assert (class_type.ResponseCount == 0)
    return


@pytest.mark.parametrize("class_type", FindPDR_Request())
def test_FindPDR_Request(class_type):
    """Verify FindPDR_Request initialization"""

    assert (class_type.CommandValue == 0x52), "Incorrect command code"
    assert (len(class_type.fields_desc) == 21), "Incorrect number of fields"

    assert (class_type.FindHandle == 0)
    assert (class_type.FindOperationFlag == 0)
    assert (class_type.RequestCount == 0)
    assert (class_type.PDRType == 0)
    assert (class_type.ParameterFormatNumber == 0)
    assert (class_type.Wildcard_8 == 0)
    assert (class_type.Wildcard_7 == 0)
    assert (class_type.Wildcard_6 == 0)
    assert (class_type.Wildcard_5 == 0)
    assert (class_type.Wildcard_4 == 0)
    assert (class_type.Wildcard_3 == 0)
    assert (class_type.Wildcard_2 == 0)
    assert (class_type.Wildcard_1 == 0)
    assert (class_type.Wildcard_16 == 0)
    assert (class_type.Wildcard_15 == 0)
    assert (class_type.Wildcard_14 == 0)
    assert (class_type.Wildcard_13 == 0)
    assert (class_type.Wildcard_12 == 0)
    assert (class_type.Wildcard_11 == 0)
    assert (class_type.Wildcard_10 == 0)
    assert (class_type.Wildcard_9 == 0)
    return


@pytest.mark.parametrize("class_type", FindPDR_Response())
def test_FindPDR_Response(class_type):
    """Verify FindPDR_Response initialization"""

    assert (class_type.CommandValue == FindPDR_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NextFindHandle == 0)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 1)
    assert (class_type.ResponseCount == 0)
    assert (class_type.RecordData == [])
    return


@pytest.mark.parametrize("class_type", RunInitAgent_Request())
def test_RunInitAgent_Request(class_type):
    """Verify RunInitAgent_Request initialization"""

    assert (class_type.CommandValue == 0x58), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.InitConditionEmulation == 0)
    assert (class_type.TID == 0)
    return


@pytest.mark.parametrize("class_type", RunInitAgent_Response())
def test_RunInitAgent_Response(class_type):
    """Verify RunInitAgent_Response initialization"""

    assert (class_type.CommandValue == RunInitAgent_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetPDRRepositorySignature_Request())
def test_GetPDRRepositorySignature_Request(class_type):
    """Verify GetPDRRepositorySignature_Request initialization"""

    assert (class_type.CommandValue == 0x53), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetPDRRepositorySignature_Response())
def test_GetPDRRepositorySignature_Response(class_type):
    """Verify GetPDRRepositorySignature_Response initialization"""

    assert (class_type.CommandValue == GetPDRRepositorySignature_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.PdrRepositorySignature == 0)
    return


@pytest.mark.parametrize("class_type", GetPLDMEventLogInfo_Request())
def test_GetPLDMEventLogInfo_Request(class_type):
    """Verify GetPLDMEventLogInfo_Request initialization"""

    assert (class_type.CommandValue == 0x40), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetPLDMEventLogInfo_Response.Data())
def test_GetPLDMEventLogInfo(class_type):
    """Verify GetPLDMEventLogInfo_Response data structure"""

    assert (len(class_type.fields_desc) == 11), "Incorrect number of fields"
    assert (class_type.LogOperationalStatus == 0)
    assert (class_type.ActiveLogClearingPolicy == 0)
    assert (class_type.EntryCount == 0)
    assert (class_type.StoragePercentUsed == 0)
    assert (class_type.PercentWear == 0)
    assert (class_type.MostRecentAddTimestampUTCOffset == 0)
    assert (class_type.MostRecentAddTimestampSeconds is not None)
    assert (class_type.MostRecentAddTimestamp100s == 0)
    assert (class_type.MostRecentEraseTimestampUTCOffset == 0)
    assert (class_type.MostRecentEraseTimestampSeconds is not None)
    assert (class_type.MostRecentEraseTimestamp100s == 0)
    return


@pytest.mark.parametrize("class_type", GetPLDMEventLogInfo_Response())
def test_GetPLDMEventLogInfo_Response(class_type):
    """Verify GetPLDMEventLogInfo_Response initialization"""

    assert (class_type.CommandValue == GetPLDMEventLogInfo_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.EventLogInfo is not None)
    return


@pytest.mark.parametrize("class_type", EnablePLDMEventLogging_Request())
def test_EnablePLDMEventLogging_Request(class_type):
    """Verify EnablePLDMEventLogging_Request initialization"""

    assert (class_type.CommandValue == 0x41), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.EnableLogging == 0)
    return


@pytest.mark.parametrize("class_type", EnablePLDMEventLogging_Response())
def test_EnablePLDMEventLogging_Response(class_type):
    """Verify EnablePLDMEventLogging_Response initialization"""

    assert (class_type.CommandValue == EnablePLDMEventLogging_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.LogOperationalStatus == 0)
    return


@pytest.mark.parametrize("class_type", ClearPLDMEventLog_Request())
def test_ClearPLDMEventLog_Request(class_type):
    """Verify ClearPLDMEventLog_Request initialization"""

    assert (class_type.CommandValue == 0x42), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", ClearPLDMEventLog_Response())
def test_ClearPLDMEventLog_Response(class_type):
    """Verify ClearPLDMEventLog_Response initialization"""

    assert (class_type.CommandValue == ClearPLDMEventLog_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.LogOperationalStatus == 0)
    return


@pytest.mark.parametrize("class_type", GetPLDMEventLogTimestamp_Request())
def test_GetPLDMEventLogTimestamp_Request(class_type):
    """Verify GetPLDMEventLogTimestamp_Request initialization"""

    assert (class_type.CommandValue == 0x43), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetPLDMEventLogTimestamp_Response())
def test_GetPLDMEventLogTimestamp_Response(class_type):
    """Verify GetPLDMEventLogTimestamp_Response initialization"""

    assert (class_type.CommandValue == GetPLDMEventLogTimestamp_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.EntryTimestampUTCOffset == 0)
    assert (class_type.EntryTimestampSeconds is not None)
    assert (class_type.EntryTimestamp100s == 0)
    return


@pytest.mark.parametrize("class_type", SetPLDMEventLogTimestamp_Request())
def test_SetPLDMEventLogTimestamp_Request(class_type):
    """Verify SetPLDMEventLogTimestamp_Request initialization"""

    assert (class_type.CommandValue == 0x44), "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.EntryTimestampUTCOffset == 0)
    assert (class_type.EntryTimestampSeconds is not None)
    assert (class_type.EntryTimestamp100s == 0)
    assert (class_type.LogUpdateEvent == 0)
    return


@pytest.mark.parametrize("class_type", SetPLDMEventLogTimestamp_Response())
def test_SetPLDMEventLogTimestamp_Response(class_type):
    """Verify SetPLDMEventLogTimestamp_Response initialization"""

    assert (class_type.CommandValue == SetPLDMEventLogTimestamp_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.EntryTimestampUTCOffset == 0)
    assert (class_type.EntryTimestampSeconds is not None)
    assert (class_type.EntryTimestamp100s == 0)
    assert (class_type.TimestampResolution == 0)
    return


@pytest.mark.parametrize("class_type", ReadPLDMEventLog_Request())
def test_ReadPLDMEventLog_Request(class_type):
    """Verify ReadPLDMEventLog_Request initialization"""

    assert (class_type.CommandValue == 0x45), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.EntryID == 0)
    assert (class_type.TransferOperationFlag == 0)
    return


@pytest.mark.parametrize("class_type", ReadPLDMEventLog_Response())
def test_ReadPLDMEventLog_Response(class_type):
    """Verify ReadPLDMEventLog_Response initialization"""

    assert (class_type.CommandValue == ReadPLDMEventLog_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NextEntryID == 0)
    assert (class_type.SplitEntry == 0)
    assert (class_type.TransferredDataSize == 0)
    assert (class_type.TransferredEntryData == [])
    return


@pytest.mark.parametrize("class_type", GetPLDMEventLogPolicyInfo_Request())
def test_GetPLDMEventLogPolicyInfo_Request(class_type):
    """Verify GetPLDMEventLogPolicyInfo_Request initialization"""

    assert (class_type.CommandValue == 0x46), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetPLDMEventLogPolicyInfo_Response.Data())
def test_GetPLDMEventLogPolicyInfoData(class_type):
    """Verify GetPLDMEventLogPolicyInfo_Response data structure"""

    assert (len(class_type.fields_desc) == 14), "Incorrect number of fields"
    assert (class_type.Reserved == 0)
    assert (class_type.MPercentageConfgurable == 0)
    assert (class_type.NPercentageConfgurable == 0)
    assert (class_type.AgePercentageConfgurable == 0)
    assert (class_type.NMin == 0)
    assert (class_type.NMax == 0)
    assert (class_type.NPercentageMin == 0)
    assert (class_type.NPercentageMax == 0)
    assert (class_type.MMin == 0)
    assert (class_type.MMax == 0)
    assert (class_type.MPercentageMin == 0)
    assert (class_type.MPercentageMax == 0)
    assert (class_type.AgeMin == 0)
    assert (class_type.AgeMax == 0)
    return


@pytest.mark.parametrize("class_type", GetPLDMEventLogPolicyInfo_Response())
def test_GetPLDMEventLogPolicyInfo_Response(class_type):
    """Verify GetPLDMEventLogPolicyInfo_Response initialization"""

    assert (class_type.CommandValue == GetPLDMEventLogPolicyInfo_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.LogInfo is not None)
    return


@pytest.mark.parametrize("class_type", SetPLDMEventLogPolicy_Request())
def test_SetPLDMEventLogPolicy_Request(class_type):
    """Verify SetPLDMEventLogPolicy_Request initialization"""

    assert (class_type.CommandValue == 0x47), "Incorrect command code"
    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.SetOperation == 0)
    assert (class_type.N == 0)
    assert (class_type.NPercentage == 0)
    assert (class_type.M == 0)
    assert (class_type.MPercentage == 0)
    assert (class_type.Age == 0)
    return


@pytest.mark.parametrize("class_type", SetPLDMEventLogPolicy_Response())
def test_SetPLDMEventLogPolicy_Response(class_type):
    """Verify SetPLDMEventLogPolicy_Response initialization"""

    assert (class_type.CommandValue == SetPLDMEventLogPolicy_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", FindPLDMEventLogEntry_Request())
def test_FindPLDMEventLogEntry_Request(class_type):
    """Verify FindPLDMEventLogEntry_Request initialization"""

    assert (class_type.CommandValue == 0x48), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.SearchType == 0)
    assert (class_type.StartingPoint == 0)
    assert (class_type.CompareTimestampUTCOffset == 0)
    assert (class_type.CompareTimestampSeconds is not None)
    assert (class_type.CompareTimestamp100s == 0)
    return


@pytest.mark.parametrize("class_type", FindPLDMEventLogEntry_Response())
def test_FindPLDMEventLogEntry_Response(class_type):
    """Verify FindPLDMEventLogEntry_Response initialization"""

    assert (class_type.CommandValue == FindPLDMEventLogEntry_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.EntryID == 0)
    return
