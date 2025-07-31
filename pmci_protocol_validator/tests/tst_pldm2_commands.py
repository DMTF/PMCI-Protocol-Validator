# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0240 basic test cases.
##############################################################################

from testframework.utilities import common_send_receive
from pldm.type2 import *
from pldm.pdrs import *


def test_GetPDRRepositoryInfo(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get PDR Repository Info request """

    # Assemble the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetPDRRepositoryInfo_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    # Send the request and wait for the response
    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    # Validate header fields
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    # Validate response fields
    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPDRRepositoryInfo_Response.CommandValue)
    assert (RecvPacket[GetPDRRepositoryInfo_Response].CompletionCode == 0x00)
    assert (RecvPacket[GetPDRRepositoryInfo_Response].RepoInfo.RecordCount > 0x00)
    assert (RecvPacket[GetPDRRepositoryInfo_Response].RepoInfo.RepositorySize > 0x00)
    assert (RecvPacket[GetPDRRepositoryInfo_Response].RepoInfo.LargestRecordSize > 0x00)

    return RecvPacket


def test_GetPDRRepositorySignature(testFixture, lowerLayerHeaders):
    """ Test DSP0248 GetPDRRepositorySignature request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetPDRRepositorySignature_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPDRRepositorySignature_Response.CommandValue)
    assert (RecvPacket[GetPDRRepositorySignature_Response].CompletionCode == 0x00)
    assert (RecvPacket[GetPDRRepositorySignature_Response].PdrRepositorySignature != 0x00)

    return RecvPacket


def test_GetTerminusUID(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get Terminus UID request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetTerminusUID_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetTerminusUID_Request.CommandValue)
    assert (RecvPacket[GetTerminusUID_Response].CompletionCode == 0)

    return RecvPacket


def test_SetEventReceiver(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set Event Receiver request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetEventReceiver_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetEventReceiver_Request.CommandValue)
    assert (RecvPacket[SetEventReceiver_Response].CompletionCode == 0)

    return RecvPacket


def test_GetEventReceiver(testFixture, lowerLayerHeaders):
    """ Test DSP0248 GetEventReceiver_request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetEventReceiver_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetEventReceiver_Request.CommandValue)
    assert (RecvPacket[GetEventReceiver_Response].CompletionCode == 0)

    return RecvPacket


def test_PlatformEventMessage(testFixture, lowerLayerHeaders):
    """ Test DSP0248 PlatformEventMessage_request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / PlatformEventMessage_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == PlatformEventMessage_Request.CommandValue)
    assert (RecvPacket[PlatformEventMessage_Response].CompletionCode == 0)
    assert (RecvPacket[PlatformEventMessage_Response].Status <= 5)

    return RecvPacket


def test_PollForPlatformEventMessage(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Poll For Platform Event Message request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / PollForPlatformEventMessage_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == PollForPlatformEventMessage_Request.CommandValue)
    assert (RecvPacket[PollForPlatformEventMessage_Response].CompletionCode == 0)
    assert (RecvPacket[PollForPlatformEventMessage_Response].TransferFlag in [0, 1, 4, 5])
    assert (RecvPacket[PollForPlatformEventMessage_Response].EventClass <= 6)

    return RecvPacket


def test_EventMessageSupported(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Event Message Supported request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / EventMessageSupported_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == EventMessageSupported_Request.CommandValue)
    assert (RecvPacket[EventMessageSupported_Response].CompletionCode == 0)
    assert (RecvPacket[EventMessageSupported_Response].ResponseData.synchronyConfiguration <= 3)
    assert (RecvPacket[EventMessageSupported_Response].ResponseData.Reserved_2 == 0)
    assert (RecvPacket[EventMessageSupported_Response].ResponseData.Reserved_1 == 0)

    return RecvPacket


def test_EventMessageBufferSize(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Event Message Buffer Size request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / EventMessageBufferSize_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == EventMessageBufferSize_Request.CommandValue)
    assert (RecvPacket[EventMessageBufferSize_Response].CompletionCode == 0)

    return RecvPacket


def test_SetNumericSensorEnable(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set Numeric Sensor Enable request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetNumericSensorEnable_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetNumericSensorEnable_Request.CommandValue)
    assert (RecvPacket[SetNumericSensorEnable_Response].CompletionCode == 0)

    return RecvPacket


def test_GetSensorReading(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get Sensor Reading request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetSensorReading_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetSensorReading_Request.CommandValue)
    assert (RecvPacket[GetSensorReading_Response].CompletionCode == 0)

    assert (RecvPacket[GetSensorReading_Response].SensorData.SensorDataSize <= 5)
    assert (RecvPacket[GetSensorReading_Response].SensorData.SensorOperationalState <= 7)
    assert (RecvPacket[GetSensorReading_Response].SensorData.SensorEventMessageEnable <= 4)
    assert (RecvPacket[GetSensorReading_Response].SensorData.PresentState <= 10)
    assert (RecvPacket[GetSensorReading_Response].SensorData.PreviousState <= 10)
    assert (RecvPacket[GetSensorReading_Response].SensorData.EventState <= 10)

    return RecvPacket


def test_GetSensorThresholds(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get Sensor Thresholds request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetSensorThresholds_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetSensorThresholds_Request.CommandValue)
    assert (RecvPacket[GetSensorThresholds_Response].CompletionCode == 0)
    assert (RecvPacket[GetSensorThresholds_Response].ThresholdData.SensorDataSize <= 5)

    return RecvPacket


def test_SetSensorThresholds(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set Sensor Thresholds request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetSensorThresholds_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetSensorThresholds_Request.CommandValue)
    assert (RecvPacket[SetSensorThresholds_Response].CompletionCode == 0)

    return RecvPacket


def test_RestoreSensorThresholds(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Restore Sensor Thresholds request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / RestoreSensorThresholds_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == RestoreSensorThresholds_Request.CommandValue)
    assert (RecvPacket[RestoreSensorThresholds_Response].CompletionCode == 0)

    return RecvPacket


def test_GetSensorHysteresis(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get Sensor Hysteresis request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetSensorHysteresis_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetSensorHysteresis_Request.CommandValue)
    assert (RecvPacket[GetSensorHysteresis_Response].CompletionCode == 0)
    assert (RecvPacket[GetSensorHysteresis_Response].SensorDataSize <= 5)

    return RecvPacket


def test_SetSensorHysteresis(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set Sensor Hysteresis request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetSensorHysteresis_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetSensorHysteresis_Request.CommandValue)
    assert (RecvPacket[SetSensorHysteresis_Response].CompletionCode == 0)

    return RecvPacket


def test_InitNumericSensor_Request(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Init Numeric Sensor request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / InitNumericSensor_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == InitNumericSensor_Request.CommandValue)
    assert (RecvPacket[InitNumericSensor_Response].CompletionCode == 0)

    return RecvPacket


def test_SetStateSensorEnables_Request(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set State Sensor Enables request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetStateSensorEnables_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetStateSensorEnables_Request.CommandValue)
    assert (RecvPacket[SetStateSensorEnables_Response].CompletionCode == 0)

    return RecvPacket


def test_GetStateSensorReadings(testFixture, lowerLayerHeaders):
    """ Test DSP0248 GetStateSensorReadings_request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetStateSensorReadings_Requestxx()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetStateSensorReadings_Request.CommandValue)
    assert (RecvPacket[GetStateSensorReadings_Response].CompletionCode == 0)
    assert (RecvPacket[GetStateSensorReadings_Response].SensorReadingStateFields.SensorOperationalState <= 7)
    assert (RecvPacket[GetStateSensorReadings_Response].SensorReadingStateFields.PreviousState <= 7)
    assert (RecvPacket[GetStateSensorReadings_Response].SensorReadingStateFields.EventState <= 7)

    return RecvPacket


def test_InitStateSensor(testFixture, lowerLayerHeaders):
    """ Test DSP0248 InitStateSensor_request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / InitStateSensor_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == InitStateSensor_Request.CommandValue)
    assert (RecvPacket[InitStateSensor_Response].CompletionCode == 0)

    return RecvPacket


def test_SetNumericEffecterEnable(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set Numeric Effecter Enable request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetNumericEffecterEnable_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetNumericEffecterEnable_Request.CommandValue)
    assert (RecvPacket[SetNumericEffecterEnable_Response].CompletionCode == 0)

    return RecvPacket


def test_SetNumericEffecterValue(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set Numeric Effecter Value request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetNumericEffecterValue_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetNumericEffecterValue_Request.CommandValue)
    assert (RecvPacket[SetNumericEffecterValue_Response].CompletionCode == 0)

    return RecvPacket


def test_GetNumericEffecterValue(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get Numeric Effecter Value request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetNumericEffecterValue_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetNumericEffecterValue_Request.CommandValue)
    assert (RecvPacket[GetNumericEffecterValue_Response].CompletionCode == 0)
    assert (RecvPacket[GetNumericEffecterValue_Response].EffecterDataSize <= 5)
    assert (RecvPacket[GetNumericEffecterValue_Response].EffecterOperationalState <= 8)

    return RecvPacket


def test_SetStateEffecterEnables_Request(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set State Effecter Enables request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetStateEffecterEnables_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetStateEffecterEnables_Request.CommandValue)
    assert (RecvPacket[SetStateEffecterEnables_Response].CompletionCode == 0)

    return RecvPacket


def test_SetStateEffecterStates(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set State Effecter States request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetStateEffecterStates_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetStateEffecterStates_Request.CommandValue)
    assert (RecvPacket[SetStateEffecterStates_Response].CompletionCode == 0)

    return RecvPacket


def test_GetStateEffecterStates(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get State Effecter States request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetStateEffecterStates_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetStateEffecterStates_Request.CommandValue)
    assert (RecvPacket[GetStateEffecterStates_Response].CompletionCode == 0)
    assert (RecvPacket[GetStateEffecterStates_Response].CompositeEffecterCount >= 1)
    assert (RecvPacket[GetStateEffecterStates_Response].CompositeEffecterCount <= 8)

    return RecvPacket


def test_GetPLDMEventLogInfo(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get PLDM Event Log Info request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetPLDMEventLogInfo_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPLDMEventLogInfo_Request.CommandValue)
    assert (RecvPacket[GetPLDMEventLogInfo_Response].CompletionCode == 0)
    assert (RecvPacket[GetPLDMEventLogInfo_Response].EventLogInfo.LogOperationalStatus <= 6)
    assert (RecvPacket[GetPLDMEventLogInfo_Response].EventLogInfo.ActiveLogClearingPolicy <= 2)

    return RecvPacket


def test_EnablePLDMEventLogging(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Enable PLDM Event Logging"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / EnablePLDMEventLogging_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == EnablePLDMEventLogging_Request.CommandValue)
    assert (RecvPacket[EnablePLDMEventLogging_Response].CompletionCode == 0)
    assert (RecvPacket[EnablePLDMEventLogging_Response].LogOperationalStatus <= 6)

    return RecvPacket


def test_ClearPLDMEventLog(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Clear PLDM Event Log request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / ClearPLDMEventLog_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == ClearPLDMEventLog_Request.CommandValue)
    assert (RecvPacket[ClearPLDMEventLog_Response].CompletionCode == 0)
    assert (RecvPacket[ClearPLDMEventLog_Response].LogOperationalStatus <= 6)

    return RecvPacket


def test_GetPLDMEventLogTimestamp(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get PLDM EventLog Timestamp request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetPLDMEventLogTimestamp_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPLDMEventLogTimestamp_Request.CommandValue)
    assert (RecvPacket[GetPLDMEventLogTimestamp_Response].CompletionCode == 0)

    return RecvPacket


def test_SetPLDMEventLogTimestamp(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set PLDM EventLog Timestamp request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetPLDMEventLogTimestamp_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetPLDMEventLogTimestamp_Request.CommandValue)
    assert (RecvPacket[SetPLDMEventLogTimestamp_Response].CompletionCode == 0)

    return RecvPacket


def test_ReadPLDMEventLog(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Read PLDM Event Log request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / ReadPLDMEventLog_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == ReadPLDMEventLog_Request.CommandValue)
    assert (RecvPacket[ReadPLDMEventLog_Response].CompletionCode == 0)
    assert (RecvPacket[ReadPLDMEventLog_Response].SplitEntry <= 4)

    return RecvPacket


def test_GetPLDMEventLogPolicyInfo(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get PLDM Event Log Policy Info request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetPLDMEventLogPolicyInfo_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPLDMEventLogPolicyInfo_Request.CommandValue)
    assert (RecvPacket[GetPLDMEventLogPolicyInfo_Response].CompletionCode == 0)
    assert (RecvPacket[GetPLDMEventLogPolicyInfo_Response].Reserved == 0)

    return RecvPacket


def test_SetPLDMEventLogPolicy(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Set PLDM EventLog Policy request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetPLDMEventLogPolicy_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetPLDMEventLogPolicy_Request.CommandValue)
    assert (RecvPacket[SetPLDMEventLogPolicy_Response].CompletionCode == 0)

    return RecvPacket


def test_FindPLDMEventLogEntry(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Find PLDM Event Log Entry request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / FindPLDMEventLogEntry_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == FindPLDMEventLogEntry_Request.CommandValue)
    assert (RecvPacket[FindPLDMEventLogEntry_Response].CompletionCode == 0)

    return RecvPacket


def test_GetPDR(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get PDR request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetPDR_Request(RequestCount=150, TransferOperationFlag=1)
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPDR_Request.CommandValue)
    assert (RecvPacket[GetPDR_Response].CompletionCode == 0)

    return RecvPacket
