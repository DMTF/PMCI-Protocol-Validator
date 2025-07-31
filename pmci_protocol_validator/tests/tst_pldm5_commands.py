# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0267 test cases.
##############################################################################

from pmci_protocol_validator.framework.utilities import common_send_receive
from pmci_protocol_validator.pldm.classes.dsp0267 import (
    PLDM_HEADER,
    QueryDeviceIdentifiers_Request,
    QueryDeviceIdentifiers_Response,
    GetFirmwareParameters_Request,
    GetFirmwareParameters_Response,
    QueryDownstreamDevices_Request,
    QueryDownstreamDevices_Response,
    QueryDownstreamIdentifiers_Request,
    QueryDownstreamIdentifiers_Response,
    GetDownstreamFirmwareParameters_Request,
    GetDownstreamFirmwareParameters_Response,
    RequestUpdate_Request,
    RequestUpdate_Response,
    GetDeviceMetaData_Request,
    GetDeviceMetaData_Response,
    PassComponentTable_Request,
    PassComponentTable_Response,
    UpdateComponent_Request,
    UpdateComponent_Response,
    ActivateFirmware_Request,
    ActivateFirmware_Response,
    GetStatus_Request,
    GetStatus_Response,
    CancelUpdateComponent_Request,
    CancelUpdateComponent_Response,
    CancelUpdate_Request,
    CancelUpdate_Response,
    ActivatePendingComponentImageSet_Request,
    ActivatePendingComponentImageSet_Response,
    ActivatePendingComponentImage_Request,
    ActivatePendingComponentImage_Response,
    RequestDownstreamDeviceUpdate_Request,
    RequestDownstreamDeviceUpdate_Response
)


def test_QueryDeviceIdentifiers(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Query Device Identifiers request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / QueryDeviceIdentifiers_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == QueryDeviceIdentifiers_Response.CommandValue)
    assert (RecvPacket[QueryDeviceIdentifiers_Response].CompletionCode == 0x00)

    return RecvPacket


def test_GetFirmwareParameters(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get Firmware Parameters request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetFirmwareParameters_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetFirmwareParameters_Response.CommandValue)
    assert (RecvPacket[GetFirmwareParameters_Response].CompletionCode == 0x00)
    assert (RecvPacket[GetFirmwareParameters_Response].Parameters.FirmwareDeviceUpdateModeRestrictionsReserved_0 == 0)
    assert (RecvPacket[GetFirmwareParameters_Response].Parameters.GetFirmwareParametersReserved_0 == 0)
    assert (RecvPacket[GetFirmwareParameters_Response].Parameters.GetFirmwareParametersReserved_1 == 0)
    assert (RecvPacket[GetFirmwareParameters_Response].Parameters.ActiveComponentImageSetVersionStringType <= 5)
    assert (RecvPacket[GetFirmwareParameters_Response].Parameters.PendingComponentImageSetVersionStringType <= 5)

    return RecvPacket


def test_QueryDownstreamDevices(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Query Downstream Devices request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / QueryDownstreamDevices_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == QueryDownstreamDevices_Response.CommandValue)
    assert (RecvPacket[QueryDownstreamDevices_Response].CompletionCode == 0x00)
    assert (RecvPacket[QueryDownstreamDevices_Response].Parameters.DownstreamDeviceUpdateSupported <= 1)
    assert (RecvPacket[QueryDownstreamDevices_Response].Parameters.Reserved_0 == 0)
    assert (RecvPacket[QueryDownstreamDevices_Response].Parameters.Reserved_1 == 0)

    return RecvPacket


def test_QueryDownstreamIdentifiers(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Query Downstream Identifiers request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / QueryDownstreamIdentifiers_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == QueryDownstreamIdentifiers_Response.CommandValue)
    assert (RecvPacket[QueryDownstreamIdentifiers_Response].CompletionCode == 0x00)
    assert (RecvPacket[QueryDownstreamIdentifiers_Response].TransferFlag in [1, 2, 4, 5])

    return RecvPacket


def test_GetDownstreamFirmwareParameters(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get Downstream Firmware Parameters request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetDownstreamFirmwareParameters_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetDownstreamFirmwareParameters_Response.CommandValue)
    assert (RecvPacket[GetDownstreamFirmwareParameters_Response].CompletionCode == 0x00)
    assert (RecvPacket[GetDownstreamFirmwareParameters_Response].Parameters.TransferFlag in [1, 2, 4, 5])
    assert (RecvPacket[GetDownstreamFirmwareParameters_Response].Parameters.FDPCapabilitiesDuringUpdateReserved_1 == 0)
    assert (RecvPacket[GetDownstreamFirmwareParameters_Response].Parameters.FDPCapabilitiesDuringUpdateReserved_0 == 0)
    assert (RecvPacket[GetDownstreamFirmwareParameters_Response].Parameters.FDPCapabilitiesDuringUpdateReserved_2 == 0)
    assert (RecvPacket[GetDownstreamFirmwareParameters_Response].Parameters.FDPCapabilitiesDuringUpdateReserved_3 == 0)

    return RecvPacket


def test_RequestUpdate(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Request Update request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / RequestUpdate_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == RequestUpdate_Response.CommandValue)
    assert (RecvPacket[RequestUpdate_Response].CompletionCode == 0x00)
    assert (RecvPacket[RequestUpdate_Response].FDWillSendGetPackageDataCommand == 0)

    return RecvPacket


def test_GetDeviceMetaData(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get Device Meta Data request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetDeviceMetaData_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetDeviceMetaData_Response.CommandValue)
    assert (RecvPacket[GetDeviceMetaData_Response].CompletionCode == 0x00)
    assert (RecvPacket[GetDeviceMetaData_Response].TransferFlag in [1, 2, 4, 5])

    return RecvPacket


def test_PassComponentTable(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Pass Component Table request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / PassComponentTable_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == PassComponentTable_Response.CommandValue)
    assert (RecvPacket[PassComponentTable_Response].CompletionCode == 0x00)
    assert (RecvPacket[PassComponentTable_Response].ComponentResponse <= 1)
    assert (RecvPacket[PassComponentTable_Response].ComponentResponseCode <= 11)

    return RecvPacket


def test_UpdateComponent(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Update Component request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / UpdateComponent_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == UpdateComponent_Response.CommandValue)
    assert (RecvPacket[UpdateComponent_Response].CompletionCode == 0x00)
    assert (RecvPacket[UpdateComponent_Response].ComponentCompatibilityResponse <= 1)
    assert (RecvPacket[UpdateComponent_Response].ComponentCompatibilityResponseCode <= 11)
    assert (RecvPacket[UpdateComponent_Response].Reserved_0 == 0)
    assert (RecvPacket[UpdateComponent_Response].Reserved_1 == 0)

    return RecvPacket


def test_ActivateFirmware(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Activate Firmware request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / ActivateFirmware_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == ActivateFirmware_Response.CommandValue)
    assert (RecvPacket[ActivateFirmware_Response].CompletionCode == 0x00)

    return RecvPacket


def test_GetStatus(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Get Get Status request """

    # Assemble the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetStatus_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    # Send the request and wait for the response
    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    # Validate header fields
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    # Validate response fields
    assert (RecvPacket[PLDM_HEADER].CommandCode == GetStatus_Response.CommandValue)
    assert (RecvPacket[GetStatus_Response].CompletionCode == 0x00)

    return RecvPacket


def test_CancelUpdateComponent(testFixture, lowerLayerHeaders):
    """ Test DSP0248 CancelUpdateComponent request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / CancelUpdateComponent_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == CancelUpdateComponent_Response.CommandValue)
    assert (RecvPacket[CancelUpdateComponent_Response].CompletionCode == 0x80)  # ERROR not in update mode
###    assert (RecvPacket[CancelUpdate_Response].CompletionCode == 0x00) # SUCCESS

    return RecvPacket


def test_CancelUpdate(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Cancel Update request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / CancelUpdate_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == CancelUpdate_Response.CommandValue)
    assert (RecvPacket[CancelUpdate_Response].CompletionCode == 0x80)
###    assert (RecvPacket[CancelUpdate_Response].CompletionCode == 0x00)

    return RecvPacket


def test_ActivatePendingComponentImageSet(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Activate Pending Component Image Set request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / ActivatePendingComponentImageSet_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == ActivatePendingComponentImageSet_Response.CommandValue)
    assert (RecvPacket[ActivatePendingComponentImageSet_Response].CompletionCode == 0x00)

    return RecvPacket


def test_ActivatePendingComponentImage(testFixture, lowerLayerHeaders):
    """ Test DSP0248 ActivatePendingComponentImage request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / ActivatePendingComponentImage_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == ActivatePendingComponentImage_Response.CommandValue)
    assert (RecvPacket[ActivatePendingComponentImage_Response].CompletionCode == 0x00)

    return RecvPacket


def test_RequestDownstreamDeviceUpdate(testFixture, lowerLayerHeaders):
    """ Test DSP0248 Request Downstream Device Update request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / RequestDownstreamDeviceUpdate_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == RequestDownstreamDeviceUpdate_Response.CommandValue)
    assert (RecvPacket[RequestDownstreamDeviceUpdate_Response].CompletionCode == 0x00)
    assert (RecvPacket[RequestDownstreamDeviceUpdate_Response].DDWillSendGetPackageDataCommand <= 1)

    return RecvPacket
