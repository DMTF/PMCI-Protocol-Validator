# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0240 test cases.
##############################################################################

from testframework.utilities import common_send_receive
from pldm.type0 import (
    PLDM_HEADER,
    SetTID_Request,
    SetTID_Response,
    GetTID_Request,
    GetTID_Response,
    GetPldmVersion_Request,
    GetPldmVersion_Response,
    GetPldmTypes_Request,
    GetPldmTypes_Response,
    GetPldmCommands_Request,
    GetPldmCommands_Response,
    SelectPLDMVersion_Request,
    SelectPLDMVersion_Response
)


def VerifyCommonFields(RecvPacket, SendPacket):
    """ Validate PLDM header fields """

    ### TODO: Implement
    pass


def test_SetTID(testFixture, lowerLayerHeaders):
    """ Test DSP0240 SetTID request """

    # Assemble the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SetTID_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()
    SendPacket[SetTID_Request].TID = 5

    # Send the request and wait for the response
    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    # Validate fields
    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SetTID_Response.CommandValue)
    assert (RecvPacket[SetTID_Response].CompletionCode == 0x00)

    # Return reponse packet for further processing
    return RecvPacket


def test_GetTID(testFixture, lowerLayerHeaders):
    """ Test DSP0240 PLDM Get TID request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetTID_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetTID_Response.CommandValue)
    assert (RecvPacket[GetTID_Response].CompletionCode == 0x00)
    assert (RecvPacket[GetTID_Response].TID != 0xFF)

    return RecvPacket


def test_GetPldmVersion(testFixture, lowerLayerHeaders):
    """" Test DSP0240 PLDM Get Pldm Version request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetPldmVersion_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()
    SendPacket[GetPldmVersion_Request].TransferOperationFlag = 1

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPldmVersion_Response.CommandValue)
    assert (RecvPacket[GetPldmVersion_Response].CompletionCode == 0x00)
    assert (RecvPacket[GetPldmVersion_Response].TransferFlag == 0x05), "Test only supports a single transfer"

    return RecvPacket


def test_GetPldmTypes(testFixture, lowerLayerHeaders):
    """ Test DSP0240 PLDM GetPldmTypes request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetPldmTypes_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPldmTypes_Response.CommandValue)
    assert (RecvPacket[GetPldmTypes_Response].CompletionCode == 0x00)

    return RecvPacket


def test_GetPldmCommands(testFixture, lowerLayerHeaders, requestVersion=0xF1F1F000):
    """ Test DSP0240 PLDM Get PLDM Commands request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetPldmCommands_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()
    SendPacket[GetPldmCommands_Request].PldmType = 0
    SendPacket[GetPldmCommands_Request].Version = requestVersion

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPldmCommands_Response.CommandValue)
    assert (RecvPacket[GetPldmCommands_Response].CompletionCode == 0x00)

    return RecvPacket


def test_SelectPLDMVersion(testFixture, lowerLayerHeaders, requestVersion=0xF1F1F000):
    """ Test DSP0240 Select PLDM Version request """

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SelectPLDMVersion_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()
    SendPacket[SelectPLDMVersion_Request].PldmType = 0
    SendPacket[SelectPLDMVersion_Request].Version = requestVersion

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetPldmCommands_Response.CommandValue)
    assert (RecvPacket[SelectPLDMVersion_Response].CompletionCode == 0x00)

    return RecvPacket
