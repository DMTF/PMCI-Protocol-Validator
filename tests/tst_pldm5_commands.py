##############################################################################
#  File Abstract:
#  DSP0267 test cases.
##############################################################################

from pldm.type5 import *  # pylint: disable=unused-import, unused-wildcard-import

""" Supported by CITE
    PLDM_FW_CMD_QUERY_DEV_ID
    PLDM_FW_CMD_GET_FW_PRM
    PLDM_FW_CMD_REQ_UPDATE
    PLDM_FW_CMD_PASS_COMP_TBL
    PLDM_FW_CMD_UPDT_COMP
    PLDM_FW_CMD_ACTIVATE
    PLDM_FW_CMD_GET_STS *
    PLDM_FW_CMD_CANCEL_UPDT_COMP *
    PLDM_FW_CMD_CANCEL_UPDT *
"""

def test_GetStatus(testFixture, lowerLayerHeaders):
    """Test DSP0248 Get Get Status request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / GetStatus_Request()

    # Send request
    testFixture.showPacket(SendPacket)

    ErrorCode = testFixture.commObject.Write(SendPacket)
    if ErrorCode == testFixture.commObject.ERROR_SUCCESS:

        # Get response
        (ErrorCode, RecvPacket) = testFixture.commObject.Read()

        if ErrorCode == testFixture.commObject.ERROR_SUCCESS:
            testFixture.showPacket(RecvPacket)

            # Validate fields
            testFixture.VerifyCommonFields(RecvPacket, SendPacket)

            assert (RecvPacket[PLDM_HEADER].CommandCode ==
                    GetStatus_Response.CommandValue)
            assert (RecvPacket[GetStatus_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_CancelUpdateComponent(testFixture, lowerLayerHeaders):
    """Test DSP0248 CancelUpdateComponent request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / CancelUpdateComponent_Request()

    # Send request
    testFixture.showPacket(SendPacket)

    ErrorCode = testFixture.commObject.Write(SendPacket)
    if ErrorCode == testFixture.commObject.ERROR_SUCCESS:

        # Get response
        (ErrorCode, RecvPacket) = testFixture.commObject.Read()

        if ErrorCode == testFixture.commObject.ERROR_SUCCESS:
            testFixture.showPacket(RecvPacket)

            # Validate fields
            testFixture.VerifyCommonFields(RecvPacket,SendPacket)

            assert (RecvPacket[PLDM_HEADER].CommandCode ==
                    CancelUpdateComponent_Response.CommandValue)
            assert (RecvPacket[CancelUpdateComponent_Response].CompletionCode == 0x80) # ERROR not in update mode
###            assert (RecvPacket[CancelUpdate_Response].CompletionCode == 0x00) # SUCCESS

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_CancelUpdate(testFixture, lowerLayerHeaders):
    """Test DSP0248 Cancel Update request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / CancelUpdate_Request()

    # Send request
    testFixture.showPacket(SendPacket)

    ErrorCode = testFixture.commObject.Write(SendPacket)
    if ErrorCode == testFixture.commObject.ERROR_SUCCESS:

        # Get response
        (ErrorCode, RecvPacket) = testFixture.commObject.Read()

        if ErrorCode == testFixture.commObject.ERROR_SUCCESS:
            testFixture.showPacket(RecvPacket)

            # Validate fields
            testFixture.VerifyCommonFields(RecvPacket,SendPacket)

            assert (RecvPacket[PLDM_HEADER].CommandCode ==
                    CancelUpdate_Response.CommandValue)
            assert (RecvPacket[CancelUpdate_Response].CompletionCode == 0x80)
###            assert (RecvPacket[CancelUpdate_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return

def test_QueryDeviceIdentifiers(testFixture, lowerLayerHeaders):
    """Test DSP0248 """

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / QueryDeviceIdentifiers_Request()

    # Send request
    testFixture.showPacket(SendPacket)

    ErrorCode = testFixture.commObject.Write(SendPacket)
    if ErrorCode == testFixture.commObject.ERROR_SUCCESS:

        # Get response
        (ErrorCode, RecvPacket) = testFixture.commObject.Read()

        if ErrorCode == testFixture.commObject.ERROR_SUCCESS:
            testFixture.showPacket(RecvPacket)

            # Validate fields
            testFixture.VerifyCommonFields(RecvPacket,SendPacket)

            assert (RecvPacket[PLDM_HEADER].CommandCode ==
                    QueryDeviceIdentifiers_Response.CommandValue)
            assert (RecvPacket[QueryDeviceIdentifiers_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_GetFirmwareParameters(testFixture, lowerLayerHeaders):
    """Test DSP0248 """

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / GetFirmwareParameters_Request()

    # Send request
    testFixture.showPacket(SendPacket)

    ErrorCode = testFixture.commObject.Write(SendPacket)
    if ErrorCode == testFixture.commObject.ERROR_SUCCESS:

        # Get response
        (ErrorCode, RecvPacket) = testFixture.commObject.Read()

        if ErrorCode == testFixture.commObject.ERROR_SUCCESS:
            testFixture.showPacket(RecvPacket)

            # Validate fields
            testFixture.VerifyCommonFields(RecvPacket,SendPacket)

            assert (RecvPacket[PLDM_HEADER].CommandCode ==
                    GetFirmwareParameters_Response.CommandValue)
            assert (RecvPacket[GetFirmwareParameters_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return

