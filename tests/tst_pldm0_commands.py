##############################################################################
#  File Abstract:
#  DSP0240 test cases.
##############################################################################

from pldm.type0 import *  # pylint: disable=unused-import, unused-wildcard-import


def test_SetTID(testFixture, lowerLayerHeaders):
    """Test DSP0240 SetTID request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / SetTID_Request(TID=5)

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
                    SetTID_Response.CommandValue)
            assert (RecvPacket[SetTID_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
            testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_GetTID(testFixture, lowerLayerHeaders):
    """Test DSP0240 PLDM Get TID request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / GetTID_Request()

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
                    GetTID_Response.CommandValue)
            assert (RecvPacket[GetTID_Response].CompletionCode == 0x00)
            assert (RecvPacket[GetTID_Response].TID != 0xFF)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
            testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_GetPldmVersion(testFixture, lowerLayerHeaders):
    """"Test DSP0240 PLDM Get Pldm Version request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / GetPldmVersion_Request(TransferOperationFlag=1)

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
                    GetPldmVersion_Response.CommandValue)
            assert (RecvPacket[GetPldmVersion_Response].CompletionCode == 0x00)
            assert (RecvPacket[GetPldmVersion_Response].TransferFlag == 0x05), "Test only supports a single transfer"

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_GetPldmTypes(testFixture, lowerLayerHeaders):
    """Test DSP0240 PLDM GetPldmTypes request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / GetPldmTypes_Request()

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
                    GetPldmTypes_Response.CommandValue)
            assert (RecvPacket[GetPldmTypes_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_GetPldmCommands(testFixture, lowerLayerHeaders):
    """Test DSP0240 PLDM Get PLDM Commands request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / GetPldmCommands_Request(PldmType=0)

### TODO Need to set Version Field

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
                    GetPldmCommands_Response.CommandValue)
            assert (RecvPacket[GetPldmCommands_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_SelectPLDMVersion(testFixture, lowerLayerHeaders):
    """Test DSP0240 Select PLDM Version request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / SelectPLDMVersion_Request(PldmType=0)

### TODO Need to set Version Field

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
                    GetPldmCommands_Response.CommandValue)
            assert (RecvPacket[GetPldmCommands_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return
