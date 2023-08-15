##############################################################################
#  File Abstract:
#  DSP0218 test cases.
##############################################################################

from pldm.type6 import *  # pylint: disable=unused-import, unused-wildcard-import


def test_NegotiateRedfishParameters(testFixture, lowerLayerHeaders):
    """Test DSP0218 Negotiate Redfish Parameters request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / NegotiateRedfishParameters_Request()

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
                    NegotiateRedfishParameters_Request.CommandValue)
            assert (RecvPacket[NegotiateRedfishParameters_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage(
                "ERROR: read failed: " +
                testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage(
            "ERROR: write failed: " +
            testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_NegotiateMediumParameters(testFixture, lowerLayerHeaders):
    """Test DSP0218 Negotiate Medium Parameters request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / NegotiateMediumParameters_Request(MCMaximumTransferChunkSizeBytes = 64)

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
                    NegotiateMediumParameters_Request.CommandValue)
            assert (RecvPacket[NegotiateMediumParameters_Response].CompletionCode == 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
            testFixture.commObject.ResponseToStr(ErrorCode))
    return
