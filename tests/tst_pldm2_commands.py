# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0240 test cases.
##############################################################################

from pldm.type2 import *  # pylint: disable=unused-import, unused-wildcard-import


def test_GetPDRRepositoryInfo(testFixture, lowerLayerHeaders):
    """Test DSP0248 Get PDR Repository Info request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / GetPDRRepositoryInfo_Request()

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
                    GetPDRRepositoryInfo_Response.CommandValue)
            assert (RecvPacket[GetPDRRepositoryInfo_Response].CompletionCode == 0x00)

            assert (RecvPacket[GetPDRRepositoryInfo_Response].RecordCount > 0x00)
            assert (RecvPacket[GetPDRRepositoryInfo_Response].RepositorySize > 0x00)
            assert (RecvPacket[GetPDRRepositoryInfo_Response].LargestRecordSize > 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return


def test_GetPDRRepositorySignature(testFixture, lowerLayerHeaders):
    """Test DSP0248 GetPDRRepositorySignature request"""

    # Build the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER(InstanceID=testFixture.getNextInstanceID())
    SendPacket = SendPacket / GetPDRRepositorySignature_Request()

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
                    GetPDRRepositorySignature_Response.CommandValue)
            assert (RecvPacket[GetPDRRepositorySignature_Response].CompletionCode == 0x00)
            assert (RecvPacket[GetPDRRepositorySignature_Response].PdrRepositorySignature != 0x00)

        else:
            testFixture.logMessage("ERROR: read failed: " +
                                   testFixture.commObject.ResponseToStr(ErrorCode))
    else:
        testFixture.logMessage("ERROR: write failed: " +
                               testFixture.commObject.ResponseToStr(ErrorCode))
    return
