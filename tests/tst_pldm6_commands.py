# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0218 test cases.
##############################################################################

from testframework.utilities import common_send_receive
from pldm.type6 import *    # noqa:F403


def VerifyCommonFields(RecvPacket, SendPacket):
    """Validate PLDM fields"""

    ### TODO: Implement
    pass
    return


def test_NegotiateRedfishParameters(testFixture, lowerLayerHeaders):
    """Test DSP0218 Negotiate Redfish Parameters request"""

    # Assemble the full PLDM request packet
    SendPacket = lowerLayerHeaders / PLDM_HEADER() / NegotiateRedfishParameters_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    # Send the request and wait for the response
    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    # Validate header fields
    VerifyCommonFields(RecvPacket, SendPacket)

    # Validate response fields
    assert (RecvPacket[PLDM_HEADER].CommandCode == NegotiateRedfishParameters_Request.CommandValue)
    assert (RecvPacket[NegotiateRedfishParameters_Response].CompletionCode == 0x00)
    assert (RecvPacket[NegotiateRedfishParameters_Response].Parameters.NegotiateRedfishParametersReserved_0 == 0)
    assert (RecvPacket[NegotiateRedfishParameters_Response].Parameters.NegotiateRedfishParametersReserved_1 == 0)
    assert (RecvPacket[NegotiateRedfishParameters_Response].Parameters.DeviceProviderName.stringFormat <= 5)

    return RecvPacket


def test_NegotiateMediumParameters(testFixture, lowerLayerHeaders):
    """Test DSP0218 Negotiate Medium Parameters request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / NegotiateMediumParameters_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()
    SendPacket[NegotiateMediumParameters_Request].MCMaximumTransferChunkSizeBytes = 64

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == NegotiateMediumParameters_Request.CommandValue)
    assert (RecvPacket[NegotiateMediumParameters_Response].CompletionCode == 0x00)

    return RecvPacket


def test_GetSchemaDictionary(testFixture, lowerLayerHeaders):
    """Test DSP0218 Get Schema Dictionary request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetSchemaDictionary_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetSchemaDictionary_Request.CommandValue)
    assert (RecvPacket[GetSchemaDictionary_Response].CompletionCode == 0)

    return RecvPacket


def test_GetSchemaURI(testFixture, lowerLayerHeaders):
    """Test DSP0218 Get SchemaURI Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetSchemaURI_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetSchemaURI_Request.CommandValue)
    assert (RecvPacket[GetSchemaURI_Response].CompletionCode == 0)

    for i in range(0, RecvPacket[GetSchemaURI_Response].StringFragmentCount):
        assert (RecvPacket[GetSchemaURI_Response].SchemaURIs[i].stringFormat <= 5)

    return RecvPacket


def test_GetResourceETag(testFixture, lowerLayerHeaders):
    """Test DSP0218 GetResource ETag Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetResourceETag_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetResourceETag_Request.CommandValue)
    assert (RecvPacket[GetResourceETag_Response].CompletionCode == 0)
    assert (RecvPacket[GetResourceETag_Response].ETag.stringFormat <= 5)

    return RecvPacket


def test_GetOEMCount(testFixture, lowerLayerHeaders):
    """Test DSP0218 Get OEM Count Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetOEMCount_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetOEMCount_Request.CommandValue)
    assert (RecvPacket[GetOEMCount_Response].CompletionCode == 0)

    return RecvPacket


def test_GetOEMName(testFixture, lowerLayerHeaders):
    """Test DSP0218 Get OEM Name Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetOEMName_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetOEMName_Request.CommandValue)
    assert (RecvPacket[GetOEMName_Response].CompletionCode == 0)
    assert (RecvPacket[GetOEMName_Response].OEMName.stringFormat <= 5)

    return RecvPacket


def test_GetRegistryCount(testFixture, lowerLayerHeaders):
    """Test DSP0218 Get Registry Count Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetRegistryCount_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetRegistryCount_Request.CommandValue)
    assert (RecvPacket[GetRegistryCount_Response].CompletionCode == 0)

    return RecvPacket


def test_GetRegistryDetails(testFixture, lowerLayerHeaders):
    """Test DSP0218 Get Registry Details Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetRegistryDetails_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetRegistryDetails_Request.CommandValue)
    assert (RecvPacket[GetRegistryDetails_Response].CompletionCode == 0)
    assert (RecvPacket[GetRegistryDetails_Response].RegistryPrefix.stringFormat <= 5)
    assert (RecvPacket[GetRegistryDetails_Response].RegistryURI.stringFormat <= 5)
    for i in range(0, RecvPacket[GetRegistryDetails_Response].VersionCount):
        assert (RecvPacket[GetRegistryDetails_Response].RecordData[i] != 0)

    return RecvPacket


def test_SelectRegistryVersion(testFixture, lowerLayerHeaders):
    """Test DSP0218 Select Registry Version Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SelectRegistryVersion_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SelectRegistryVersion_Request.CommandValue)
    assert (RecvPacket[SelectRegistryVersion_Response].CompletionCode == 0)

    return RecvPacket


def test_GetMessageRegistry(testFixture, lowerLayerHeaders):
    """Test DSP0218 Get Message Registry_ Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetMessageRegistry_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetMessageRegistry_Request.CommandValue)
    assert (RecvPacket[GetMessageRegistry_Response].CompletionCode == 0)

    return RecvPacket


def test_GetSchemaFile(testFixture, lowerLayerHeaders):
    """Test DSP0218 Get Schema File Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / GetSchemaFile_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == GetSchemaFile_Request.CommandValue)
    assert (RecvPacket[GetSchemaFile_Response].CompletionCode == 0)

    return RecvPacket


def test_RDEOperationInit(testFixture, lowerLayerHeaders):
    """Test DSP0218 RDE Operation Init Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / RDEOperationInit_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == RDEOperationInit_Request.CommandValue)
    assert (RecvPacket[RDEOperationInit_Response].CompletionCode == 0)
    assert (RecvPacket[RDEOperationInit_Response].Parameters.Reserved_1 == 0)
    assert (RecvPacket[RDEOperationInit_Response].Parameters.Reserved == 0)
    assert (RecvPacket[RDEOperationInit_Response].Parameters.ETag.stringFormat <= 5)

    return RecvPacket


def test_SupplyCustomRequestParameters(testFixture, lowerLayerHeaders):
    """Test DSP0218 Supply Custom Request Parameters Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / SupplyCustomRequestParameters_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == SupplyCustomRequestParameters_Request.CommandValue)
    assert (RecvPacket[SupplyCustomRequestParameters_Response].CompletionCode == 0)
    assert (RecvPacket[SupplyCustomRequestParameters_Response].Reserved_1 == 0)
    assert (RecvPacket[SupplyCustomRequestParameters_Response].Reserved == 0)
    assert (RecvPacket[SupplyCustomRequestParameters_Response].ETag.stringFormat )<= 5

    return RecvPacket


def test_RetrieveCustomResponseParameters(testFixture, lowerLayerHeaders):
    """Test DSP0218 Retrieve Custom Response Parameters Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / RetrieveCustomResponseParameters_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == RetrieveCustomResponseParameters_Request.CommandValue)
    assert (RecvPacket[RetrieveCustomResponseParameters_Response].CompletionCode == 0)

    return RecvPacket


def test_RDEOperationComplete(testFixture, lowerLayerHeaders):
    """Test DSP0218 RDE Operation Complete Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / RDEOperationComplete_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == RDEOperationComplete_Request.CommandValue)
    assert (RecvPacket[RDEOperationComplete_Response].CompletionCode == 0)

    return RecvPacket


def test_RDEOperationStatus(testFixture, lowerLayerHeaders):
    """Test DSP0218 RDE Operation Status Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / RDEOperationStatus_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == RDEOperationStatus_Request.CommandValue)
    assert (RecvPacket[RDEOperationStatus_Response].CompletionCode == 0)
    assert (RecvPacket[RDEOperationStatus_Response].Status.Reserved_1 == 0)
    assert (RecvPacket[RDEOperationStatus_Response].Status.Reserved == 0)
    assert (RecvPacket[RDEOperationStatus_Response].Status.ETag.stringFormat == 0)

    return RecvPacket


def test_RDEOperationKill(testFixture, lowerLayerHeaders):
    """Test DSP0218 RDE Operation Kill Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / RDEOperationKill_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == RDEOperationKill_Request.CommandValue)
    assert (RecvPacket[RDEOperationKill_Response].CompletionCode == 0)

    return RecvPacket


def test_RDEOperationEnumerate(testFixture, lowerLayerHeaders):
    """Test DSP0218 RDE Operation Enumerate Request"""

    SendPacket = lowerLayerHeaders / PLDM_HEADER() / RDEOperationEnumerate_Request()
    SendPacket[PLDM_HEADER].InstanceID = testFixture.getNextInstanceID()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[PLDM_HEADER].CommandCode == RDEOperationEnumerate_Request.CommandValue)
    assert (RecvPacket[RDEOperationEnumerate_Response].CompletionCode == 0)

    for i in range(0, RecvPacket[RDEOperationEnumerate_Response].OperationCount):
        assert (RecvPacket[RDEOperationEnumerate_Response].Resources.OperationType <= 6)

    return RecvPacket

