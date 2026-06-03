# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Verify RDE Scapy classes

File : test_dsp0218.py

Brief : Verify RDE Scapy classes
"""

import pytest
from pmci_protocol_validator.pldm.classes.dsp0218 import *

@pytest.mark.parametrize("class_type", PLDM_TYPE_6_PAYLOAD())
def test_PLDM_TYPE_6_PAYLOAD_class(class_type):
    """Verify PLDM_TYPE_6_PAYLOAD class initialization"""

    assert (class_type.PldmPayloadType == 0x06)
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", NegotiateRedfishParameters_Request())
def test_NegotiateRedfishParameters_Request(class_type):
    """Verify NegotiateRedfishParameters_Request initialization"""

    assert (class_type.CommandValue == 0x01), "Incorrect command code"
    assert (len(class_type.fields_desc) == 11), "Incorrect number of fields"

    assert (class_type.MCConcurrencySupport == 0)

    assert (class_type.events_supported == 0)
    assert (class_type.action_supported == 0)
    assert (class_type.replace_supported == 0)
    assert (class_type.update_supported == 0)
    assert (class_type.delete_supported == 0)
    assert (class_type.create_supported == 0)
    assert (class_type.read_supported == 0)
    assert (class_type.head_supported == 0)

    assert (class_type.NegotiateRedfishParametersReserved_0 == 0)
    assert (class_type.bej1_1_supported == 0)
    return


@pytest.mark.parametrize("class_type", NegotiateRedfishParameters_Response.Data())
def test_NegotiateRedfishParametersData(class_type):
    """Verify NegotiateRedfishParameters_Response data structure"""

    assert (len(class_type.fields_desc) == 16), "Incorrect number of fields"

    assert (class_type.DeviceConcurrencySupport == 0x00)
    assert (class_type.NegotiateRedfishParametersReserved_0 == 0x00)
    assert (class_type.bej1_1_supported == 0x00)
    assert (class_type.expand_supported == 0x00)
    assert (class_type.atomic_resource_read == 0x00)

    assert (class_type.events_supported == 0)
    assert (class_type.action_supported == 0)
    assert (class_type.replace_supported == 0)
    assert (class_type.update_supported == 0)
    assert (class_type.delete_supported == 0)
    assert (class_type.create_supported == 0)
    assert (class_type.read_supported == 0)
    assert (class_type.head_supported == 0)

    assert (class_type.NegotiateRedfishParametersReserved_1 == 0x00)
    assert (class_type.DeviceConfigurationSignature == 0x00)
    return


@pytest.mark.parametrize("class_type", NegotiateRedfishParameters_Response())
def test_NegotiateRedfishParameters_Response(class_type):
    """Verify NegotiateRedfishParameters_Response initialization"""

    assert (class_type.CommandValue == NegotiateRedfishParameters_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.Parameters is not None)
    return

@pytest.mark.parametrize("class_type", NegotiateMediumParameters_Request())
def test_NegotiateMediumParameters_Request(class_type):
    """Verify NegotiateMediumParameters_Request initialization"""

    assert (class_type.CommandValue == 0x02), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.MCMaximumTransferChunkSizeBytes == 0)
    return


@pytest.mark.parametrize("class_type", NegotiateMediumParameters_Response())
def test_NegotiateMediumParameters_Response(class_type):
    """Verify NegotiateMediumParameters_Response initialization"""

    assert (class_type.CommandValue == NegotiateMediumParameters_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.DeviceMaximumTransferChunkSizeBytes == 0x00)
    return


@pytest.mark.parametrize("class_type", GetSchemaDictionary_Request())
def test_GetSchemaDictionary_Request(class_type):
    """Verify GetSchemaDictionary_Request initialization"""

    assert (class_type.CommandValue == 0x03), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.ResourceID == 0)
    assert (class_type.RequestedSchemaClass == 0)
    return


@pytest.mark.parametrize("class_type", GetSchemaDictionary_Response())
def test_GetSchemaDictionary_Response(class_type):
    """Verify GetSchemaDictionary_Response initialization"""

    assert (class_type.CommandValue == GetSchemaDictionary_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.CompletionCode == 0x00)
    assert (class_type.DictionaryFormat == 0x00)
    assert (class_type.TransferHandle == 0x00)
    return


@pytest.mark.parametrize("class_type", GetSchemaURI_Request())
def test_GetSchemaURI_Request(class_type):
    """Verify GetSchemaURI_Request initialization"""

    assert (class_type.CommandValue == 0x04), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.RequestedSchemaClass == 0)
    assert (class_type.OEMExtensionNumber == 0)
    return


@pytest.mark.parametrize("class_type", GetSchemaURI_Response())
def test_GetSchemaURI_Response(class_type):
    """Verify GetSchemaURI_Response initialization"""

    assert (class_type.CommandValue == GetSchemaURI_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.StringFragmentCount is None)
    assert (class_type.SchemaURIs == [])
    return


@pytest.mark.parametrize("class_type", GetResourceETag_Request())
def test_GetResourceETag_Request(class_type):
    """Verify GetResourceETag_Request initialization"""

    assert (class_type.CommandValue == 0x05), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.ResourceID == 0)
    return


@pytest.mark.parametrize("class_type", GetResourceETag_Response())
def test_GetResourceETag_Response(class_type):
    """Verify GetResourceETag_Response initialization"""

    assert (class_type.CommandValue == GetResourceETag_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.ETag is not None)
    return


@pytest.mark.parametrize("class_type", GetOEMCount_Request())
def test_GetOEMCount_Request(class_type):
    """Verify GetOEMCount_Request initialization"""

    assert (class_type.CommandValue == 0x06), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.RequestedSchemaClass == 0)
    return


@pytest.mark.parametrize("class_type", GetOEMCount_Response())
def test_GetOEMCount_Response(class_type):
    """Verify GetOEMCount_Response initialization"""

    assert (class_type.CommandValue == GetOEMCount_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.OEMCount == 0x00)
    return


@pytest.mark.parametrize("class_type", GetOEMName_Request())
def test_GetOEMName_Request(class_type):
    """Verify GetOEMName_Request initialization"""

    assert (class_type.CommandValue == 0x07), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.RequestedSchemaClass == 0)
    assert (class_type.OEMIndex == 0)
    return


@pytest.mark.parametrize("class_type", GetOEMName_Response())
def test_GetOEMName_Response(class_type):
    """Verify GetOEMName_Response initialization"""

    assert (class_type.CommandValue == GetOEMName_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.OEMName is not None)
    return


@pytest.mark.parametrize("class_type", GetRegistryCount_Request())
def test_GetRegistryCount_Request(class_type):
    """Verify GetRegistryCount_Request initialization"""

    assert (class_type.CommandValue == 0x08), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetRegistryCount_Response())
def test_GetRegistryCount_Response(class_type):
    """Verify GetRegistryCount_Response initialization"""

    assert (class_type.CommandValue == GetRegistryCount_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.RegistryCount == 0x00)
    return


@pytest.mark.parametrize("class_type", GetRegistryDetails_Request())
def test_GetRegistryDetails_Request(class_type):
    """Verify GetRegistryDetails_Request initialization"""

    assert (class_type.CommandValue == 0x09), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.RegistryIndex == 0)
    return


@pytest.mark.parametrize("class_type", GetRegistryDetails_Response())
def test_GetRegistryDetails_Response(class_type):
    """Verify GetRegistryDetails_Response initialization"""

    assert (class_type.CommandValue == GetRegistryDetails_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.RegistryPrefix is not None)
    assert (class_type.RegistryURI is not None)
    assert (class_type.RegistryLanguage == 0x00)
    assert (class_type.VersionCount == 0x00)
    assert (class_type.RecordData == [])
    return


@pytest.mark.parametrize("class_type", SelectRegistryVersion_Request())
def test_SelectRegistryVersion_Request(class_type):
    """Verify SelectRegistryVersion_Request initialization"""

    assert (class_type.CommandValue == 0x0A), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.RegistryIndex == 0)
    assert (class_type.RegistryVersion == 0)
    return


@pytest.mark.parametrize("class_type", SelectRegistryVersion_Response())
def test_SelectRegistryVersion_Response(class_type):
    """Verify SelectRegistryVersion_Response initialization"""

    assert (class_type.CommandValue == SelectRegistryVersion_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetMessageRegistry_Request())
def test_GetMessageRegistry_Request(class_type):
    """Verify GetMessageRegistry_Request initialization"""

    assert (class_type.CommandValue == 0x0B), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.RegistryIndex == 0)
    return


@pytest.mark.parametrize("class_type", GetMessageRegistry_Response())
def test_GetMessageRegistry_Response(class_type):
    """Verify GetMessageRegistry_Response initialization"""

    assert (class_type.CommandValue == GetMessageRegistry_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.SchemaFormat == 0x00)
    assert (class_type.TransferHandle == 0x00)
    return


@pytest.mark.parametrize("class_type", GetSchemaFile_Request())
def test_GetSchemaFile_Request(class_type):
    """Verify GetSchemaFile_Request initialization"""

    assert (class_type.CommandValue == 0x0C), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.RequestedSchemaClass == 0)
    assert (class_type.OEMOffset == 0)
    return


@pytest.mark.parametrize("class_type", GetSchemaFile_Response())
def test_GetSchemaFile_Response(class_type):
    """Verify GetSchemaFile_Response initialization"""

    assert (class_type.CommandValue == GetSchemaFile_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.SchemaFormat == 0x00)
    assert (class_type.TransferHandle == 0x00)
    return


@pytest.mark.parametrize("class_type", RDEOperationInit_Request())
def test_RDEOperationInit_Request(class_type):
    """Verify RDEOperationInit_Request initialization"""

    assert (class_type.CommandValue == 0x10), "Incorrect command code"
    assert (len(class_type.fields_desc) == 13), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.OperationID == 0)
    assert (class_type.OperationType == 0)

    assert (class_type.Reserved == 0)
    assert (class_type.ExcerptFlag == 0)
    assert (class_type.ContainsCustomRequestParameters == 0)
    assert (class_type.ContainsRequestPayload == 0)
    assert (class_type.LocatorValid == 0)
    assert (class_type.SendDataTransferHandle == 0)
    assert (class_type.OperationLocatorLength == 0)
    assert (class_type.RequestPayloadLength == 0)
    assert (class_type.OperationLocator is None)
    assert (class_type.RequestPayload is None)
    return


@pytest.mark.parametrize("class_type", RDEOperationInit_Response.Data())
def test_RDEOperationInitData(class_type):
    """Verify RDEOperationInit_Response data structure"""

    assert (len(class_type.fields_desc) == 19), "Incorrect number of fields"

    assert (class_type.OperationStatus == 0x00)
    assert (class_type.CompletionPercentage == 0x00)
    assert (class_type.CompletionTimeSeconds == 0x00)
    assert (class_type.Reserved_1 == 0x00)
    assert (class_type.CacheAllowed == 0x00)
    assert (class_type.HaveResultPayload == 0x00)
    assert (class_type.HaveCustomResponseParameters == 0x00)
    assert (class_type.TaskSpawned == 0x00)
    assert (class_type.ResultTransferHandle == 0x00)

    assert (class_type.Reserved == 0x00)
    assert (class_type.HeadAccess == 0x00)
    assert (class_type.DeleteAccess == 0x00)
    assert (class_type.CreateAccess == 0x00)
    assert (class_type.ReplaceAccess == 0x00)
    assert (class_type.UpdateAccess == 0x00)
    assert (class_type.ReadAccess == 0x00)
    assert (class_type.ResponsePayloadLength == 0x00)
    assert (class_type.ETag is not None)
    assert (class_type.ResponsePayload == 0x00)
    return


@pytest.mark.parametrize("class_type", RDEOperationInit_Response())
def test_RDEOperationInit_Response(class_type):
    """Verify RDEOperationInit_Response initialization"""

    assert (class_type.CommandValue == RDEOperationInit_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.Parameters is not None)
    return


@pytest.mark.parametrize("class_type", SupplyCustomRequestParametersETags())
def test_SupplyCustomRequestParametersETags(class_type):
    """Verify SupplyCustomRequestParametersETags initialization"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.ETag is not None)
    return


@pytest.mark.parametrize("class_type", SupplyCustomParameters())
def test_SupplyCustomParameters(class_type):
    """Verify SupplyCustomParameters initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.HeaderName is not None)
    assert (class_type.HeaderParameter is not None)
    return


@pytest.mark.parametrize("class_type", SupplyCustomRequestParameters_Request())
def test_SupplyCustomRequestParameters_Request(class_type):
    """Verify SupplyCustomRequestParameters_Request initialization"""

    assert (class_type.CommandValue == 0x11), "Incorrect command code"
    assert (len(class_type.fields_desc) == 11), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.OperationID == 0)
    assert (class_type.LinkExpand == 0)
    assert (class_type.CollectionSkip == 0)
    assert (class_type.CollectionTop == 0)
    assert (class_type.PaginationOffset == 0)
    assert (class_type.ETagOperation == 0)
    assert (class_type.ETagCount == 0)
    assert (class_type.Etags is not None)
    assert (class_type.HeaderCount == 0)
    assert (class_type.Headers is not None)
    return


@pytest.mark.parametrize("class_type", SupplyCustomRequestParameters_Response.Data())
def test_SupplyCustomRequestParametersData(class_type):
    """Verify SupplyCustomRequestParameters_Response data structure"""

    assert (len(class_type.fields_desc) == 19), "Incorrect number of fields"
    assert (class_type.OperationStatus == 0x00)
    assert (class_type.CompletionPercentage == 0x00)
    assert (class_type.CompletionTimeSeconds == 0x00)

    assert (class_type.Reserved_1 == 0x00)
    assert (class_type.CacheAllowed == 0x00)
    assert (class_type.HaveResultPayload == 0x00)
    assert (class_type.HaveCustomResponseParameters == 0x00)
    assert (class_type.TaskSpawned == 0x00)
    assert (class_type.ResultTransferHandle == 0x00)

    assert (class_type.Reserved == 0x00)
    assert (class_type.HeadAccess == 0x00)
    assert (class_type.DeleteAccess == 0x00)
    assert (class_type.CreateAccess == 0x00)
    assert (class_type.ReplaceAccess == 0x00)
    assert (class_type.UpdateAccess == 0x00)
    assert (class_type.ReadAccess == 0x00)
    assert (class_type.ResponsePayloadLength == 0x00)
    assert (class_type.ETag is not None)
    assert (class_type.ResponsePayload == 0x00)
    return


@pytest.mark.parametrize("class_type", SupplyCustomRequestParameters_Response())
def test_SupplyCustomRequestParameters_Response(class_type):
    """Verify SupplyCustomRequestParameters_Response initialization"""

    assert (class_type.CommandValue == SupplyCustomRequestParameters_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.Parameters is not None)
    return


@pytest.mark.parametrize("class_type", RetrieveCustomResponseParameters_Request())
def test_RetrieveCustomResponseParameters_Request(class_type):
    """Verify RetrieveCustomResponseParameters_Request initialization"""

    assert (class_type.CommandValue == 0x12), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.ResourceID == 0)
    assert (class_type.OperationID == 0)
    return


@pytest.mark.parametrize("class_type", RetrieveCustomResponseParameters_Response())
def test_RetrieveCustomResponseParameters_Response(class_type):
    """Verify RetrieveCustomResponseParameters_Response initialization"""

    assert (class_type.CommandValue == RetrieveCustomResponseParameters_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.DeferralTimeframe == 0x00)
    assert (class_type.NewResourceID == 0x00)
    assert (class_type.ResponseHeaderCount == 0x00)
    assert (class_type.Headers is not None)
    return


@pytest.mark.parametrize("class_type", RDEOperationComplete_Request())
def test_RDEOperationComplete_Request(class_type):
    """Verify RDEOperationComplete_Request initialization"""

    assert (class_type.CommandValue == 0x13), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.ResourceID == 0)
    assert (class_type.OperationID == 0)
    return


@pytest.mark.parametrize("class_type", RDEOperationComplete_Response())
def test_RDEOperationComplete_Response(class_type):
    """Verify RDEOperationComplete_Response initialization"""

    assert (class_type.CommandValue == RDEOperationComplete_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", RDEOperationStatus_Request())
def test_RDEOperationStatus_Request(class_type):
    """Verify RDEOperationStatus_Request initialization"""

    assert (class_type.CommandValue == 0x14), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.OperationID == 0)
    return


@pytest.mark.parametrize("class_type", RDEOperationStatus_Response.Data())
def test_RDEOperationStatusData(class_type):
    """Verify RDEOperationStatus_Response data structure"""

    assert (len(class_type.fields_desc) == 19), "Incorrect number of fields"

    assert (class_type.OperationStatus == 0x00)
    assert (class_type.CompletionPercentage == 0x00)
    assert (class_type.CompletionTimeSeconds == 0x00)

    assert (class_type.Reserved_1 == 0x00)
    assert (class_type.CacheAllowed == 0x00)
    assert (class_type.HaveResultPayload == 0x00)
    assert (class_type.HaveCustomResponseParameters == 0x00)
    assert (class_type.TaskSpawned == 0x00)
    assert (class_type.ResultTransferHandle == 0x00)

    assert (class_type.Reserved == 0x00)
    assert (class_type.HeadAccess == 0x00)
    assert (class_type.DeleteAccess == 0x00)
    assert (class_type.CreateAccess == 0x00)
    assert (class_type.ReplaceAccess == 0x00)
    assert (class_type.UpdateAccess == 0x00)
    assert (class_type.ReadAccess == 0x00)
    assert (class_type.ResponsePayloadLength == 0x00)
    assert (class_type.ETag is not None)
    assert (class_type.ResponsePayload == 0x00)
    return


@pytest.mark.parametrize("class_type", RDEOperationStatus_Response())
def test_RDEOperationStatus_Response(class_type):
    """Verify RDEOperationStatus_Response initialization"""

    assert (class_type.CommandValue == RDEOperationStatus_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.Status is not None)
    return

@pytest.mark.parametrize("class_type", RDEOperationKill_Request())
def test_RDEOperationKill_Request(class_type):
    """Verify RDEOperationKill_Request initialization"""

    assert (class_type.CommandValue == 0x15), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.ResourceID == 0)
    assert (class_type.OperationID == 0)
    assert (class_type.Reserved == 0)
    assert (class_type.DiscardResults == 0)
    assert (class_type.RunToCompletion == 0)
    assert (class_type.DiscardRecord == 0)
    return


@pytest.mark.parametrize("class_type", RDEOperationKill_Response())
def test_RDEOperationKill_Response(class_type):
    """Verify RDEOperationKill_Response initialization"""

    assert (class_type.CommandValue == RDEOperationKill_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", RDEOperationEnumerate_Request())
def test_RDEOperationEnumerate_Request(class_type):
    """Verify RDEOperationEnumerate_Request initialization"""

    assert (class_type.CommandValue == 0x16), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", RDEOperationEnumerateFields())
def test_RDEOperationEnumerateFields_Request(class_type):
    """Verify RDEOperationEnumerateFields initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResourceID == 0)
    assert (class_type.OperationID == 0)
    assert (class_type.OperationType == 0)
    return





@pytest.mark.parametrize("class_type", RDEOperationEnumerate_Response())
def test_RDEOperationEnumerate_Response(class_type):
    """Verify RDEOperationEnumerate_Response initialization"""

    assert (class_type.CommandValue == RDEOperationEnumerate_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.OperationCount == 0x00)
    assert (class_type.Resources is None)
    return


@pytest.mark.parametrize("class_type", MultipartSend_Request())
def test_MultipartSend_Request(class_type):
    """Verify MultipartSend_Request initialization"""

    assert (class_type.CommandValue == 0x30), "Incorrect command code"
    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.OperationID == 0)
    assert (class_type.TransferFlag == 0)
    assert (class_type.NextTransferHandle == 0)
    assert (class_type.DataLengthBytes is None)
    assert (class_type.Data == [])
    assert (class_type.DataIntegrityChecksum is None)
    return


@pytest.mark.parametrize("class_type", MultipartSend_Response())
def test_MultipartSend_Response(class_type):
    """Verify MultipartSend_Response initialization"""

    assert (class_type.CommandValue == MultipartSend_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.TransferOperation == 0x00)
    return


@pytest.mark.parametrize("class_type", MultipartReceive_Request())
def test_MultipartReceive_Request(class_type):
    """Verify MultipartReceive_Request initialization"""

    assert (class_type.CommandValue == 0x31), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.OperationID == 0)
    assert (class_type.TransferOperation == 0)
    return


@pytest.mark.parametrize("class_type", MultipartReceive_Response())
def test_MultipartReceive_Response(class_type):
    """Verify MultipartReceive_Response initialization"""

    assert (class_type.CommandValue == MultipartReceive_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.TransferFlag == 0x00)
    assert (class_type.NextTransferHandle == 0x00)
    assert (class_type.DataLengthBytes is None)
    assert (class_type.Data == [])
    assert (class_type.DataIntegrityChecksum is None)
    return
