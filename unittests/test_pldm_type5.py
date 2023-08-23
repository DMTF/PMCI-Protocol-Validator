# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Initialization tests for PLDM Type 5 (PLDM Firmware Update) wrappers
##############################################################################

import pytest
from pldm.type5 import *  # pylint: disable=unused-import, unused-wildcard-import


@pytest.mark.parametrize("class_type", PLDM_TYPE_5_PAYLOAD())
def test_PLDM_TYPE_5_PAYLOAD_class(class_type):
    """Verify PLDM_TYPE_5_PAYLOAD class initialization"""

    assert (class_type.PldmPayloadType == 0x05), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", RecordDescriptor())
def test_RecordDescriptor(class_type):
    "Verify RecordDescriptor initialization"

    assert (len(class_type.fields_desc) == 15), "Incorrect number of fields"

    assert (class_type.DescriptorType == 0)
    assert (class_type.DescriptorLength == 2)
    return


@pytest.mark.parametrize("class_type", ComponentParameterTableEntry())
def test_ComponentParameterTableEntry(class_type):
    "Verify ComponentParameterTableEntry initialization"

    assert (len(class_type.fields_desc) == 27), "Incorrect number of fields"

    assert (class_type.ComponentClassification == 0)
    assert (class_type.ComponentIdentifier == 0)
    assert (class_type.ComponentClassificationIndex == 0)
    assert (class_type.ActiveComponentComparisonStamp == 0)
    assert (class_type.ActiveComponentVersionStringType == 0)
    assert (class_type.ActiveComponentVersionStringLength is None)
    assert (class_type.ActiveComponentReleaseDate is not None)
    assert (class_type.PendingComponentComparisonStamp == 0)
    assert (class_type.PendingComponentVersionStringType == 0)
    assert (class_type.PendingComponentVersionStringLength is None)
    assert (class_type.PendingComponentReleaseDate is not None)
    assert (class_type.ComponentActivationPendingComponentImageSet == 0)
    assert (class_type.ComponentActivationPendingImage == 0)
    assert (class_type.ComponentActivationAcPowerCycle == 0)
    assert (class_type.ComponentActivationDcPowerCycle == 0)
    assert (class_type.ComponentActivationSystemReboot == 0)
    assert (class_type.ComponentActivationMediumSpecificReset == 0)
    assert (class_type.ComponentActivationSelfContained == 0)
    assert (class_type.ComponentActivationAutomatic == 0)
    assert (class_type.ComponentActivationMethodsReserved_0 == 0)
    assert (class_type.CapabilitiesDuringUpdateReserved_1 == 0)
    assert (class_type.CapabilitiesDuringUpdateComponentDowngradeCapability == 0)
    assert (class_type.CapabilitiesDuringUpdateReserved_0 == 0)
    assert (class_type.CapabilitiesDuringUpdateFirmwareDeviceApplyState == 0)
    assert (class_type.CapabilitiesDuringUpdateReserved_2 == 0)
    assert (class_type.ActiveComponentVersionString == b"")
    assert (class_type.PendingComponentVersionString == b"")
    return


@pytest.mark.parametrize("class_type", QueryDeviceIdentifiers_Request())
def test_QueryDeviceIdentifiers_Request(class_type):
    """Verify QueryDeviceIdentifiers_Request initialization"""

    assert (class_type.CommandValue == 0x01), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", QueryDeviceIdentifiers_Response())
def test_QueryDeviceIdentifiers_Response(class_type):
    """Verify QueryDeviceIdentifiers_Response initialization"""

    assert (class_type.CommandValue == QueryDeviceIdentifiers_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.DeviceIdentifiersLength is None)
    assert (class_type.DescriptorCount is None)
    assert (class_type.Descriptors is not None)
    return


@pytest.mark.parametrize("class_type", GetFirmwareParameters_Request())
def test_GetFirmwareParameters_Request(class_type):
    "Verify GetFirmwareParameters_Request initialization"

    assert (class_type.CommandValue == 0x02), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetFirmwareParameters_Response())
def test_GetFirmwareParameters_Response(class_type):
    "Verify GetFirmwareParameters_Response initialization"

    assert (class_type.CommandValue == GetFirmwareParameters_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 18), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.FirmwareDeviceUpdateModeRestrictionsReserved_0 == 0)
    assert (class_type.FirmwareDeviceUpdateModeRestrictions == 0)
    assert (class_type.FirmwareDevicePartialUpdates == 0)
    assert (class_type.FirmwareDeviceHostFunctionalityDuringUpdate == 0)
    assert (class_type.ComponentUpdateFailureRetryCapability == 0)
    assert (class_type.ComponentUpdateFailureRecoveryCapability == 0)
    assert (class_type.GetFirmwareParametersReserved_0 == 0)
    assert (class_type.FirmwareDeviceDowngradeRestrictions == 0)
    assert (class_type.GetFirmwareParametersReserved_1 == 0)
    assert (class_type.ComponentCount is None)
    assert (class_type.ActiveComponentImageSetVersionStringType == 0)
    assert (class_type.ActiveComponentImageSetVersionStringLength is None)
    assert (class_type.PendingComponentImageSetVersionStringType == 0)
    assert (class_type.PendingComponentImageSetVersionStringLength is None)
    assert (class_type.ActiveComponentImageSetVersionString == b'')
    assert (class_type.PendingComponentImageSetVersionString == b'')
    assert (class_type.ComponentParameterTable == [])
    return


@pytest.mark.parametrize("class_type", QueryDownstreamDevices_Request())
def test_QueryDownstreamDevices_Request(class_type):
    "Verify QueryDownstreamDevices_Request initialization"

    assert (class_type.CommandValue == 0x03), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", QueryDownstreamDevices_Response())
def test_QueryDownstreamDevices_Response(class_type):
    "Verify QueryDownstreamDevices_Response initialization"

    assert (class_type.CommandValue == QueryDownstreamDevices_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 9), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.DownstreamDeviceUpdateSupported == 0)
    assert (class_type.NumberofDownstreamDevices == 0)
    assert (class_type.MaxNumberofDownstreamDevices == 0)
    assert (class_type.Reserved_0 == 0)
    assert (class_type.FDPSupportsAbilityToUpdateMultipleDownstreamDevicesSimultaneously == 0)
    assert (class_type.FDPSupportsDownstreamDevicesDynamicallyRemoved == 0)
    assert (class_type.FDPSupportsDownstreamDevicesDynamicallyAttached == 0)
    assert (class_type.Reserved_1 == 0)
    return


@pytest.mark.parametrize("class_type", QueryDownstreamIdentifiers_Request())
def test_QueryDownstreamIdentifiers_Request(class_type):
    "Verify QueryDownstreamIdentifiers_Request initialization"

    assert (class_type.CommandValue == 0x04), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.TransferOperationFlag == 0)
    return


@pytest.mark.parametrize("class_type", DownstreamDevice())
def test_DownstreamDevice(class_type):
    "Verify DownstreamDevice initialization"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.DownstreamDeviceIndex == 0)
    assert (class_type.DownstreamDescriptorCount is None)
    assert (class_type.DownstreamDescriptors == [])
    return


@pytest.mark.parametrize("class_type", QueryDownstreamIdentifiers_Response())
def test_QueryDownstreamIdentifiers_Response(class_type):
    "Verify QueryDownstreamIdentifiers_Response initialization"

    assert (class_type.CommandValue == QueryDownstreamIdentifiers_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 1)
    assert (class_type.DownstreamDevicesLength is None)
    assert (class_type.NumberOfDownstreamDevices is None)
    assert (class_type.DownstreamDevices == [])
    return


@pytest.mark.parametrize("class_type", GetDownstreamFirmwareParameters_Request())
def test_GetDownstreamFirmwareParameters_Request(class_type):
    "Verify GetDownstreamFirmwareParameters_Request initialization"

    assert (class_type.CommandValue == 0x05), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.TransferOperationFlag == 0)
    return


@pytest.mark.parametrize("class_type", DownstreamDeviceParameterTableEntry())
def test_DownstreamDeviceParameterTableEntry(class_type):
    "Verify DownstreamDeviceParameterTableEntry initialization"

    assert (len(class_type.fields_desc) == 25), "Incorrect number of fields"

    assert (class_type.DownstreamDeviceIndex == 0)
    assert (class_type.ActiveComponentComparisonStamp == 0)
    assert (class_type.ActiveComponentVersionStringType == 0)
    assert (class_type.ActiveComponentVersionStringLength is None)
    assert (class_type.ActiveComponentReleaseDate is not None)
    assert (class_type.PendingComponentVersionStringType == 0)
    assert (class_type.PendingComponentVersionStringType == 0)
    assert (class_type.PendingComponentVersionStringLength is None)
    assert (class_type.PendingComponentReleaseDate is not None)
    assert (class_type.ComponentActivationMethodsReserved_0 == 0)
    assert (class_type.ComponentActivationPendingImage == 0)
    assert (class_type.ComponentActivationAcPowerCycle == 0)
    assert (class_type.ComponentActivationDcPowerCycle == 0)
    assert (class_type.ComponentActivationSystemReboot == 0)
    assert (class_type.ComponentActivationMediumSpecificReset == 0)
    assert (class_type.ComponentActivationSelfContained == 0)
    assert (class_type.ComponentActivationAutomatic == 0)
    assert (class_type.ComponentActivationMethodsReserved_1 == 0)
    assert (class_type.CapabilitiesDuringUpdateReserved_0 == 0)
    assert (class_type.CapabilitiesDuringUpdateComponentDowngradeCapability == 0)
    assert (class_type.CapabilitiesDuringUpdateDownstreamDeviceIsUpdateable == 0)
    assert (class_type.CapabilitiesDuringUpdateDownstreamDeviceApplyState == 0)
    assert (class_type.CapabilitiesDuringUpdateReserved_1 == 0)
    assert (class_type.ActiveComponentVersionString == b"")
    assert (class_type.PendingComponentVersionString == b"")
    return


@pytest.mark.parametrize("class_type", GetDownstreamFirmwareParameters_Response())
def test_GetDownstreamFirmwareParameters_Response(class_type):
    "Verify GetDownstreamFirmwareParameters_Response initialization"

    assert (class_type.CommandValue == GetDownstreamFirmwareParameters_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 14), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 1)
    assert (class_type.FDPCapabilitiesDuringUpdateReserved_1 == 0)
    assert (class_type.FDPUpdateModeRestrictions == 0)
    assert (class_type.FDPCapabilitiesDuringUpdateReserved_0 == 0)
    assert (class_type.DownstreamDeviceHostFunctionalityDuringFirmwareUpdate == 0)
    assert (class_type.ComponentUpdateFailureRetryCapability == 0)
    assert (class_type.DownstreamDeviceComponentUpdateFailureRecoveryCapability == 0)
    assert (class_type.FDPCapabilitiesDuringUpdateReserved_2 == 0)
    assert (class_type.DowngradeRestrictions == 0)
    assert (class_type.FDPCapabilitiesDuringUpdateReserved_3 == 0)
    assert (class_type.DownstreamDeviceCount is None)
    assert (class_type.DownstreamDeviceParameterTable == [])
    return


@pytest.mark.parametrize("class_type", RequestUpdate_Request())
def test_RequestUpdate_Request(class_type):
    "Verify RequestUpdate_Request initialization"

    assert (class_type.CommandValue == 0x10), "Incorrect command code"
    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.MaximumTransferSize == 0)
    assert (class_type.NumberOfComponents == 0)
    assert (class_type.MaximumOutstandingTransferRequests == 1)
    assert (class_type.PackageDataLength == 0)
    assert (class_type.ComponentImageSetVersionStringType == 0)
    assert (class_type.ComponentImageSetVersionStringLength is None)
    assert (class_type.ComponentImageSetVersionString == b'')
    return


@pytest.mark.parametrize("class_type", RequestUpdate_Response())
def test_RequestUpdate_Response(class_type):
    "Verify RequestUpdate_Response initialization"

    assert (class_type.CommandValue == RequestUpdate_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.FirmwareDeviceMetaDataLength == 0)
    assert (class_type.FDWillSendGetPackageDataCommand == 0)
    return


@pytest.mark.parametrize("class_type", GetPackageData_Request())
def test_GetPackageData_Request(class_type):
    "Verify GetPackageData_Request initialization"

    assert (class_type.CommandValue == 0x11), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.TransferFlag == 1)
    return


@pytest.mark.parametrize("class_type", GetPackageData_Response())
def test_GetPackageData_Response(class_type):
    "Verify GetPackageData_Response initialization"

    assert (class_type.CommandValue == GetPackageData_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 1)
    assert (class_type.PortionOfPackageData == [])
    return


@pytest.mark.parametrize("class_type", GetDeviceMetaData_Request())
def test_GetDeviceMetaData_Request(class_type):
    "Verify GetDeviceMetaData_Request initialization"

    assert (class_type.CommandValue == 0x12), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.TransferOperationFlag == 0)
    return


@pytest.mark.parametrize("class_type", GetDeviceMetaData_Response())
def test_GetDeviceMetaData_Response(class_type):
    "Verify GetDeviceMetaData_Response initialization"

    assert (class_type.CommandValue == GetDeviceMetaData_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 1)
    assert (class_type.PortionOfMetaData == [])
    return


@pytest.mark.parametrize("class_type", PassComponentTable_Request())
def test_PassComponentTable_Request(class_type):
    "Verify PassComponentTable_Request initialization"

    assert (class_type.CommandValue == 0x13), "Incorrect command code"
    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"

    assert (class_type.TransferFlag == 1)
    assert (class_type.ComponentClassification == 0)
    assert (class_type.ComponentIdentifier == 0)
    assert (class_type.ComponentClassificationIndex == 0)
    assert (class_type.ComponentComparisonStamp == 0)
    assert (class_type.ComponentVersionStringType == 0)
    assert (class_type.ComponentVersionStringLength == 0)
    assert (class_type.ComponentVersionString == b"")
    return


@pytest.mark.parametrize("class_type", PassComponentTable_Response())
def test_PassComponentTable_Response(class_type):
    "Verify PassComponentTable_Response initialization"

    assert (class_type.CommandValue == PassComponentTable_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.ComponentResponse == 0)
    assert (class_type.ComponentResponseCode == 0)
    return


@pytest.mark.parametrize("class_type", UpdateComponent_Request())
def test_UpdateComponent_Request(class_type):
    "Verify UpdateComponent_Request initialization"

    assert (class_type.CommandValue == 0x14), "Incorrect command code"
    assert (len(class_type.fields_desc) == 11), "Incorrect number of fields"

    assert (class_type.ComponentClassification == 0)
    assert (class_type.ComponentIdentifier == 0)
    assert (class_type.ComponentClassificationIndex == 0)
    assert (class_type.ComponentComparisonStamp == 0)
    assert (class_type.ComponentImageSize == 0)
    assert (class_type.Reserved_0 == 0)
    assert (class_type.UpdateOptionFlagsRequestForceUpdate == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.ComponentVersionStringType == 0)
    assert (class_type.ComponentVersionStringLength == 0)
    assert (class_type.ComponentVersionString == b"")
    return


@pytest.mark.parametrize("class_type", UpdateComponent_Response())
def test_UpdateComponent_Response(class_type):
    "Verify UpdateComponent_Response initialization"

    assert (class_type.CommandValue == UpdateComponent_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.ComponentCompatibilityResponse == 0)
    assert (class_type.ComponentCompatibilityResponseCode == 0)
    assert (class_type.Reserved_0 == 0)
    assert (class_type.UpdateOptionFlagsRequestForceUpdate == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.EstimatedTimeBeforeSendingRequestFirmwareData == 0)
    return


@pytest.mark.parametrize("class_type", RequestFirmwareData_Request())
def test_RequestFirmwareData_Request(class_type):
    "Verify RequestFirmwareData_Request initialization"

    assert (class_type.CommandValue == 0x15), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.Offset == 0)
    assert (class_type.Length == 0)
    return


@pytest.mark.parametrize("class_type", RequestFirmwareData_Response())
def test_RequestFirmwareData_Response(class_type):
    "Verify RequestFirmwareData_Response initialization"

    assert (class_type.CommandValue == RequestFirmwareData_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", TransferComplete_Request())
def test_TransferComplete_Request(class_type):
    "Verify TransferComplete_Request initialization"

    assert (class_type.CommandValue == 0x16), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.TransferResult == 0)
    return


@pytest.mark.parametrize("class_type", TransferComplete_Response())
def test_TransferComplete_Response(class_type):
    "Verify TransferComplete_Response initialization"

    assert (class_type.CommandValue == TransferComplete_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", VerifyComplete_Request())
def test_VerifyComplete_Request(class_type):
    "Verify VerifyComplete_Request initialization"

    assert (class_type.CommandValue == 0x17), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.VerifyResult == 0)
    return


@pytest.mark.parametrize("class_type", VerifyComplete_Response())
def test_VerifyComplete_Response(class_type):
    "Verify VerifyComplete_Response initialization"

    assert (class_type.CommandValue == VerifyComplete_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", ApplyComplete_Request())
def test_ApplyComplete_Request(class_type):
    "Verify ApplyComplete_Request initialization"

    assert (class_type.CommandValue == 0x18), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.ApplyResult == 0)
    assert (class_type.ComponentActivationMethodsModification == 0)
    return


@pytest.mark.parametrize("class_type", ApplyComplete_Response())
def test_ApplyComplete_Response(class_type):
    "Verify ApplyComplete_Response initialization"

    assert (class_type.CommandValue == ApplyComplete_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetMetaData_Request())
def test_GetMetaData_Request(class_type):
    "Verify GetMetaData_Request initialization"

    assert (class_type.CommandValue == 0x19), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.TransferOperationFlag == 0)
    return


@pytest.mark.parametrize("class_type", GetMetaData_Response())
def test_GetMetaData_Response(class_type):
    "Verify GetMetaData_Response initialization"

    assert (class_type.CommandValue == GetMetaData_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 1)
    return


@pytest.mark.parametrize("class_type", ActivateFirmware_Request())
def test_ActivateFirmware_Request(class_type):
    "Verify ActivateFirmware_Request initialization"

    assert (class_type.CommandValue == 0x1A), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"

    assert (class_type.SelfContainedActivationRequest == 0)
    return


@pytest.mark.parametrize("class_type", ActivateFirmware_Response())
def test_ActivateFirmware_Response(class_type):
    "Verify ActivateFirmware_Response initialization"

    assert (class_type.CommandValue == ActivateFirmware_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.EstimatedTimeForSelfContainedActivation == 0)
    return


@pytest.mark.parametrize("class_type", GetStatus_Request())
def test_GetStatus_Request(class_type):
    "Verify GetStatus_Request initialization"

    assert (class_type.CommandValue == 0x1B), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetStatus_Response())
def test_GetStatus_Response(class_type):
    "Verify GetStatus_Response initialization"

    assert (class_type.CommandValue == GetStatus_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.CurrentState == 0)
    assert (class_type.PreviousState == 0)
    assert (class_type.AuxState == 0)
    assert (class_type.AuxStateStatus == 0)
    assert (class_type.ProgressPercent == 0)
    assert (class_type.ReasonCode == 0)
    assert (class_type.UpdateOptionFlagsEnabled == 0)
    return


@pytest.mark.parametrize("class_type", CancelUpdateComponent_Request())
def test_CancelUpdateComponent_Request(class_type):
    "Verify CancelUpdateComponent_Request initialization"

    assert (class_type.CommandValue == 0x1C), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", CancelUpdateComponent_Response())
def test_CancelUpdateComponent_Response(class_type):
    "Verify CancelUpdateComponent_Response initialization"

    assert (class_type.CommandValue == CancelUpdateComponent_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", CancelUpdate_Request())
def test_CancelUpdate_Request(class_type):
    "Verify CancelUpdate_Request initialization"

    assert (class_type.CommandValue == 0x1D), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", CancelUpdate_Response())
def test_CancelUpdate_Response(class_type):
    "Verify CancelUpdate_Response initialization"

    assert (class_type.CommandValue == CancelUpdate_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NonFunctioningComponentIndication == 0)
    assert (class_type.NonFunctioningComponentBitmap == 0)
    return


@pytest.mark.parametrize("class_type", ActivatePendingComponentImageSet_Request())
def test_ActivatePendingComponentImageSet_Request(class_type):
    "Verify ActivatePendingComponentImageSet_Request initialization"

    assert (class_type.CommandValue == 0x1E), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", ActivatePendingComponentImageSet_Response())
def test_ActivatePendingComponentImageSet_Response(class_type):
    "Verify ActivatePendingComponentImageSet_Response initialization"

    assert (class_type.CommandValue == ActivatePendingComponentImageSet_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.EstimatedTimeForActivation == 0)
    return


@pytest.mark.parametrize("class_type", ActivatePendingComponentImage_Request())
def test_ActivatePendingComponentImage_Request(class_type):
    "Verify ActivatePendingComponentImage_Request initialization"

    assert (class_type.CommandValue == 0x1F), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ComponentClassification == 0)
    assert (class_type.ComponentIdentifier == 0)
    assert (class_type.ComponentClassificationIndex == 0)
    return


@pytest.mark.parametrize("class_type", ActivatePendingComponentImage_Response())
def test_ActivatePendingComponentImage_Response(class_type):
    "Verify ActivatePendingComponentImage_Response initialization"

    assert (class_type.CommandValue == ActivatePendingComponentImage_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.EstimatedTimeForActivation == 0)
    return


@pytest.mark.parametrize("class_type", RequestDownstreamDeviceUpdate_Request())
def test_RequestDownstreamDeviceUpdate_Request(class_type):
    "Verify RequestDownstreamDeviceUpdate_Request initialization"

    assert (class_type.CommandValue == 0x20), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.MaximumDownstreamDeviceTransferSize == 0)
    assert (class_type.MaximumOutstandingTransferRequests == 1)
    assert (class_type.DownstreamDevicePackageDataLength == 0)
    return


@pytest.mark.parametrize("class_type", RequestDownstreamDeviceUpdate_Response())
def test_RequestDownstreamDeviceUpdate_Response(class_type):
    "Verify RequestDownstreamDeviceUpdate_Response initialization"

    assert (class_type.CommandValue == RequestDownstreamDeviceUpdate_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.DownstreamDeviceMetaDataLength == 0)
    assert (class_type.DDWillSendGetPackageDataCommand == 0)
    return


@pytest.mark.parametrize("class_type", TestUnsupportedPldm_Request())
def test_TestUnsupportedPldm_Request(class_type):
    "Verify TestUnsupportedPldm_Request initialization"

    assert (class_type.CommandValue == 0xF2), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", TestUnsupportedPldm_Response())
def test_TestUnsupportedPldm_Response(class_type):
    "Verify TestUnsupportedPldm_Response initialization"

    assert (class_type.CommandValue == TestUnsupportedPldm_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return
