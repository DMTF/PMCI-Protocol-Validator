# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Verify additional NC-SI definitions
##############################################################################

import pytest
from ncsi.dmtf_1_2_0 import *  # pylint: disable=unused-import, unused-wildcard-import


@pytest.mark.parametrize("class_type", GetNcCapabilitiesSettings_Request())
def test_GetNcCapabilitiesSettings_Request(class_type):
    """Verify GetNcCapabilitiesSettings_Request initialization"""

    assert (class_type.CommandValue == 0x25), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetNcCapabilitiesSettings_Response())
def test_GetNcCapabilitiesSettings_Response(class_type):
    """Verify GetNcCapabilitiesSettings_Response initialization"""

    assert (class_type.CommandValue == GetNcCapabilitiesSettings_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 24), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.MaxPorts == 0)
    assert (class_type.EnabledPorts == 0)
    assert (class_type.MaxPCIeEndpoints == 0)
    assert (class_type.EnabledPCIeEndpoints == 0)
    assert (class_type.MaxPFs == 0)
    assert (class_type.EnabledPFs == 0)
    assert (class_type.MaxVFs == 0)

    assert (class_type.FabricsEthernet == 0)
    assert (class_type.FabricsFibreChannel == 0)
    assert (class_type.FabricsInfiniBand == 0)
    assert (class_type.Reserved_0 == 0)

    assert (class_type.EnabledFabricsEthernet == 0)
    assert (class_type.EnabledFabricsFibreChannel == 0)
    assert (class_type.EnabledFabricsInfiniBand == 0)
    assert (class_type.EnabledFabricsReserved == 0)

    assert (class_type.VFAllocation == 0)
    assert (class_type.EnabledPortsFlag == 0)
    assert (class_type.EnabledPCIeEndpointsFlag == 0)
    assert (class_type.EnabledPFsFlag == 0)
    assert (class_type.MaxDataTransferSizeExp == 0)
    assert (class_type.Reserved_1 == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPfAssignment_Request())
def test_GetPfAssignment_Request(class_type):
    """Verify GetPfAssignment_Request initialization"""

    assert (class_type.CommandValue == 0x27), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPfAssignment_Response())
def test_GetPfAssignment_Response(class_type):
    """Verify GetPfAssignment_Response initialization"""

    assert (class_type.CommandValue == GetPfAssignment_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetPfAssignment_Request())
def test_SetPfAssignment_Request(class_type):
    """Verify SetPfAssignment_Request initialization"""

    assert (class_type.CommandValue == 0x28), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetPfAssignment_Response())
def test_SetPfAssignment_Response(class_type):
    """Verify SetPfAssignment_Response initialization"""

    assert (class_type.CommandValue == SetPfAssignment_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetChannelConfiguration_Request())
def test_GetChannelConfiguration_Request(class_type):
    """Verify GetChannelConfiguration_Request initialization"""

    assert (class_type.CommandValue == 0x29), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", ChannelConfigurationEntry())
def test_ChannelConfigurationEntry(class_type):
    """Verify ChannelConfigurationEntry initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.MaxTxBW == 0)
    assert (class_type.MinTxBW == 0)
    return


@pytest.mark.parametrize("class_type", GetChannelConfiguration_Response())
def test_GetChannelConfiguration_Response(class_type):
    """Verify GetChannelConfiguration_Response initialization"""

    assert (class_type.CommandValue == GetChannelConfiguration_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 13), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.FabricType == 0)
    assert (class_type.SharedInterface == 0)
    assert (class_type.Reserved_0 == 0)
    assert (class_type.SFFcage == 0)
    assert (class_type.BaseT == 0)
    assert (class_type.Backplane == 0)
    assert (class_type.MaxMTU == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.NumEnabledPartitions is None)
    assert (class_type.Bandwidth is not None)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetChannelConfiguration_Request())
def test_SetChannelConfiguration_Request(class_type):
    """Verify SetChannelConfiguration_Request initialization"""

    assert (class_type.CommandValue == 0x2A), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.FabricType == 0)
    assert (class_type.NumPartitions == 0)
    assert (class_type.MaxMTU == 0)
    assert (class_type.NumEnabledPartitions == 0)
    assert (class_type.Bandwidth is not None)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetChannelConfiguration_Response())
def test_SetChannelConfiguration_Response(class_type):
    """Verify SetChannelConfiguration_Response initialization"""

    assert (class_type.CommandValue == SetChannelConfiguration_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPartitionConfiguration_Request())
def test_GetPartitionConfiguration_Request(class_type):
    "Verify GetPartitionConfiguration_Request initialization"

    assert (class_type.CommandValue == 0x2B), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", AddressTlvEntry())
def test_AddressTlvEntry(class_type):
    "Verify AddressTlvEntry initialization"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.AddressType == 0)
    assert (class_type.AddressLength is None)
    assert (class_type.Address == [])
    return


@pytest.mark.parametrize("class_type", GetPartitionConfiguration_Response())
def test_GetPartitionConfiguration_Response(class_type):
    """Verify GetPartitionConfiguration_Response initialization"""

    assert (class_type.CommandValue == GetPartitionConfiguration_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) >= 8), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetPartitionConfiguration_Request())
def test_SetPartitionConfiguration_Request(class_type):
    """Verify SetPartitionConfiguration_Request initialization"""

    assert (class_type.CommandValue == 0x2C), "Incorrect command code"
    assert (len(class_type.fields_desc) == 16), "Incorrect number of fields"

    assert (class_type.PartitionID == 0)
    assert (class_type.EthernetStatus == 0)
    assert (class_type.FibreChannelStatus == 0)
    assert (class_type.FibreChannelOverEthernetStatus == 0)
    assert (class_type.InfiniBandStatus == 0)

    assert (class_type.iSCSIOffloadStatus == 0)
    assert (class_type.RDMAStatus == 0)
    assert (class_type.NVMe == 0)
    assert (class_type.Reserved_0 == 0)
    assert (class_type.Reserved_1 == 0)

    assert (class_type.PartitionLinkControl == 0)
    assert (class_type.Reserved_2 == 0)
    assert (class_type.AddressCount == 0)
    assert (class_type.AddressLength == 0)
    assert (class_type.AddressType == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetPartitionConfiguration_Response())
def test_SetPartitionConfiguration_Response(class_type):
    """Verify SetPartitionConfiguration_Response initialization"""

    assert (class_type.CommandValue == SetPartitionConfiguration_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", BootProtocolTlvPXE())
def test_BootProtocolTlvPXE(class_type):
    """Verify BootProtocolTlvPXE initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.Type == 0x00)
    assert (class_type.Length is None)
    assert (class_type.Value == [])
    return


@pytest.mark.parametrize("class_type", BootProtocolTlvFC())
def test_BootProtocolTlvFC(class_type):
    """Verify BootProtocolTlvFC initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.Type == 0x00)
    assert (class_type.Length is None)
    assert (class_type.Value == [])
    return


@pytest.mark.parametrize("class_type", BootProtocolTlvFCoE())
def test_BootProtocolTlvFCoE(class_type):
    """Verify BootProtocolTlvFCoE initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.Type == 0x00)
    assert (class_type.Length is None)
    assert (class_type.Value == [])
    return

@pytest.mark.parametrize("class_type", BootProtocolTlvISCSI())
def test_BootProtocolTlvISCSI(class_type):
    """Verify BootProtocolTlvISCSI initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.Type == 0x00)
    assert (class_type.Length is None)
    assert (class_type.Value == [])
    return

@pytest.mark.parametrize("class_type", BootProtocolTlvNVMeoFC())
def test_BootProtocolTlvNVMeoFC(class_type):
    """Verify BootProtocolTlvNVMeoFC initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.Type == 0x00)
    assert (class_type.Length is None)
    assert (class_type.Value == [])
    return

@pytest.mark.parametrize("class_type", BootProtocolTlvGeneric())
def test_BootProtocolTlvGeneric(class_type):
    """Verify BootProtocolTlvGeneric initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.Type == 0x00)
    assert (class_type.Length is None)
    assert (class_type.Value == [])
    return


@pytest.mark.parametrize("class_type", GetBootConfig_Request())
def test_GetBootConfig_Request(class_type):
    """Verify GetBootConfig_Request initialization"""

    assert (class_type.CommandValue == 0x2D), "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.PartitionID == 0)
    assert (class_type.Reserved == 0)
    assert (class_type.ProtocolType == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetBootConfig_Response())
def test_GetBootConfig_Response(class_type):
    """Verify GetBootConfig_Response initialization"""

    assert (class_type.CommandValue == GetBootConfig_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.Reserved == 0x00)
    assert (class_type.ProtocolType == 0x00)
    assert (class_type.NumberOfTLVs is None)
    assert (class_type.TLVs == [])

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetBootConfig_Request())
def test_SetBootConfig_Request(class_type):
    """Verify SetBootConfig_Request initialization"""

    assert (class_type.CommandValue == 0x2E), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.PartitionID == 0)
    assert (class_type.Reserved == 0)
    assert (class_type.ProtocolType == 0)
    assert (class_type.NumberOfTLVs is None)
    assert (class_type.TLVs == [])

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetBootConfig_Response())
def test_SetBootConfig_Response(class_type):
    """Verify SetBootConfig_Response initialization"""

    assert (class_type.CommandValue == SetBootConfig_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPartitionStatistics_Request())
def test_GetPartitionStatistics_Request(class_type):
    """Verify GetPartitionStatistics_Request initialization"""

    assert (class_type.CommandValue == 0x2F), "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.PartitionID == 0)
    assert (class_type.Reserved == 0)
    assert (class_type.StatsType == 1)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPartitionStatisticsEthernet())
def test_GetPartitionStatisticsEthernet_Request(class_type):
    """Verify GetPartitionStatisticsEthernet initialization"""

    assert (len(class_type.fields_desc) == 45), "Incorrect number of fields"
    assert (class_type.TotalBroadcastBytesTransmittedSize == 0)

    return


@pytest.mark.parametrize("class_type", GetPartitionStatisticsFCoE())
def test_GetPartitionStatisticsFCoE_Request(class_type):
    """Verify GetPartitionStatisticsFCoE initialization"""

    assert (len(class_type.fields_desc) == 18), "Incorrect number of fields"
    assert (class_type.Reserved_0 == 0)

    return


@pytest.mark.parametrize("class_type", GetPartitionStatisticsISCSI())
def test_GetPartitionStatisticsISCSI_Request(class_type):
    """Verify GetPartitionStatisticsISCSI initialization"""

    assert (len(class_type.fields_desc) == 18), "Incorrect number of fields"
    assert (class_type.Reserved_0 == 0)

    return


@pytest.mark.parametrize("class_type", GetPartitionStatisticsIB())
def test_GetPartitionStatisticsIB_Request(class_type):
    """Verify GetPartitionStatisticsIB initialization"""

    assert (len(class_type.fields_desc) == 33), "Incorrect number of fields"
    assert (class_type.TotalBroadcastBytesTransmittedSize == 0)

    return


@pytest.mark.parametrize("class_type", GetPartitionStatisticsFC())
def test_GetPartitionStatisticsFC_Request(class_type):
    """Verify GetPartitionStatisticsFC initialization"""

    assert (len(class_type.fields_desc) == 20), "Incorrect number of fields"
    assert (class_type.Reserved_0 == 0)

    return


@pytest.mark.parametrize("class_type", GetPartitionStatisticsRDMA())
def test_GetPartitionStatisticsRDMA_Request(class_type):
    """Verify GetPartitionStatisticsRDMA initialization"""

    assert (len(class_type.fields_desc) == 30), "Incorrect number of fields"
    assert (class_type.Reserved_0 == 0)

    return


@pytest.mark.parametrize("class_type", GetPartitionStatistics_Response())
def test_GetPartitionStatistics_Response(class_type):
    """Verify GetPartitionStatistics_Response initialization"""

    assert (class_type.CommandValue == GetPartitionStatistics_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 10), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.StatsType == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetModuleManagementData_Request())
def test_SetModuleManagementData_Request(class_type):
    """Verify SetModuleManagementData_Request initialization"""

    assert (class_type.CommandValue == 0x30), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.RequestedBank == 0)
    assert (class_type.RequestedPage == 0)
    assert (class_type.Offset == 0)
    assert (class_type.Length is None)
    assert (class_type.ManagementData == [])

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetModuleManagementData_Response())
def test_SetModuleManagementData_Response(class_type):
    """Verify SetModuleManagementDatax_Response initialization"""

    assert (class_type.CommandValue == SetModuleManagementData_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetPassThroughModeControl_Request())
def test_SetPassThroughModeControl_Request(class_type):
    """Verify SetPassThroughModeControl_Request initialization"""

    assert (class_type.CommandValue == 0x33), "Incorrect command code"
    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.Reserved_0 == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.NetworkBMCPassthroughTraffic == 0)
    assert (class_type.HostBmcPassthroughTraffic == 0)
    assert (class_type.EmbeddedCpuBmcPassthroughTraffic == 0)
    assert (class_type.Reserved_2 == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetPassThroughModeControl_Response())
def test_SetPassThroughModeControl_Response(class_type):
    """Verify SetPassThroughModeControl_Response initialization"""

    assert (class_type.CommandValue == SetPassThroughModeControl_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPassThroughModeControl_Request())
def test_GetPassThroughModeControl_Request(class_type):
    """Verify GetPassThroughModeControl_Request initialization"""

    assert (class_type.CommandValue == 0x34), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPassThroughModeControl_Response())
def test_GetPassThroughModeControl_Response(class_type):
    """Verify GetPassThroughModeControl_Response initialization"""

    assert (class_type.CommandValue == GetPassThroughModeControl_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 12), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.Reserved_0 == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.EmbeddedCpuBmcPassthroughTraffic == 0)
    assert (class_type.HostBmcPassthroughTraffic == 0)
    assert (class_type.NetworkBMCPassthroughTraffic == 0)
    assert (class_type.Reserved_2 == 0)
    assert (class_type.EmbeddedCpuBmcPassthroughTrafficSupported == 0)
    assert (class_type.HostBmcPassthroughTrafficSupported == 0)
    assert (class_type.NetworkBMCPassthroughTrafficSupported == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetVfAllocation_Request())
def test_GetVfAllocation_Request(class_type):
    """Verify GetVfAllocation_Request initialization"""

    assert (class_type.CommandValue == 0x35), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetVfAllocation_Response())
def test_GetVfAllocation_Response(class_type):
    """Verify GetVfAllocation_Response initialization"""

    assert (class_type.CommandValue == GetVfAllocation_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.FunctionNumVfList == [])
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetVfAllocation_Request())
def test_SetVfAllocation_Request(class_type):
    """Verify SetVfAllocation_Request initialization"""

    assert (class_type.CommandValue == 0x36), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.FunctionNumVfList == [])
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetVfAllocation_Response())
def test_SetVfAllocation_Response(class_type):
    """Verify SetVfAllocation_Response initialization"""

    assert (class_type.CommandValue == SetVfAllocation_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SettingsCommit_Request())
def test_SettingsCommit_Request(class_type):
    """Verify SettingsCommit_Request initialization"""

    assert (class_type.CommandValue == 0x47), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SettingsCommit_Response())
def test_SettingsCommit_Response(class_type):
    """Verify SettingsCommit_Response initialization"""

    assert (class_type.CommandValue == SettingsCommit_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", ThermalShutdownControl_Request())
def test_ThermalShutdownControl_Request(class_type):
    """Verify ThermalShutdownControl_Request initialization"""

    assert (class_type.CommandValue == 0x4B), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.Reserved == 0x00)
    assert (class_type.Operation == 0x00)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", ThermalShutdownControl_Response())
def test_ThermalShutdownControl_Response(class_type):
    """Verify ThermalShutdownControl_Response initialization"""

    assert (class_type.CommandValue == ThermalShutdownControl_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.Reserved_0 == 0x00)
    assert (class_type.Reserved_1 == 0x00)
    assert (class_type.EnableDisableSupport == 0x00)
    assert (class_type.OperatingState == 0x00)
    assert (class_type.ShutdownTemperature == 0x00)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", TransmitDataNC_Request())
def test_TransmitDataNC_Request(class_type):
    """Verify TransmitDataNC_Request initialization"""

    assert (class_type.CommandValue == 0x4C), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.Reserved == 0)
    assert (class_type.OpCode == 0)
    assert (class_type.Offset == 0)
    assert (class_type.DataHandle == 0)
    assert (class_type.Data == [])

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", TransmitDataNC_Response())
def test_TransmitDataNC_Response(class_type):
    """Verify TransmitDataNC_Response initialization"""

    assert (class_type.CommandValue == TransmitDataNC_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", RetrieveDataFromNC_Request())
def test_RetrieveDataFromNC_Request(class_type):
    """Verify RetrieveDataFromNC_Request initialization"""

    assert (class_type.CommandValue == 0x4D), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.Reserved == 0)
    assert (class_type.OpCode == 0)
    assert (class_type.Offset == 0)
    assert (class_type.DataHandle == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", RetrieveDataFromNC_Response())
def test_RetrieveDataFromNC_Response(class_type):
    """Verify RetrieveDataFromNC_Response initialization"""

    assert (class_type.CommandValue == RetrieveDataFromNC_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.Reserved == 0)
    assert (class_type.OpCode == 0)
    assert (class_type.Data == [])

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetInventoryInformation_Request())
def test_GetInventoryInformation_Request(class_type):
    """Verify GetInventoryInformation_Request initialization"""

    assert (class_type.CommandValue == 0x4E), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", InventoryInfoEntry())
def test_InventoryInfoEntry(class_type):
    """Verify InventoryInfoEntry initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.AttributeNameType == 0)
    assert (class_type.Length is None)
    assert (class_type.Value == [])
    return


@pytest.mark.parametrize("class_type", GetInventoryInformation_Response())
def test_GetInventoryInformation_Response(class_type):
    """Verify GetInventoryInformation_Response initialization"""

    assert (class_type.CommandValue == GetInventoryInformation_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.NumberOfTLVs is None)
    assert (class_type.TLV is not None)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", TransportSpecificAENEnable_Request())
def test_TransportSpecificAENEnable_Request(class_type):
    """Verify TransportSpecificAENEnable_Request initialization"""

    assert (class_type.CommandValue == 0x55), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.Reserved_0 == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.PendingSpdmRequestAEN == 0)
    assert (class_type.PendingPldmRequestAEN == 0)
    assert (class_type.MediumChangeAenControl == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", TransportSpecificAENEnable_Response())
def test_TransportSpecificAENEnable_Response(class_type):
    """Verify TransportSpecificAENEnable_Response initialization"""

    assert (class_type.CommandValue == TransportSpecificAENEnable_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SPDM_Request())
def test_SPDM_Request(class_type):
    """Verify SPDM_Request initialization"""

    assert (class_type.CommandValue == 0x60), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.SpdmVersion == 0)
    assert (class_type.RequestCode == 0)
    assert (class_type.Param1 == 0)
    assert (class_type.Param2 == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SPDM_Response())
def test_SPDM_Response(class_type):
    """Verify SPDM_Response initialization"""

    assert (class_type.CommandValue == SPDM_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.SpdmVersion == 0)
    assert (class_type.RequestCode == 0)
    assert (class_type.Param1 == 0)
    assert (class_type.Param2 == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", QueryPendingNcSpdmRequest_Request())
def test_QueryPendingNcSpdmRequest_Request(class_type):
    """VerifyQueryPendingNcSpdmRequest_Request initialization"""

    assert (class_type.CommandValue == 0x61), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", QueryPendingNcSpdmRequest_Response())
def test_QueryPendingNcSpdmRequest_Response(class_type):
    """Verify QueryPendingNcSpdmRequest_Response initialization"""

    assert (class_type.CommandValue == QueryPendingNcSpdmRequest_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.SpdmVersion == 0)
    assert (class_type.RequestCode == 0)
    assert (class_type.Param1 == 0)
    assert (class_type.Param2 == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SendNcSpdmReply_Request())
def test_SendNcSpdmReply_Request(class_type):
    """VerifySendNcSpdmReply_Request initialization"""

    assert (class_type.CommandValue == 0x62), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.SpdmVersion == 0)
    assert (class_type.RequestCode == 0)
    assert (class_type.Param1 == 0)
    assert (class_type.Param2 == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SendNcSpdmReply_Response())
def test_SendNcSpdmReply_Response(class_type):
    """Verify SendNcSpdmReply_Response initialization"""

    assert (class_type.CommandValue == SendNcSpdmReply_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.Reserved == 0)
    assert (class_type.ReservedFlags == 0)
    assert (class_type.PendingRequest == 0)

    assert (class_type.Checksum is None)
    return

