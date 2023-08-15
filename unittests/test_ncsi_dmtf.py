##############################################################################
#  File Abstract:
#  Verify the NC-SI definitions
##############################################################################

import pytest
from ncsi.dmtf import *  # pylint: disable=unused-import, unused-wildcard-import


@pytest.mark.parametrize("class_type", NCSI_HEADER())
def test_NCSI_HEADER(class_type):
    """Verify NCSI_HEADER class strucutre and initialization"""

    assert (len(class_type.fields_desc) == 10), "Incorrect number of fields"

    assert (class_type.MC_ID == 0)
    assert (class_type.HeaderRevision == 1)
    assert (class_type.NcsiHeaderReserved_1 == 0)
    assert (class_type.IID == 1)
    assert (class_type.Command is None)
    assert (class_type.PackageID == 0)
    assert (class_type.ChannelID == 0)
    assert (class_type.Flags == 0)
    assert (class_type.PayloadLength is None)
    assert (class_type.NcsiHeaderReserved_2 == 0)
    return


@pytest.mark.parametrize("class_type", ClearInitialState_Request())
def test_ClearInitialState_Request(class_type):
    """Verify ClearInitialState_Request initialization"""

    assert (class_type.CommandValue == 0x00), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", ClearInitialState_Response())
def test_ClearInitialState_Response(class_type):
    """Verify ClearInitialState_Response initialization"""

    assert (class_type.CommandValue == ClearInitialState_Request.CommandValue | 0x80), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SelectPackage_Request())
def test_SelectPackage_Request(class_type):
    """Verify SelectPackage_Request initialization"""

    assert (class_type.CommandValue == 0x01), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.SelectPackageReserved_1 == 0)
    assert (class_type.HardwareArbitrationReserved_2 == 0)
    assert (class_type.DelayedResponseEnable == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SelectPackage_Response())
def test_SelectPackage_Response(class_type):
    """Verify SelectPackage_Response initialization"""

    assert (class_type.CommandValue == SelectPackage_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DeselectPackage_Request())
def test_DeselectPackage_Request(class_type):
    """Verify DeselectPackage_Request initialization"""

    assert (class_type.CommandValue == 0x02), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DeselectPackage_Response())
def test_DeselectPackage_Response(class_type):
    """Verify DeselectPackage_Response initialization"""

    assert (class_type.CommandValue == DeselectPackage_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableChannel_Request())
def test_EnableChannel_Request(class_type):
    """Verify EnableChannel_Request initialization"""

    assert (class_type.CommandValue == 0x03), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableChannel_Response())
def test_EnableChannel_Response(class_type):
    """Verify EnableChannel_Response initialization"""

    assert (class_type.CommandValue == EnableChannel_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableChannel_Request())
def test_DisableChannel_Request(class_type):
    """Verify DisableChannel_Request initialization"""

    assert (class_type.CommandValue == 0x04), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.Reserved == 0)
    assert (class_type.ALD == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableChannel_Response())
def test_DisableChannel_Response(class_type):
    """Verify DisableChannel_Response initialization"""

    assert (class_type.CommandValue == DisableChannel_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", ResetChannel_Request())
def test_ResetChannel_Request(class_type):
    """Verify ResetChannel_Request initialization"""

    assert (class_type.CommandValue == 0x05), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.Reserved == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", ResetChannel_Response())
def test_ResetChannel_Response(class_type):
    """Verify ResetChannel_Response initialization"""

    assert (class_type.CommandValue == ResetChannel_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableChannelNetworkTx_Request())
def test_EnableChannelNetworkTx_Request(class_type):
    """Verify EnableChannelNetworkTx_Request initialization"""

    assert (class_type.CommandValue == 0x06), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableChannelNetworkTx_Response())
def test_EnableChannelNetworkTx_Response(class_type):
    """Verify EnableChannelNetworkTx_Response initialization"""

    assert (class_type.CommandValue == EnableChannelNetworkTx_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableChannelNetworkTx_Request())
def test_DisableChannelNetworkTx_Request(class_type):
    """Verify DisableChannelNetworkTx_Request initialization"""

    assert (class_type.CommandValue == 0x07), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableChannelNetworkTx_Response())
def test_DisableChannelNetworkTx_Response(class_type):
    """Verify EnableChannelNetworkTx_Response initialization"""

    assert (class_type.CommandValue == DisableChannelNetworkTx_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", AenEnable_Request())
def test_AenEnable_Request(class_type):
    """Verify AenEnable_Request initialization"""

    assert (class_type.CommandValue == 0x08), "Incorrect command code"

    # DSP0222 1.1.0 AEN control definition
    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"

    assert (class_type.OEM == 0)
    assert (class_type.AEN_Reserved_1 == 0)
    assert (class_type.HostNcDriverStatus == 0)
    assert (class_type.ConfigurationRequired == 0)
    assert (class_type.LinkStatusChange == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", AenEnable_Response())
def test_AenEnable_Response(class_type):
    """Verify AenEnable_Response initialization"""

    assert (class_type.CommandValue == AenEnable_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetLink_Request())
def test_SetLink_Request(class_type):
    """Verify SetLink_Request initialization"""

    assert (class_type.CommandValue == 0x09), "Incorrect command code"
    assert (len(class_type.fields_desc) == 29), "Incorrect number of fields"

    assert (class_type.SetLinkReserved_2 == 0)
    assert (class_type.ParallelDetect == 0)
    assert (class_type.LinkTraining == 0)
    assert (class_type.EnergyEfficientEthernet == 0)

    assert (class_type.FecAlgorithm == 0)
    assert (class_type.ModulationScheme == 0)
    assert (class_type.SetLinkReserved_1 == 0)
    assert (class_type.Enable800Gbps == 0)
    assert (class_type.Enable400Gbps == 0)
    assert (class_type.Enable200Gbps == 0)
    assert (class_type.Enable5Gbps == 0)

    assert (class_type.Enable2_5Gbps == 0)
    assert (class_type.Enable100Gbps == 0)
    assert (class_type.Enable50Gbps == 0)
    assert (class_type.EnableOEM == 0)
    assert (class_type.EnableAsymmetricPause == 0)
    assert (class_type.EnablePause == 0)
    assert (class_type.EnableFullDuplex == 0)
    assert (class_type.EnableHalfDuplex == 0)

    assert (class_type.Enable40Gbps == 0)
    assert (class_type.Enable25Gbps == 0)
    assert (class_type.Enable20Gbps == 0)
    assert (class_type.Enable10Gbps == 0)
    assert (class_type.Enable1Gbps == 0)
    assert (class_type.Enable100Mbps == 0)
    assert (class_type.Enable10Mbps == 0)
    assert (class_type.AutoNegotiation == 0)

    assert (class_type.OEM_Settings == 0)
    return


@pytest.mark.parametrize("class_type", SetLink_Response())
def test_SetLink_Response(class_type):
    """Verify SetLink_Response initialization"""

    assert (class_type.CommandValue == SetLink_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetLinkStatus_Request())
def test_GetLinkStatus_Request(class_type):
    """Verify GetLinkStatus_Request initialization"""

    assert (class_type.CommandValue == 0x0A), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetLinkStatus_Response())
def test_GetLinkStatus_Response(class_type):
    """Verify GetLinkStatus_Response initialization"""

    assert (class_type.CommandValue == GetLinkStatus_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 29), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.ExtendedSpeedAndDuplex == 0)
    assert (class_type.ModulationScheme == 0)
    assert (class_type.OemLinkSpeedValid == 0)
    assert (class_type.SerDesLink == 0)
    assert (class_type.LinkPartnerAdvertisedFlowControl == 0)
    assert (class_type.RxFlowControlFlag == 0)
    assert (class_type.TxFlowControlFlag == 0)
    assert (class_type.LinkPartnerAdvertisedSpeedAndDuplex10THD == 0)
    assert (class_type.LinkPartnerAdvertisedSpeedAndDuplex10TFD == 0)
    assert (class_type.LinkPartnerAdvertisedSpeedAndDuplex100TXHD == 0)
    assert (class_type.LinkPartnerAdvertisedSpeedAndDuplex100TXFD == 0)
    assert (class_type.LinkPartnerAdvertisedSpeedAndDuplex100T4 == 0)
    assert (class_type.LinkPartnerAdvertisedSpeedAndDuplex1000THD == 0)
    assert (class_type.LinkPartnerAdvertisedSpeedAndDuplex1000TFD == 0)
    assert (class_type.LinkStatusReserved_1 == 0)
    assert (class_type.ParallelDetectionFlag == 0)
    assert (class_type.AutoNegotiateComplete == 0)
    assert (class_type.AutoNegotiateFlag == 0)
    assert (class_type.SpeedAndDuplex == 0)
    assert (class_type.LinkFlag == 0)

    assert (class_type.GetLinkStatusOtherReserved_1 == 0)
    assert (class_type.ParallelDetect == 0)
    assert (class_type.LinkTraining == 0)
    assert (class_type.EnergyEfficientEthernet == 0)
    assert (class_type.HostDriverStatusIndication == 0)
    assert (class_type.OemLinkStatus == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetVlanFilter_Request())
def test_SetVlanFilter_Request(class_type):
    """Verify SetVlanFilter_Request initialization"""

    assert (class_type.CommandValue == 0x0B), "Incorrect command code"
    assert (len(class_type.fields_desc) == 9), "Incorrect number of fields"

    assert (class_type.SetVlanFilterReserved_1 == 0)
    assert (class_type.Priority == 0)
    assert (class_type.CFI == 0)
    assert (class_type.VlanId == 0)
    assert (class_type.SetVlanFilterReserved_2 == 0)
    assert (class_type.FilterSelector == 0)
    assert (class_type.SetVlanFilterReserved_3 == 0)
    assert (class_type.Enable == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetVlanFilter_Response())
def test_SetVlanFilter_Response(class_type):
    """Verify SetVlanFilter_Response initialization"""

    assert (class_type.CommandValue == SetVlanFilter_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableVlan_Request())
def test_EnableVlan_Request(class_type):
    """Verify EnableVlan_Request initialization"""

    assert (class_type.CommandValue == 0x0C), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.EnableVlanReserved_1 == 0)
    assert (class_type.Mode == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableVlan_Response())
def test_EnableVlan_Response(class_type):
    """Verify EnableVlan_Response initialization"""

    assert (class_type.CommandValue == EnableVlan_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableVlan_Request())
def test_DisableVlan_Request(class_type):
    """Verify DisableVlan_Request initialization"""

    assert (class_type.CommandValue == 0x0D), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableVlan_Response())
def test_DisableVlan_Response(class_type):
    """Verify DisableVlan_Response initialization"""

    assert (class_type.CommandValue == DisableVlan_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetSupportedMedia_Request())
def test_GetSupportedMedia_Request(class_type):
    """Verify GetSupportedMedia_Request initialization"""

    assert (class_type.CommandValue == 0x54), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetSupportedMedia_Response())
def test_GetSupportedMedia_Response(class_type):
    """Verify GetSupportedMedia_Response initialization"""

    assert (class_type.CommandValue == GetSupportedMedia_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.GetSupportedMediaReserved_1 == 0x00)
    assert (class_type.NumberOfSupportedMedias is None)
    assert (class_type.MediaDescriptors == [])
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetMcMacAddress_Request())
def test_GetMcMacAddress_Request(class_type):
    """Verify GetMcMacAddress_Request initialization"""

    assert (class_type.CommandValue == 0x58), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetMcMacAddress_Response())
def test_GetMcMacAddress_Response(class_type):
    """Verify GetMcMacAddress_Response initialization"""

    assert (class_type.CommandValue == GetMcMacAddress_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.AddressCount is None)
    assert (class_type.GetMcMacAddress_1 == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", AEN())
def test_AEN(class_type):
    """Verify _Request initialization"""

    assert (class_type.CommandValue == 0xFF), "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.AenReserved_1 == 0)
    assert (class_type.AenType == 0)
    assert (class_type.OptionalAenData == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetMACAddress_Request())
def test_SetMACAddress_Request(class_type):
    """Verify SetMACAddress_Request initialization"""

    assert (class_type.CommandValue == 0x0E), "Incorrect command code"
    assert (len(class_type.fields_desc) == 11), "Incorrect number of fields"

    assert (class_type.MACAddress_5 == 0)
    assert (class_type.MACAddress_4 == 0)
    assert (class_type.MACAddress_3 == 0)
    assert (class_type.MACAddress_2 == 0)
    assert (class_type.MACAddress_1 == 0)
    assert (class_type.MACAddress_0 == 0)
    assert (class_type.MACAddressNum == 0)
    assert (class_type.AddressType == 0)
    assert (class_type.Reserved == 0)
    assert (class_type.Enable == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetMACAddress_Response())
def test_SetMACAddress_Response(class_type):
    """Verify SetMACAddress_Response initialization"""

    assert (class_type.CommandValue == SetMACAddress_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableBroadcastFilter_Request())
def test_EnableBroadcastFilter_Request(class_type):
    """Verify EnableBroadcastFilter_Request initialization"""

    assert (class_type.CommandValue == 0x10), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.Reserved == 0)
    assert (class_type.NetBIOSPackets == 0)
    assert (class_type.DHCPServerPackets == 0)
    assert (class_type.DHCPClientPackets == 0)
    assert (class_type.ARPPackets == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableBroadcastFilter_Response())
def test_EnableBroadcastFilter_Response(class_type):
    """Verify EnableBroadcastFilter_Response initialization"""

    assert (class_type.CommandValue == EnableBroadcastFilter_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetVersionID_Request())
def test_GetVersionID_Request(class_type):
    """Verify GetVersionID_Request initialization"""

    assert (class_type.CommandValue == 0x15), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetVersionID_Response())
def test_GetVersionID_Response(class_type):
    """Verify GetVersionID_Response initialization"""

    assert (class_type.CommandValue == GetVersionID_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 21), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.NCSIVersionMajor == 0)
    assert (class_type.NCSIVersionMinor == 0)
    assert (class_type.NCSIVersionUpdate == 0)
    assert (class_type.NCSIVersionAlpha1 == 0)

    assert (class_type.Reserved == 0)
    assert (class_type.NCSIVersionAlpha2 == 0)

    assert (class_type.FirmwareNameString11_08 == b"")
    assert (class_type.FirmwareNameString07_04 == b"")
    assert (class_type.FirmwareNameString03_00 == b"")

    assert (class_type.FirmwareVersionMajor == 0)
    assert (class_type.FirmwareVersionMinor == 0)
    assert (class_type.FirmwareVersionUpdate == 0)
    assert (class_type.FirmwareVersionAlpha == 0)

    assert (class_type.PCIDID == 0)
    assert (class_type.PCIVID == 0)
    assert (class_type.PCISSID == 0)
    assert (class_type.PCISVID == 0)

    assert (class_type.ManufacturerID == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetCapabilities_Request())
def test_GetCapabilities_Request(class_type):
    """Verify GetCapabilities_Request initialization"""

    assert (class_type.CommandValue == 0x16), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetCapabilities_Response())
def test_GetCapabilities_Response(class_type):
    """Verify GetCapabilities_Response initialization"""

    assert (class_type.CommandValue == GetCapabilities_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 42), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.Reserved_1 == 0)
    assert (class_type.DelayedResponseSupport == 0)
    assert (class_type.ThermalShutdownImplementationStatus == 0)
    assert (class_type.HardwareArbitrationImplementationStatus == 0)
    assert (class_type.AllMulticastAddressesSupport == 0)
    assert (class_type.ManagementControllerToNetworkControllerFlowControlSupport == 0)
    assert (class_type.NetworkControllerToManagementControllerFlowControlSupport == 0)
    assert (class_type.HostNCDriverStatus == 0)
    assert (class_type.HardwareArbitrationCapability == 0)
    assert (class_type.Reserved_2 == 0)
    assert (class_type.NetBIOSPackets == 0)
    assert (class_type.DHCPServerPackets == 0)
    assert (class_type.DHCPClientPackets == 0)
    assert (class_type.ARPPackets == 0)
    assert (class_type.Reserved_3 == 0)
    assert (class_type.IPv6NeighborSolicitation == 0)
    assert (class_type.DHCPv6MulticastsFromServerToClientsListeningOnWellknownUDPPorts == 0)
    assert (class_type.DHCPv6RelayAndServerMulticast == 0)
    assert (class_type.IPv6RouterAdvertisement == 0)
    assert (class_type.IPv6NeighborAdvertisement == 0)
    assert (class_type.BufferingCapability == 0)
    assert (class_type.OEMSpecificAENControl == 0)
    assert (class_type.Reserved_4 == 0)
    assert (class_type.TransceiverEventAENControl == 0)
    assert (class_type.DelayedResponseReadyAENControl == 0)
    assert (class_type.HostNCDriverStatusChangeAENControl == 0)
    assert (class_type.ConfigurationRequiredAENControl == 0)
    assert (class_type.LinkStatusChangeAENControl == 0)
    assert (class_type.VLANFilterCount == 0)
    assert (class_type.MixedFilterCount == 0)
    assert (class_type.MulticastFilterCount == 0)
    assert (class_type.UnicastFilterCount == 0)
    assert (class_type.Reserved_5 == 0)
    assert (class_type.Reserved_6 == 0)
    assert (class_type.AnyVLAN_NonVLAN == 0)
    assert (class_type.VLAN_NonVLAN == 0)
    assert (class_type.VLANOnly == 1)
    assert (class_type.ChannelCount == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetParameters_Request())
def test_GetParameters_Request(class_type):
    """Verify GetParameters_Request initialization"""

    assert (class_type.CommandValue == 0x17), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetParameters_Response())
def test_GetParameters_Response(class_type):
    """Verify GetParameters_Response initialization"""

    assert (class_type.CommandValue == GetParameters_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 37), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.MACAddressCount == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.MACAddressFlags == 0)
    assert (class_type.VLANTagCount == 0)
    assert (class_type.Reserved_2 == 0)
    assert (class_type.VLANTagFlags == 0)
    assert (class_type.LinkSettings == 0)
    assert (class_type.BroadcastPacketFilterSettings == 0)
    assert (class_type.Reserved_3 == 0)
    assert (class_type.GlobalMulticastPacketFilterStatus == 0)
    assert (class_type.ChannelNetworkTXEnabled == 0)
    assert (class_type.ChannelEnabled == 0)
    assert (class_type.BroadcastPacketFilterStatus == 0)
    assert (class_type.Mode == 0)
    assert (class_type.FlowControlEnable == 0)
    assert (class_type.Reserved_4 == 0)
    assert (class_type.OEMSpecificAENControl == 0)
    assert (class_type.Reserved_5 == 0)
    assert (class_type.HostNCDriverStatusChangeAENControl == 0)
    assert (class_type.ConfigurationRequiredAENControl == 0)
    assert (class_type.LinkStatusChangeAENControl == 0)
    assert (class_type.MACAddress1_5 == 0)
    assert (class_type.MACAddress1_4 == 0)
    assert (class_type.MACAddress1_3 == 0)
    assert (class_type.MACAddress1_2 == 0)
    assert (class_type.MACAddress1_1 == 0)
    assert (class_type.MACAddress1_0 == 0)
    assert (class_type.MACAddress2_5 == 0)
    assert (class_type.MACAddress2_4 == 0)
    assert (class_type.MACAddress2_3 == 0)
    assert (class_type.MACAddress2_2 == 0)
    assert (class_type.MACAddress2_1 == 0)
    assert (class_type.MACAddress2_0 == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetControllerPacketStatistics_Request())
def test_GetControllerPacketStatistics_Request(class_type):
    """Verify GetControllerPacketStatistics_Request initialization"""

    assert (class_type.CommandValue == 0x18), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetControllerPacketStatistics_Response())
def test_GetControllerPacketStatistics_Response(class_type):
    """Verify GetControllerPacketStatistics_Response initialization"""

    assert (class_type.CommandValue == GetControllerPacketStatistics_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 43), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.CountersClearedFromLastRead == 0)
    assert (class_type.TotalBytesReceived == 0)
    assert (class_type.TotalBytesTransmitted == 0)
    assert (class_type.TotalUnicastPacketsReceived == 0)
    assert (class_type.TotalMulticastPacketsReceived == 0)
    assert (class_type.TotalBroadcastPacketsReceived == 0)
    assert (class_type.TotalUnicastPacketsTransmitted == 0)
    assert (class_type.TotalMulticastPacketsTransmitted == 0)
    assert (class_type.TotalBroadcastPacketsTransmitted == 0)
    assert (class_type.FCSReceiveErrors == 0)
    assert (class_type.AlignmentErrors == 0)
    assert (class_type.FalseCarrierDetections == 0)
    assert (class_type.RuntPacketsReceived == 0)
    assert (class_type.JabberPacketsReceived == 0)
    assert (class_type.PauseXONFramesReceived == 0)
    assert (class_type.PauseXOFFFramesReceived == 0)
    assert (class_type.PauseXONFramesTransmitted == 0)
    assert (class_type.PauseXOFFFramesTransmitted == 0)
    assert (class_type.SingleCollisionTransmitFrames == 0)
    assert (class_type.MultipleCollisionTransmitFrames == 0)
    assert (class_type.LateCollisionFrames == 0)
    assert (class_type.ExcessiveCollisionFrames == 0)
    assert (class_type.ControlFramesReceived == 0)
    assert (class_type._64_ByteFramesReceived == 0)
    assert (class_type._65_127ByteFramesReceived == 0)
    assert (class_type._128_255ByteFramesReceived == 0)
    assert (class_type._256_511ByteFramesReceived == 0)
    assert (class_type._512_1023ByteFramesReceived == 0)
    assert (class_type._1024_1522ByteFramesReceived == 0)
    assert (class_type._1523_9022ByteFramesReceived == 0)
    assert (class_type._64_ByteFramesTransmitted == 0)
    assert (class_type._65_127ByteFramesTransmitted == 0)
    assert (class_type._128_255ByteFramesTransmitted == 0)
    assert (class_type._256_511ByteFramesTransmitted == 0)
    assert (class_type._512_1023ByteFramesTransmitted == 0)
    assert (class_type._1024_1522ByteFramesTransmitted == 0)
    assert (class_type._1523_9022ByteFramesTransmitted == 0)
    assert (class_type.ValidBytesReceived == 0)
    assert (class_type.ErrorRuntPacketsReceived == 0)
    assert (class_type.ErrorJabberPacketsReceived == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetNCSIStatistics_Request())
def test_GetNCSIStatistics_Request(class_type):
    """Verify GetNCSIStatistics_Request initialization"""

    assert (class_type.CommandValue == 0x19), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetNCSIStatistics_Response())
def test_GetNCSIStatistics_Response(class_type):
    """Verify GetNCSIStatistics_Response initialization"""

    assert (class_type.CommandValue == GetNCSIStatistics_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 10), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.NCSICommandsReceived == 0)
    assert (class_type.NCSIControlPacketsDropped == 0)
    assert (class_type.NCSICommandTypeErrors == 0)
    assert (class_type.NCSICommandChecksumErrors == 0)
    assert (class_type.NCSIReceivePackets == 0)
    assert (class_type.NCSITransmitPackets == 0)
    assert (class_type.AENsSent == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", OEMCommand_Request())
def test_OEMCommand_Request(class_type):
    """Verify OEMCommand_Request initialization"""

    assert (class_type.CommandValue == 0x50), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.ManufacturerID == 0x00000000)
    return


@pytest.mark.parametrize("class_type", OEMCommand_Response())
def test_OEMCommand_Response(class_type):
    """Verify OEMCommand_Response initialization"""

    assert (class_type.CommandValue == OEMCommand_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.ManufacturerID == 0x00000000)
    return


@pytest.mark.parametrize("class_type", SendNCPLDMReply_Request())
def test_SendNCPLDMReply_Request(class_type):
    """Verify SendNCPLDMReply_Request initialization"""

    assert (class_type.CommandValue == 0x57), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.MessageCommonFields == 0)
    assert (class_type.PLDMCompletionCode == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SendNCPLDMReply_Response())
def test_SendNCPLDMReply_Response(class_type):
    """Verify SendNCPLDMReply_Response initialization"""

    assert (class_type.CommandValue == SendNCPLDMReply_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Reserved == 0)
    assert (class_type.Flags == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", TransportSpecificAENEnable_Request())
def test_TransportSpecificAENEnable_Request(class_type):
    """Verify TransportSpecificAENEnable_Request initialization"""

    assert (class_type.CommandValue == 0x55), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.Reserved_1 == 0)
    assert (class_type.Reserved_2 == 0)
    assert (class_type.PendingSPDMRequestAEN == 0)
    assert (class_type.PendingPLDMRequestAEN == 0)
    assert (class_type.MediumChangeAENControl == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", TransportSpecificAENEnable_Response())
def test_TransportSpecificAENEnable_Response(class_type):
    """Verify TransportSpecificAENEnable_Response initialization"""

    assert (class_type.CommandValue == TransportSpecificAENEnable_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", PendingPLDMRequestAEN_Request())
def test_PendingPLDMRequestAEN_Request(class_type):
    """Verify PendingPLDMRequestAEN_Request initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.Reserved == 0)
    assert (class_type.AENType == 0x71)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPackageUUID_Request())
def test_GetPackageUUID_Request(class_type):
    """Verify GetPackageUUID_Request initialization"""

    assert (class_type.CommandValue == 0x52), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPackageUUID_Response())
def test_GetPackageUUID_Response(class_type):
    """Verify GetPackageUUID_Response initialization"""

    assert (class_type.CommandValue == GetPackageUUID_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.UUID is not None)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableBroadcastFilter_Request())
def test_DisableBroadcastFilter_Request(class_type):
    """Verify DisableBroadcastFilter_Request initialization"""

    assert (class_type.CommandValue == 0x11), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableBroadcastFilter_Response())
def test_DisableBroadcastFilter_Response(class_type):
    """Verify DisableBroadcastFilter_Response initialization"""

    assert (class_type.CommandValue == DisableBroadcastFilter_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableGlobalMulticastFilter_Request())
def test_EnableGlobalMulticastFilter_Request(class_type):
    """Verify EnableGlobalMulticastFilter_Request initialization"""

    assert (class_type.CommandValue == 0x12), "Incorrect command code"
    assert (len(class_type.fields_desc) == 11), "Incorrect number of fields"

    assert (class_type.Reserved == 0)
    assert (class_type.mDNSv6 == 0)
    assert (class_type.mDNSv4 == 0)
    assert (class_type.LLDP == 0)
    assert (class_type.IPv6NeighborSolicitation == 0)
    assert (class_type.IPv6MLD == 0)
    assert (class_type.DHCPv6MulticastsFromServerToClientsListeningOnWellKnownUDPPorts == 0)
    assert (class_type.DHCPv6RelayAndServerMulticast == 0)
    assert (class_type.IPv6RouterAdvertisement == 0)
    assert (class_type.IPv6NeighborAdvertisement == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", EnableGlobalMulticastFilter_Response())
def test_EnableGlobalMulticastFilter_Response(class_type):
    """Verify EnableGlobalMulticastFilter_Response initialization"""

    assert (class_type.CommandValue == EnableGlobalMulticastFilter_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableGlobalMulticastFilter_Request())
def test_DisableGlobalMulticastFilter_Request(class_type):
    """Verify DisableGlobalMulticastFilter_Request initialization"""

    assert (class_type.CommandValue == 0x13), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", DisableGlobalMulticastFilter_Response())
def test_DisableGlobalMulticastFilter_Response(class_type):
    """Verify DisableGlobalMulticastFilter_Response initialization"""

    assert (class_type.CommandValue == DisableGlobalMulticastFilter_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetNCSIFlowControl_Request())
def test_SetNCSIFlowControl_Request(class_type):
    """Verify SetNCSIFlowControl_Request initialization"""

    assert (class_type.CommandValue == 0x14), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.Reserved == 0)
    assert (class_type.FlowControlEnable == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", SetNCSIFlowControl_Response())
def test_SetNCSIFlowControl_Response(class_type):
    """Verify SetNCSIFlowControl_Response initialization"""

    assert (class_type.CommandValue == SetNCSIFlowControl_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetNCSIPassthroughStatistics_Request())
def test_GetNCSIPassthroughStatistics_Request(class_type):
    """Verify GetNCSIPassthroughStatistics_Request initialization"""

    assert (class_type.CommandValue == 0x1A), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetNCSIPassthroughStatistics_Response())
def test_GetNCSIPassthroughStatistics_Response(class_type):
    """Verify Get NCSI Passthrough Statistics Response initialization"""

    assert (class_type.CommandValue == GetNCSIPassthroughStatistics_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Stats is not None)
    return


@pytest.mark.parametrize("class_type", GetPackageStatus_Request())
def test_GetPackageStatus_Request(class_type):
    """Verify Get Package Status Request initialization"""

    assert (class_type.CommandValue == 0x1B), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetPackageStatus_Response())
def test_GetPackageStatus_Response(class_type):
    """Verify GetPackageStatus Response initialization"""

    assert (class_type.CommandValue == GetPackageStatus_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.Reserved == 0)
    assert (class_type.HardwareArbitrationStatus == 0)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetAsicTemperature_Request())
def test_GetAsicTemperature_Request(class_type):
    """Verify Get ASIC Temperature Request initialization"""

    assert (class_type.CommandValue == 0x48), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.Reserved == 0x00000000)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetAsicTemperature_Response())
def test_GetAsicTemperature_Response(class_type):
    """Verify Get ASIC Temperature Response initialization"""

    assert (class_type.CommandValue == GetAsicTemperature_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.MaximumTemperature == 0x00)
    assert (class_type.CurrentTemperature == 0x00)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetAmbientTemperature_Request())
def test_GetAmbientTemperature_Request(class_type):
    """Verify Get Ambient Temperature Request initialization"""

    assert (class_type.CommandValue == 0x49), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.Reserved == 0x00000000)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetAmbientTemperature_Response())
def test_GetAmbientTemperature_Response(class_type):
    """Verify GetAmbientTemperature Response initialization"""

    assert (class_type.CommandValue == GetAmbientTemperature_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.TemperatureValue_3 == 0x00)
    assert (class_type.TemperatureValue_2 == 0x00)
    assert (class_type.TemperatureValue_1 == 0x00)
    assert (class_type.NumberOfSensors == 0)
    assert (class_type.Checksum is None)
    return



@pytest.mark.parametrize("class_type", GetTransceiverTemperature_Request())
def test_GetTransceiverTemperature_Request(class_type):
    """Verify Get Transceiver Temperature Request initialization"""

    assert (class_type.CommandValue == 0x4A), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.Reserved == 0x00000000)
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetTransceiverTemperature_Response())
def test_GetTransceiverTemperature_Response(class_type):
    """Verify Get Transceiver Temperature Response initialization"""

    assert (class_type.CommandValue == GetTransceiverTemperature_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.TempHighAlarmThreshold == 0x0000)
    assert (class_type.TempHighWarningThreshold == 0x0000)
    assert (class_type.TemperatureValue == 0x0000)
    assert (class_type.Reserved == 0x0000)
    assert (class_type.Checksum is None)
    return




@pytest.mark.parametrize("class_type", GetChannelConfiguration_Request())
def test_GetChannelConfiguration_Request(class_type):
    """Verify Get Channel Configuration Request initialization"""

    assert (class_type.CommandValue == 0x29), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetChannelConfiguration_Response())
def test_GetChannelConfiguration_Response(class_type):
    """Verify Get Channel Configuration Response initialization"""

    assert (class_type.CommandValue == GetChannelConfiguration_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 13), "Incorrect number of fields"
    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)

    assert (class_type.FabricType == 0)
    assert (class_type.SharedInterface == 0)
    assert (class_type.Reserved_0 == 0)
    assert (class_type.SFF_Cage == 0)
    assert (class_type.Base_T == 0)
    assert (class_type.Backplane == 0)
    assert (class_type.MaxMTU == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.NumEnabledPartitions is None)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetModuleManagementData_Request())
def test_GetModuleManagementData_Request(class_type):
    """Verify Get Module Management Data Request initialization"""

    assert (class_type.CommandValue == 0x32), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.RequestedBank == 0)
    assert (class_type.RequestedPage == 0)
    assert (class_type.Reserved_0 == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.PageUpperFlag == 0)

    assert (class_type.Checksum is None)
    return


@pytest.mark.parametrize("class_type", GetModuleManagementData_Response())
def test_GetModuleManagementData_Response(class_type):
    """Verify Get Module ManagementData Response initialization"""

    assert (class_type.CommandValue == GetModuleManagementData_Request.CommandValue | 0x80), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x00)
    assert (class_type.MaxBank == 0)
    assert (class_type.MaxPage == 0)
    assert (class_type.BankNumber == 0)
    assert (class_type.PageNumber == 0)
    assert (class_type.Checksum is None)
    return
