# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0222 runtime test cases.
##############################################################################

from pmci_protocol_validator.framework.utilities import common_send_receive
from pmci_protocol_validator.tests.tst_ncsi_enums import *
from pmci_protocol_validator.ncsi.classes.dsp0222 import *
from pmci_protocol_validator.ncsi.classes.dsp0222_pldm_payload import NcsiPldm_Request, NcsiPldm_Response
from pmci_protocol_validator.ncsi.classes.dsp0222 import PLDM_HEADER


def test_clear_initial_state(testFixture, lowerLayer):
    """ Test DSP0222 Clear Initial State Request and Response """

    # Assemble the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / ClearInitialState_Request()

    # Send the request and get the response
    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    # Validate the response header
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    # Validate the response fields
    assert (RecvPacket[ClearInitialState_Response].ResponseCode == 0)
    assert (RecvPacket[ClearInitialState_Response].ReasonCode == 0)

    # Return the response packet for further processing
    return RecvPacket


def test_select_package(testFixture, lowerLayer, hwArbEnabled=0, delayedRespEnable=0):
    """ Test DSP0222 Select Package Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SelectPackage_Request()

    SendPacket[SelectPackage_Request].DelayedResponseEnable = delayedRespEnable
    SendPacket[SelectPackage_Request].HardwareArbitrationDisable = hwArbEnabled

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[SelectPackage_Response].ResponseCode == 0)
    assert (RecvPacket[SelectPackage_Response].ReasonCode == 0)
    return RecvPacket


def test_deselect_package(testFixture, lowerLayer):
    """ Test DSP0222 Deselect Package Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DeselectPackage_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DeselectPackage_Response].ResponseCode == 0)
    assert (RecvPacket[DeselectPackage_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_channel(testFixture, lowerLayer):
    """ Test DSP0222 Enable Channel Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableChannel_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[EnableChannel_Response].ResponseCode == 0)
    assert (RecvPacket[EnableChannel_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_channel(testFixture, lowerLayer, allowLinkDown=0):
    """ Test DSP0222 Disable Channel Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableChannel_Request(ALD=allowLinkDown)

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DisableChannel_Response].ResponseCode == 0)
    assert (RecvPacket[DisableChannel_Response].ReasonCode == 0)
    return RecvPacket


def test_reset_channel(testFixture, lowerLayer):
    """ Test DSP0222 Reset Channel Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / ResetChannel_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[ResetChannel_Response].ResponseCode == 0)
    assert (RecvPacket[ResetChannel_Response].ReasonCode == 0)
    return RecvPacket


def test_get_version_id(testFixture, lowerLayer):
    """ Test DSP0222 Get Version ID Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetVersionID_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetVersionID_Response].ResponseCode == 0)
    assert (RecvPacket[GetVersionID_Response].ReasonCode == 0)
    assert (RecvPacket[GetVersionID_Response].Reserved == 0), "Reserved field NOT zero"

    return RecvPacket


def test_get_capabilities(testFixture, lowerLayer):
    """ Test DSP0222 Get Capabilities Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetCapabilities_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetCapabilities_Response].ResponseCode == 0)
    assert (RecvPacket[GetCapabilities_Response].ReasonCode == 0)

    assert (RecvPacket[GetCapabilities_Response].Capabilities.Reserved_1 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetCapabilities_Response].Capabilities.Reserved_2 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetCapabilities_Response].Capabilities.Reserved_3 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetCapabilities_Response].Capabilities.Reserved_4 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetCapabilities_Response].Capabilities.Reserved_5 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetCapabilities_Response].Capabilities.Reserved_6 == 0), "Reserved field NOT zero"

    return RecvPacket


def test_get_parameters(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get Parameter Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetParameters_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetParameters_Response].ResponseCode == 0)
    assert (RecvPacket[GetParameters_Response].ReasonCode == 0)

    assert (RecvPacket[GetParameters_Response].Parameters.Reserved_1 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetParameters_Response].Parameters.Reserved_2 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetParameters_Response].Parameters.Reserved_3 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetParameters_Response].Parameters.Reserved_4 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetParameters_Response].Parameters.Reserved_5 == 0), "Reserved field NOT zero"

    return RecvPacket


def test_enable_channel_network_tx(testFixture, lowerLayer):
    """ Test DSP0222 Enable Channel Network TX """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableChannelNetworkTx_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[EnableChannelNetworkTx_Response].ResponseCode == 0)
    assert (RecvPacket[EnableChannelNetworkTx_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_channel_network_tx(testFixture, lowerLayer):
    """ Test DSP0222 Disable Channel Network TX """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableChannelNetworkTx_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DisableChannelNetworkTx_Response].ResponseCode == 0)
    assert (RecvPacket[DisableChannelNetworkTx_Response].ReasonCode == 0)
    return RecvPacket


def test_aen_enable(testFixture, lowerLayer, OEM=0, HostNcDriverStatus=0, ConfigurationRequired=0, LinkStatusChange=0):
    """ Test DSP0222 AEN Enable """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / AenEnable_Request()

    SendPacket[AenEnable_Request].OEM = OEM
    SendPacket[AenEnable_Request].HostNcDriverStatus = HostNcDriverStatus
    SendPacket[AenEnable_Request].ConfigurationRequired = ConfigurationRequired
    SendPacket[AenEnable_Request].LinkStatusChange = LinkStatusChange

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[AenEnable_Response].ResponseCode == 0)
    assert (RecvPacket[AenEnable_Response].ReasonCode == 0)
    return RecvPacket


def test_set_link(testFixture, lowerLayer, flagsControl=0, flagsSpeeds=0, oemLinkSettings=0):
    """ Test DSP0222 Set Link """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetLink_Request()

    SendPacket[SetLink_Request].AutoNegotiation = 1 if flagsControl & NCSI_09H_CTL_AUTO_NEG else 0
    SendPacket[SetLink_Request].EnableHalfDuplex = 1 if flagsControl & NCSI_09H_CTL_HALF_DUPLEX else 0
    SendPacket[SetLink_Request].EnableFullDuplex = 1 if flagsControl & NCSI_09H_CTL_FULL_DUPLEX else 0
    SendPacket[SetLink_Request].EnablePause = 1 if flagsControl & NCSI_09H_CTL_ENABLE_PAUSE else 0
    SendPacket[SetLink_Request].EnableAsymmetricPause = 1 if flagsControl & NCSI_09H_CTL_ASYM_PAUSE_CAP else 0
    SendPacket[SetLink_Request].EnableOEM = 1 if flagsControl & NCSI_09H_CTL_OEM_SETTINGS_VALID else 0
    SendPacket[SetLink_Request].FecBASE_R_FEC = 1 if flagsControl & NCSI_09H_CTL_BASE_R_FEC else 0
    SendPacket[SetLink_Request].FecRS_FEC = 1 if flagsControl & NCSI_09H_CTL_RS_FEC else 0
    SendPacket[SetLink_Request].EnergyEfficientEthernet = 1 if flagsControl & NCSI_09H_CTL_EEE else 0
    SendPacket[SetLink_Request].LinkTraining = 1 if flagsControl & NCSI_09H_CTL_LINK_TRAINING else 0
    SendPacket[SetLink_Request].ParallelDetect = 1 if flagsControl & NCSI_09H_CTL_PARALLEL_DETECT else 0
    SendPacket[SetLink_Request].Enable_NRZ = 1 if flagsControl & NCSI_09H_CTL_MOD_NRZ else 0
    SendPacket[SetLink_Request].Enable_PAM_4 = 1 if flagsControl & NCSI_09H_CTL_MOD_PAM4 else 0

    SendPacket[SetLink_Request].Enable10Mbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_10_MBPS else 0
    SendPacket[SetLink_Request].Enable100Mbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_100_MBPS else 0
    SendPacket[SetLink_Request].Enable1Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_1_GBPS else 0
    SendPacket[SetLink_Request].Enable10Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_10_GBPS else 0
    SendPacket[SetLink_Request].Enable20Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_20_GBPS else 0
    SendPacket[SetLink_Request].Enable25Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_25_GBPS else 0
    SendPacket[SetLink_Request].Enable40Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_40_GBPS else 0
    SendPacket[SetLink_Request].Enable50Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_50_GBPS else 0
    SendPacket[SetLink_Request].Enable100Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_100_GBPS else 0
    SendPacket[SetLink_Request].Enable2_5Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_2_5_GBPS else 0
    SendPacket[SetLink_Request].Enable5Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_5_GBPS else 0
    SendPacket[SetLink_Request].Enable200Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_200_GBPS else 0
    SendPacket[SetLink_Request].Enable400Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_400_GBPS else 0
    SendPacket[SetLink_Request].Enable800Gbps = 1 if flagsSpeeds & NCSI_09H_SPD_ENB_800_GBPS else 0

    SendPacket[SetLink_Request].OEM_Settings = oemLinkSettings

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[SetLink_Response].ResponseCode == 0)
    assert (RecvPacket[SetLink_Response].ReasonCode == 0)
    return RecvPacket


def test_get_link_status(testFixture, lowerLayer):
    """ Test DSP0222 Get Link """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetLinkStatus_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetLinkStatus_Response].ResponseCode == 0)
    assert (RecvPacket[GetLinkStatus_Response].ReasonCode == 0)
    assert (RecvPacket[GetLinkStatus_Response].LinkStatus.LinkStatusReserved_1 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetLinkStatus_Response].LinkStatus.GetLinkStatusOtherReserved_1 == 0), "Reserved field NOT zero"

    return RecvPacket


def test_set_vlan_filter(testFixture, lowerLayer, Priority=0, CFI=0, VlanId=0, FilterSelector=0, Enable=0):
    """ Test DSP0222 Set VLAN Filter """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetVlanFilter_Request()

    SendPacket[SetVlanFilter_Request].Priority = Priority
    SendPacket[SetVlanFilter_Request].CFI = CFI
    SendPacket[SetVlanFilter_Request].VlanId = VlanId
    SendPacket[SetVlanFilter_Request].FilterSelector = FilterSelector
    SendPacket[SetVlanFilter_Request].Enable = Enable

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[SetVlanFilter_Response].ResponseCode == 0)
    assert (RecvPacket[SetVlanFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_vlan(testFixture, lowerLayer, mode=1):
    """ Test DSP0222 Enable VLAN """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableVlan_Request(Mode=mode)

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[EnableVlan_Response].ResponseCode == 0)
    assert (RecvPacket[EnableVlan_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_vlan(testFixture, lowerLayer):
    """ Test DSP0222 Disable VLAN """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableVlan_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DisableVlan_Response].ResponseCode == 0)
    assert (RecvPacket[DisableVlan_Response].ReasonCode == 0)
    return RecvPacket


def test_set_mac_address(testFixture, lowerLayer, Addr, Enable=False, AddrNum=0, Unicast=True):
    """ Test DSP0222 Set MAC Address """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetMACAddress_Request()


    SendPacket[SetMACAddress_Request].MACAddress_5 = RawVal(Addr[0])
    SendPacket[SetMACAddress_Request].MACAddress_4 = RawVal(Addr[1])
    SendPacket[SetMACAddress_Request].MACAddress_3 = RawVal(Addr[2])
    SendPacket[SetMACAddress_Request].MACAddress_2 = RawVal(Addr[3])
    SendPacket[SetMACAddress_Request].MACAddress_1 = RawVal(Addr[4])
    SendPacket[SetMACAddress_Request].MACAddress_0 = RawVal(Addr[5])

    SendPacket[SetMACAddress_Request].MACAddressNum = AddrNum
    SendPacket[SetMACAddress_Request].AddressType = 0 if Unicast is True else 1
    SendPacket[SetMACAddress_Request].Enable = 0 if Enable is False else 1

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[SetMACAddress_Response].ResponseCode == 0)
    assert (RecvPacket[SetMACAddress_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_broadcast_filter(testFixture, lowerLayer, EnableNetBIOS=False, EnableDHCPServer=False, EnableDHCPClient=False, EnableARP=False):
    """ Test DSP0222 Enable Broadcast Filter """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableBroadcastFilter_Request()

    SendPacket[EnableBroadcastFilter_Request].NetBIOSPackets = 1 if EnableNetBIOS else 0
    SendPacket[EnableBroadcastFilter_Request].DHCPServerPackets = 1 if EnableDHCPServer else 0
    SendPacket[EnableBroadcastFilter_Request].DHCPClientPackets = 1 if EnableDHCPClient else 0
    SendPacket[EnableBroadcastFilter_Request].ARPPackets = 1 if EnableARP else 0

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[EnableBroadcastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[EnableBroadcastFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_get_controller_packet_statistics(testFixture, lowerLayer):
    """ Test DSP0222 Get Controller Packet Statistics """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetControllerPacketStatistics_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetControllerPacketStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetControllerPacketStatistics_Response].ReasonCode == 0)
    return RecvPacket


def test_get_ncsi_statistics(testFixture, lowerLayer):
    """ Test DSP0222 Get NC-SI Statistics """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetNCSIStatistics_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetNCSIStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetNCSIStatistics_Response].ReasonCode == 0)
    return RecvPacket


def test_get_package_uuid(testFixture, lowerLayer):
    """ Test DSP0222 Get Package UUID """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPackageUUID_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetPackageUUID_Response].ResponseCode == 0)
    assert (RecvPacket[GetPackageUUID_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_broadcast_filter(testFixture, lowerLayer):
    """ Test DSP0222 Disable Broadcast Filter """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableBroadcastFilter_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DisableBroadcastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[DisableBroadcastFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_global_multicast_filter(testFixture, lowerLayer, settings=0):
    """ Test DSP0222 Enable Global Multicast Filter """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableGlobalMulticastFilter_Request()

    SendPacket[EnableGlobalMulticastFilter_Request].mDNSv6 = 1 if settings & NCSI_12H_MDNSV6 else 0
    SendPacket[EnableGlobalMulticastFilter_Request].mDNSv4 = 1 if settings & NCSI_12H_MDNSV4 else 0
    SendPacket[EnableGlobalMulticastFilter_Request].LLDP = 1 if settings & NCSI_12H_LLDP else 0
    SendPacket[EnableGlobalMulticastFilter_Request].IPv6NeighborSolicitation = 1 if settings & NCSI_12H_IPV6_NEIGHBOR_SOLICITATION else 0
    SendPacket[EnableGlobalMulticastFilter_Request].IPv6MLD = 1 if settings & NCSI_12H_IPV6_MLD else 0
    SendPacket[EnableGlobalMulticastFilter_Request].DHCPv6MulticastsFromServerToClientsListeningOnWellKnownUDPPorts = 1 if settings & NCSI_12H_DHCPV6_MC_FROMSERVER_TO_CLIENTS_LISTENING_ON_WELL_KNOWN_UDP_PORTS else 0
    SendPacket[EnableGlobalMulticastFilter_Request].DHCPv6RelayAndServerMulticast = 1 if settings & NCSI_12H_DHCPV6_RELAY_AND_SERVER_MULTICAST else 0
    SendPacket[EnableGlobalMulticastFilter_Request].IPv6RouterAdvertisement = 1 if settings & NCSI_12H_IPV6_ROUTER_ADVERTISEMENT else 0
    SendPacket[EnableGlobalMulticastFilter_Request].IPv6NeighborAdvertisement = 1 if settings & NCSI_12H_IPV6_NEIGHBOR_ADVERTISEMENT else 0

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[EnableGlobalMulticastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[EnableGlobalMulticastFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_global_multicast_filter(testFixture, lowerLayer):
    """ Test DSP0222 Disable Global Multicast Filter """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableGlobalMulticastFilter_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DisableGlobalMulticastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[DisableGlobalMulticastFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_set_ncsi_flow_control(testFixture, lowerLayer, flowControlEnable=0):
    """ Test DSP0222 Set NC-SI Flow Control """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetNCSIFlowControl_Request(FlowControlEnable=flowControlEnable)

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[SetNCSIFlowControl_Response].ResponseCode == 0)
    assert (RecvPacket[SetNCSIFlowControl_Response].ReasonCode == 0)
    return RecvPacket


def test_get_ncsi_passthrough_statistics(testFixture, lowerLayer):
    """ Test DSP0222 Get NC-SI Passthrough Statistics """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetNCSIPassthroughStatistics_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetNCSIPassthroughStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetNCSIPassthroughStatistics_Response].ReasonCode == 0)
    return RecvPacket


def test_get_package_status(testFixture, lowerLayer):
    """ Test DSP0222 Get Package Status """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPackageStatus_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetPackageStatus_Response].ResponseCode == 0)
    assert (RecvPacket[GetPackageStatus_Response].ReasonCode == 0)
    assert (RecvPacket[GetPackageStatus_Response].Reserved == 0), "Reserved field NOT zero"

    return RecvPacket


def test_oem_command(testFixture, lowerLayer, payload):
    """ Test DSP0222 Get Package Status """

    SendPacket = testFixture.physicalTransportHeader / testFixture.get_ncsi_header() / payload

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    # Validate the minimum response packet fields
    RawRecvPacket = raw(RecvPacket)

    RespIANA = int.from_bytes(RawRecvPacket[35:38], "big")
    assert (RespIANA == payload.IANA), "ERROR: IANA parameter mismatch"

    ReturnCode = int.from_bytes(RawRecvPacket[31:32], "big")
    assert (ReturnCode == 0)

    ReasonCode = int.from_bytes(RawRecvPacket[33:34], "big")
    assert (ReasonCode == 0)

    return RecvPacket


def test_pldm_command(testFixture, lowerLayer, pldmRequest):
    """ Test DSP0222 PLDM Request """

    SendPacket = testFixture.physicalTransportHeader / testFixture.get_ncsi_header()
    SendPacket = SendPacket / NcsiPldm_Request() / PLDM_HEADER() / pldmRequest

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[NcsiPldm_Response].ResponseCode == 0)
    assert (RecvPacket[NcsiPldm_Response].ReasonCode == 0)
    return RecvPacket
