# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0222 runtime test cases.
##############################################################################

from testframework.utilities import common_send_receive
from ncsi.dmtf import *
from ncsi.dmtf_1_2_0 import *


def verify_ncsi_header(response, request):
    """Verify the common response NC-SI header fields"""

    assert (response.MC_ID == request.MC_ID)
    assert (response.HeaderRevision == 0x01)
    assert (response.IID == request.IID)
    assert (response.PackageID == request.PackageID)
    assert (response.ChannelID == request.ChannelID)
    return


def test_clear_initial_state(testFixture, lowerLayer):
    """Test DSP0222 Clear Initial State Request and Response"""

    # Assemble the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / ClearInitialState_Request()

    # Send the request and get the response
    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    # Validate the response header
    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    # Validate the response fields
    assert (RecvPacket[ClearInitialState_Response].ResponseCode == 0)
    assert (RecvPacket[ClearInitialState_Response].ReasonCode == 0)

    # Return the response packet for further processing
    return RecvPacket


def test_select_package(testFixture, lowerLayer):
    """Test DSP0222 Select Package Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SelectPackage_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[SelectPackage_Response].ResponseCode == 0)
    assert (RecvPacket[SelectPackage_Response].ReasonCode == 0)
    return RecvPacket


def test_deselect_package(testFixture, lowerLayer):
    """Test DSP0222 Deselect Package Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DeselectPackage_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[DeselectPackage_Response].ResponseCode == 0)
    assert (RecvPacket[DeselectPackage_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_channel(testFixture, lowerLayer):
    """Test DSP0222 Enable Channel Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableChannel_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[EnableChannel_Response].ResponseCode == 0)
    assert (RecvPacket[EnableChannel_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_channel(testFixture, lowerLayer):
    """Test DSP0222 Disable Channel Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableChannel_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[DisableChannel_Response].ResponseCode == 0)
    assert (RecvPacket[DisableChannel_Response].ReasonCode == 0)
    return RecvPacket


def test_reset_channel(testFixture, lowerLayer):
    """Test DSP0222 Reset Channel Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / ResetChannel_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[ResetChannel_Response].ResponseCode == 0)
    assert (RecvPacket[ResetChannel_Response].ReasonCode == 0)
    return RecvPacket


def test_get_version_id(testFixture, lowerLayer):
    """Test DSP0222 Get Version ID Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetVersionID_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetVersionID_Response].ResponseCode == 0)
    assert (RecvPacket[GetVersionID_Response].ReasonCode == 0)
    return RecvPacket


def test_get_capabilities(testFixture, lowerLayer):
    """Test DSP0222 Get Capabilities Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetCapabilities_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetCapabilities_Response].ResponseCode == 0)
    assert (RecvPacket[GetCapabilities_Response].ReasonCode == 0)
    return RecvPacket


def test_get_parameters(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get Parameter Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetParameters_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetParameters_Response].ResponseCode == 0)
    assert (RecvPacket[GetParameters_Response].ReasonCode == 0)
    assert (RecvPacket[GetParameters_Response].Data.Reserved_1 == 0)
    assert (RecvPacket[GetParameters_Response].Data.Reserved_2 == 0)
    assert (RecvPacket[GetParameters_Response].Data.Reserved_3 == 0)
    assert (RecvPacket[GetParameters_Response].Data.Reserved_4 == 0)
    assert (RecvPacket[GetParameters_Response].Data.Reserved_5 == 0)

    return RecvPacket


def test_get_asic_temperature(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get ASIC Temperature"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetAsicTemperature_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetAsicTemperature_Response].ResponseCode == 0)
    assert (RecvPacket[GetAsicTemperature_Response].ReasonCode == 0)
    return RecvPacket


def test_get_ambient_temperature(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 GetAmbientTemperature"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetAmbientTemperature_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetAmbientTemperature_Response].ResponseCode == 0)
    assert (RecvPacket[GetAmbientTemperature_Response].ReasonCode == 0)
    assert (RecvPacket[GetAmbientTemperature_Response].NumberOfSensors <= 3)
    return RecvPacket


def test_get_transceiver_temperature(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get Transceiver Temperature"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetTransceiverTemperature_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetTransceiverTemperature_Response].ResponseCode == 0)
    assert (RecvPacket[GetTransceiverTemperature_Response].ReasonCode == 0)
    assert (RecvPacket[GetTransceiverTemperature_Response].Reserved == 0)
    return RecvPacket


def test_get_channel_configuration(testFixture, lowerLayer):
    """Test DSP0222 Get Channel Configuration"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetChannelConfiguration_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetChannelConfiguration_Response].ResponseCode == 0)
    assert (RecvPacket[GetChannelConfiguration_Response].ReasonCode == 0)
    assert (RecvPacket[GetChannelConfiguration_Response].FabricType >= 1)
    assert (RecvPacket[GetChannelConfiguration_Response].FabricType <= 3)
    assert (RecvPacket[GetChannelConfiguration_Response].Reserved_1 == 0)

    return RecvPacket


def test_get_module_management_data(testFixture, lowerLayer):
    """Test DSP0222 Get Module Management Data"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetModuleManagementData_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetModuleManagementData_Response].ResponseCode == 0)
    assert (RecvPacket[GetModuleManagementData_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_channel_network_tx(testFixture, lowerLayer):
    """Test DSP0222 Enable Channel Network TX"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableChannelNetworkTx_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[EnableChannelNetworkTx_Response].ResponseCode == 0)
    assert (RecvPacket[EnableChannelNetworkTx_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_channel_network_tx(testFixture, lowerLayer):
    """Test DSP0222 Disable Channel Network TX"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableChannelNetworkTx_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[DisableChannelNetworkTx_Response].ResponseCode == 0)
    assert (RecvPacket[DisableChannelNetworkTx_Response].ReasonCode == 0)
    return RecvPacket


def test_aen_enable(testFixture, lowerLayer):
    """Test DSP0222 AEN Enable"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / AenEnable_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[AenEnable_Response].ResponseCode == 0)
    assert (RecvPacket[AenEnable_Response].ReasonCode == 0)
    return RecvPacket


def test_set_link(testFixture, lowerLayer):
    """Test DSP0222 Set Link"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetLink_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[SetLink_Response].ResponseCode == 0)
    assert (RecvPacket[SetLink_Response].ReasonCode == 0)
    return RecvPacket


def test_get_link_status(testFixture, lowerLayer):
    """Test DSP0222 Get Link"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetLinkStatus_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetLinkStatus_Response].ResponseCode == 0)
    assert (RecvPacket[GetLinkStatus_Response].ReasonCode == 0)
    return RecvPacket


def test_set_vlan_filter(testFixture, lowerLayer):
    """Test DSP0222 Set VLAN Filter"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetVlanFilter_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[SetVlanFilter_Response].ResponseCode == 0)
    assert (RecvPacket[SetVlanFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_vlan(testFixture, lowerLayer):
    """Test DSP0222 Enable VLAN"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableVlan_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[EnableVlan_Response].ResponseCode == 0)
    assert (RecvPacket[EnableVlan_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_vlan(testFixture, lowerLayer):
    """Test DSP0222 Disable VLAN"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableVlan_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[DisableVlan_Response].ResponseCode == 0)
    assert (RecvPacket[DisableVlan_Response].ReasonCode == 0)
    return RecvPacket


def test_get_supported_media(testFixture, lowerLayer):
    """Test DSP0222 Get Supported Media"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetSupportedMedia_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetSupportedMedia_Response].ResponseCode == 0)
    assert (RecvPacket[GetSupportedMedia_Response].ReasonCode == 0)
    return RecvPacket


def test_get_mc_mac_address(testFixture, lowerLayer):
    """Test DSP0222 Get MC MAC Address"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetMcMacAddress_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetMcMacAddress_Response].ResponseCode == 0)
    assert (RecvPacket[GetMcMacAddress_Response].ReasonCode == 0)
    return RecvPacket


def test_set_mac_address(testFixture, lowerLayer):
    """Test DSP0222 Set MAC Address"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetMACAddress_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[SetMACAddress_Response].ResponseCode == 0)
    assert (RecvPacket[SetMACAddress_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_broadcast_filter(testFixture, lowerLayer):
    """Test DSP0222 Enable Broadcast Filter"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableBroadcastFilter_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[EnableBroadcastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[EnableBroadcastFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_get_controller_packet_statistics(testFixture, lowerLayer):
    """Test DSP0222 Get Controller Packet Statistics"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetControllerPacketStatistics_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetControllerPacketStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetControllerPacketStatistics_Response].ReasonCode == 0)
    return RecvPacket


def test_get_ncsi_statistics(testFixture, lowerLayer):
    """Test DSP0222 Get NC-SI Statistics"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetNCSIStatistics_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetNCSIStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetNCSIStatistics_Response].ReasonCode == 0)
    return RecvPacket


def test_send_ncpldm_reply(testFixture, lowerLayer):
    """Test DSP0222 Send NCPLDM Reply"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SendNCPLDMReply_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[SendNCPLDMReply_Response].ResponseCode == 0)
    assert (RecvPacket[SendNCPLDMReply_Response].ReasonCode == 0)
    return RecvPacket


def test_get_package_uuid(testFixture, lowerLayer):
    """Test DSP0222 Get Package UUID"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPackageUUID_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetPackageUUID_Response].ResponseCode == 0)
    assert (RecvPacket[GetPackageUUID_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_broadcast_filter(testFixture, lowerLayer):
    """Test DSP0222 Disable Braodcast Filter"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableBroadcastFilter_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[DisableBroadcastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[DisableBroadcastFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_global_multicast_filter(testFixture, lowerLayer):
    """Test DSP0222 Enable Global Multicast Filter"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableGlobalMulticastFilter_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[EnableGlobalMulticastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[EnableGlobalMulticastFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_global_multicast_filter(testFixture, lowerLayer):
    """Test DSP0222 Disable Global Multicast Filter"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableGlobalMulticastFilter_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[DisableGlobalMulticastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[DisableGlobalMulticastFilter_Response].ReasonCode == 0)
    return RecvPacket


def test_set_ncsi_flow_control(testFixture, lowerLayer):
    """Test DSP0222 Set NC-SI Flow Control"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetNCSIFlowControl_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[SetNCSIFlowControl_Response].ResponseCode == 0)
    assert (RecvPacket[SetNCSIFlowControl_Response].ReasonCode == 0)
    return RecvPacket


def test_get_ncsi_passthrough_statistics(testFixture, lowerLayer):
    """Test DSP0222 Get NC-SI Passthrough Statistics"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetNCSIPassthroughStatistics_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetNCSIPassthroughStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetNCSIPassthroughStatistics_Response].ReasonCode == 0)
    return RecvPacket


def test_get_package_status(testFixture, lowerLayer):
    """Test DSP0222 Get Package Status"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPackageStatus_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetPackageStatus_Response].ResponseCode == 0)
    assert (RecvPacket[GetPackageStatus_Response].ReasonCode == 0)
    return RecvPacket
