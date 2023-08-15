##############################################################################
#  File Abstract:
#  DSP0222 runtime test cases.
##############################################################################

from ncsi.dmtf import *  # pylint: disable=unused-import, unused-wildcard-import


def verify_ncsi_header(response, request):
    """Verify the common response NC-SI header fields"""

    assert (response.MC_ID == request.MC_ID)
    assert (response.HeaderRevision == 0x01)
    assert (response.IID == request.IID)
    assert (response.PackageID == request.PackageID)
    assert (response.ChannelID == request.ChannelID)
    return


def send_receive(testFixture, SendPacket):
    """Common method to send the Request and receive the Response"""

    # Send request
    RecvPacket = None
    testFixture.showPacket(SendPacket)

    ErrorCode = testFixture.commObject.Write(SendPacket)
    if ErrorCode == testFixture.commObject.ERROR_SUCCESS:

        # Get response
        (ErrorCode, RecvPacket) = testFixture.commObject.Read()

        if ErrorCode == testFixture.commObject.ERROR_SUCCESS:
            testFixture.showPacket(RecvPacket)
            verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    return RecvPacket


def test_clear_initial_state(testFixture, lowerLayer):
    """Test DSP0222 Clear Initial State Request and Response"""

    # Build the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / ClearInitialState_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[ClearInitialState_Response].ResponseCode == 0)
    assert (RecvPacket[ClearInitialState_Response].ReasonCode == 0)
    return


def test_select_package(testFixture, lowerLayer):
    """Test DSP0222 Select Package Request and Response"""

    # Build the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SelectPackage_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[SelectPackage_Response].ResponseCode == 0)
    assert (RecvPacket[SelectPackage_Response].ReasonCode == 0)
    return


def test_deselect_package(testFixture, lowerLayer):
    """Test DSP0222 Deselect Package Request and Response"""

    # Build the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DeselectPackage_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[DeselectPackage_Response].ResponseCode == 0)
    assert (RecvPacket[DeselectPackage_Response].ReasonCode == 0)
    return


def test_enable_channel(testFixture, lowerLayer):
    """Test DSP0222 Enable Channel Request and Response"""

    # Build the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableChannel_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[EnableChannel_Response].ResponseCode == 0)
    assert (RecvPacket[EnableChannel_Response].ReasonCode == 0)
    return


def test_disable_channel(testFixture, lowerLayer):
    """Test DSP0222 Disable Channel Request and Response"""

    # Build the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableChannel_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[DisableChannel_Response].ResponseCode == 0)
    assert (RecvPacket[DisableChannel_Response].ReasonCode == 0)
    return


def test_reset_channel(testFixture, lowerLayer):
    """Test DSP0222 Reset Channel Request and Response"""

    # Build the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / ResetChannel_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[ResetChannel_Response].ResponseCode == 0)
    assert (RecvPacket[ResetChannel_Response].ReasonCode == 0)
    return


def test_get_version_id(testFixture, lowerLayer):
    """Test DSP0222 Get Version ID Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetVersionID_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None)
    assert (RecvPacket[GetVersionID_Response].ResponseCode == 0)
    assert (RecvPacket[GetVersionID_Response].ReasonCode == 0)
    return RecvPacket


def test_get_capabilities(testFixture, lowerLayer):
    """Test DSP0222 Get Capabilities Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetCapabilities_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetCapabilities_Response].ResponseCode == 0)
    assert (RecvPacket[GetCapabilities_Response].ReasonCode == 0)
    return RecvPacket


def test_get_parameters(testFixture, lowerLayer):
    """Test DSP0222 Get Parameter Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetParameters_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetParameters_Response].ResponseCode == 0)
    assert (RecvPacket[GetParameters_Response].ReasonCode == 0)
    return RecvPacket


def test_get_asic_temperature(testFixture, lowerLayer):
    """Test DSP0222 Get ASIC Temperature"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetAsicTemperature_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetAsicTemperature_Response].ResponseCode == 0)
    assert (RecvPacket[GetAsicTemperature_Response].ReasonCode == 0)
    return RecvPacket


def test_get_ambient_temperature(testFixture, lowerLayer):
    """Test DSP0222 GetAmbientTemperature"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetAmbientTemperature_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetAmbientTemperature_Response].ResponseCode == 0)
    assert (RecvPacket[GetAmbientTemperature_Response].ReasonCode == 0)
    return RecvPacket


def test_get_transceiver_temperature(testFixture, lowerLayer):
    """Test DSP0222 Get Transceiver Temperature"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetTransceiverTemperature_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetTransceiverTemperature_Response].ResponseCode == 0)
    assert (RecvPacket[GetTransceiverTemperature_Response].ReasonCode == 0)
    return RecvPacket


def test_get_channel_configuration(testFixture, lowerLayer):
    """Test DSP0222 Get Channel Configuration"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetChannelConfiguration_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetChannelConfiguration_Response].ResponseCode == 0)
    assert (RecvPacket[GetChannelConfiguration_Response].ReasonCode == 0)
    return


def test_get_module_management_data(testFixture, lowerLayer):
    """Test DSP0222 Get Module Management Data"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetModuleManagementData_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetModuleManagementData_Response].ResponseCode == 0)
    assert (RecvPacket[GetModuleManagementData_Response].ReasonCode == 0)
    return RecvPacket


def test_enable_channel_network_tx(testFixture, lowerLayer):
    """Test DSP0222 Enable Channel Network TX"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableChannelNetworkTx_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[EnableChannelNetworkTx_Response].ResponseCode == 0)
    assert (RecvPacket[EnableChannelNetworkTx_Response].ReasonCode == 0)
    return


def test_disable_channel_network_tx(testFixture, lowerLayer):
    """Test DSP0222 Disable Channel Network TX"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableChannelNetworkTx_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[DisableChannelNetworkTx_Response].ResponseCode == 0)
    assert (RecvPacket[DisableChannelNetworkTx_Response].ReasonCode == 0)
    return


def test_aen_enable(testFixture, lowerLayer):
    """Test DSP0222 AEN Enable"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / AenEnable_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[AenEnable_Response].ResponseCode == 0)
    assert (RecvPacket[AenEnable_Response].ReasonCode == 0)
    return


def test_set_link(testFixture, lowerLayer):
    """Test DSP0222 Set Link"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetLink_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[SetLink_Response].ResponseCode == 0)
    assert (RecvPacket[SetLink_Response].ReasonCode == 0)
    return


def test_get_link_status(testFixture, lowerLayer):
    """Test DSP0222 Get Link"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetLinkStatus_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetLinkStatus_Response].ResponseCode == 0)
    assert (RecvPacket[GetLinkStatus_Response].ReasonCode == 0)
    return RecvPacket


def test_set_vlan_filter(testFixture, lowerLayer):
    """Test DSP0222 Set VLAN Filter"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetVlanFilter_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[SetVlanFilter_Response].ResponseCode == 0)
    assert (RecvPacket[SetVlanFilter_Response].ReasonCode == 0)
    return


def test_enable_vlan(testFixture, lowerLayer):
    """Test DSP0222 Enable VLAN"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableVlan_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[EnableVlan_Response].ResponseCode == 0)
    assert (RecvPacket[EnableVlan_Response].ReasonCode == 0)
    return


def test_disable_vlan(testFixture, lowerLayer):
    """Test DSP0222 Disable VLAN"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableVlan_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[DisableVlan_Response].ResponseCode == 0)
    assert (RecvPacket[DisableVlan_Response].ReasonCode == 0)
    return


def test_get_supported_media(testFixture, lowerLayer):
    """Test DSP0222 Get Supported Media"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetSupportedMedia_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetSupportedMedia_Response].ResponseCode == 0)
    assert (RecvPacket[GetSupportedMedia_Response].ReasonCode == 0)
    return RecvPacket


def test_get_mc_mac_address(testFixture, lowerLayer):
    """Test DSP0222 Get MC MAC Address"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetMcMacAddress_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetMcMacAddress_Response].ResponseCode == 0)
    assert (RecvPacket[GetMcMacAddress_Response].ReasonCode == 0)
    return


def test_set_mac_address(testFixture, lowerLayer):
    """Test DSP0222 Set MAC Address"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetMACAddress_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[SetMACAddress_Response].ResponseCode == 0)
    assert (RecvPacket[SetMACAddress_Response].ReasonCode == 0)
    return


def test_enable_broadcast_filter(testFixture, lowerLayer):
    """Test DSP0222 Enable Broadcast Filter"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableBroadcastFilter_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[EnableBroadcastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[EnableBroadcastFilter_Response].ReasonCode == 0)
    return


def test_get_controller_packet_statistics(testFixture, lowerLayer):
    """Test DSP0222 Get Controller Packet Statistics"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetControllerPacketStatistics_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetControllerPacketStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetControllerPacketStatistics_Response].ReasonCode == 0)
    return RecvPacket


def test_get_ncsi_statistics(testFixture, lowerLayer):
    """Test DSP0222 Get NC-SI Statistics"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetNCSIStatistics_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetNCSIStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetNCSIStatistics_Response].ReasonCode == 0)
    return RecvPacket


def test_send_ncpldm_reply(testFixture, lowerLayer):
    """Test DSP0222 Send NCPLDM Reply"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SendNCPLDMReply_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[SendNCPLDMReply_Response].ResponseCode == 0)
    assert (RecvPacket[SendNCPLDMReply_Response].ReasonCode == 0)
    return RecvPacket


def test_get_package_uuid(testFixture, lowerLayer):
    """Test DSP0222 Get Package UUID"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPackageUUID_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetPackageUUID_Response].ResponseCode == 0)
    assert (RecvPacket[GetPackageUUID_Response].ReasonCode == 0)
    return RecvPacket


def test_disable_broadcast_filter(testFixture, lowerLayer):
    """Test DSP0222 Disable Braodcast Filter"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DisableBroadcastFilter_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[DisableBroadcastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[DisableBroadcastFilter_Response].ReasonCode == 0)
    return


def test_enable_global_multicast_filter(testFixture, lowerLayer):
    """Test DSP0222 Enable Global Multicast Filter"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / EnableGlobalMulticastFilter_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[EnableGlobalMulticastFilter_Response].ResponseCode == 0)
    assert (RecvPacket[EnableGlobalMulticastFilter_Response].ReasonCode == 0)
    return


def test_set_ncsi_flow_control(testFixture, lowerLayer):
    """Test DSP0222 Set NC-SI Flow Control"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetNCSIFlowControl_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[SetNCSIFlowControl_Response].ResponseCode == 0)
    assert (RecvPacket[SetNCSIFlowControl_Response].ReasonCode == 0)
    return


def test_get_ncsi_passthrough_statistics(testFixture, lowerLayer):
    """Test DSP0222 Get NC-SI Passthrough Statistics"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetNCSIPassthroughStatistics_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetNCSIPassthroughStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetNCSIPassthroughStatistics_Response].ReasonCode == 0)
    return RecvPacket


def test_get_package_status(testFixture, lowerLayer):
    """Test DSP0222 Get Package Status"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPackageStatus_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetPackageStatus_Response].ResponseCode == 0)
    assert (RecvPacket[GetPackageStatus_Response].ReasonCode == 0)
    return RecvPacket


def test_unsupported_ncsi(testFixture, lowerLayer):
    """Test an Unsupported NC-SI request"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / UnsupportedNcsi_Request()

    # Run transaction
    RecvPacket = send_receive(testFixture, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[UnsupportedNcsi_Response].ResponseCode == 0)
    assert (RecvPacket[UnsupportedNcsi_Response].ReasonCode == 0)
    return
