# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0222 v1.2.0 runtime test cases.
##############################################################################

from testframework.utilities import common_send_receive
from ncsi.dmtf_1_2_0 import *


def test_GetNcCapabilitiesSettings(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get NC Capabilities Settings Request & Response """

    # Assemble the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetNcCapabilitiesSettings_Request()

    # Send the request and get the response
    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    # Validate the response header
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    # Validate the response fields
    assert (RecvPacket[GetNcCapabilitiesSettings_Response].ResponseCode == 0)
    assert (RecvPacket[GetNcCapabilitiesSettings_Response].ReasonCode == 0)

    assert (RecvPacket[GetNcCapabilitiesSettings_Response].Reserved_0 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetNcCapabilitiesSettings_Response].Reserved_1 == 0), "Reserved field NOT zero"

    # Return the full response packet for additional processing
    return RecvPacket


def test_set_nc_configuration(testFixture, lowerLayer, EnablePortsCount=0, EnablePCIeEpCount=0, EnablePFsCount=0):
    """ Test DSP0222 v1.2.0 Set NC Configuration """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetNcConfiguration_Request()

    SendPacket[SetNcConfiguration_Request].EnablePorts = EnablePortsCount
    SendPacket[SetNcConfiguration_Request].EnablePCIeEndpoints = EnablePCIeEpCount
    SendPacket[SetNcConfiguration_Request].EnablePFs = EnablePFsCount

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[SetNcConfiguration_Response].ResponseCode == 0)
    assert (RecvPacket[SetNcConfiguration_Response].ReasonCode == 0)
    return RecvPacket


def test_GetPfAssignment(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get PF Assignment Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPfAssignment_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetPfAssignment_Response].ResponseCode == 0)
    assert (RecvPacket[GetPfAssignment_Response].ReasonCode == 0)

    return RecvPacket


def test_GetPartitionConfiguration(testFixture, lowerLayer, partitionID):
    """ Test DSP0222 v1.2.0 Get Partition Configuration Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header(PartitionID=partitionID)
    SendPacket = SendPacket / GetPartitionConfiguration_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetPartitionConfiguration_Response].ResponseCode == 0)
    assert (RecvPacket[GetPartitionConfiguration_Response].ReasonCode == 0)

    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_0 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_1 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_2 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_3 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_4 == 0), "Reserved field NOT zero"

    return RecvPacket


def test_GetBootConfig(testFixture, lowerLayer, PartitionID=0, ProtocolType=0):
    """ Test DSP0222 v1.2.0 Get Boot Configuration Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetBootConfig_Request()

    SendPacket[GetBootConfig_Request].PartitionID = PartitionID
    SendPacket[GetBootConfig_Request].ProtocolType = ProtocolType

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetBootConfig_Response].ResponseCode == 0)
    assert (RecvPacket[GetBootConfig_Response].ReasonCode == 0)

    assert (RecvPacket[GetBootConfig_Response].Reserved == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetBootConfig_Response].ProtocolType in [0, 1, 2, 3, 4, 255]), "ERROR: Invalid ProtocolType"

    return RecvPacket


def test_GetPartitionStatistics(testFixture, lowerLayer, PartitionID=0, StatsType=0):
    """ Test DSP0222 v1.2.0 Get Partition Statistics Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPartitionStatistics_Request()

    SendPacket[GetPartitionStatistics_Request].PartitionID = PartitionID
    SendPacket[GetPartitionStatistics_Request].StatsType = StatsType

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetPartitionStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetPartitionStatistics_Response].ReasonCode == 0)
    assert (RecvPacket[GetPartitionStatistics_Response].Reserved == 0), "Reserved field NOT zero"

    return RecvPacket


def test_SetPassThroughModeControl(testFixture, lowerLayer, net2bmc=0, host2bmc=0, ecpu2bmc=0):
    """ Test DSP0222 v1.2.0 Set Pass-through Mode Control Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SetPassThroughModeControl_Request()

    SendPacket[SetPassThroughModeControl_Request].NetworkBMCPassthroughTraffic = net2bmc
    SendPacket[SetPassThroughModeControl_Request].HostBmcPassthroughTraffic = host2bmc
    SendPacket[SetPassThroughModeControl_Request].EmbeddedCpuBmcPassthroughTraffic = ecpu2bmc

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[SetPassThroughModeControl_Response].ResponseCode == 0)
    assert (RecvPacket[SetPassThroughModeControl_Response].ReasonCode == 0)

    return RecvPacket


def test_GetPassThroughModeControl(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get Pass-through Mode Control Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPassThroughModeControl_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetPassThroughModeControl_Response].ResponseCode == 0)
    assert (RecvPacket[GetPassThroughModeControl_Response].ReasonCode == 0)

    assert (RecvPacket[GetPassThroughModeControl_Response].Data.Reserved_0 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetPassThroughModeControl_Response].Data.Reserved_1 == 0), "Reserved field NOT zero"
    assert (RecvPacket[GetPassThroughModeControl_Response].Data.Reserved_2 == 0), "Reserved field NOT zero"

    return RecvPacket


def test_GetVfAllocation(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get VF Allocation Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetVfAllocation_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetVfAllocation_Response].ResponseCode == 0)
    assert (RecvPacket[GetVfAllocation_Response].ReasonCode == 0)

    return RecvPacket


def test_GetInventoryInformation(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get Inventory Information Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetInventoryInformation_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetInventoryInformation_Response].ResponseCode == 0)
    assert (RecvPacket[GetInventoryInformation_Response].ReasonCode == 0)
    assert (RecvPacket[GetInventoryInformation_Response].Data.AttributeNameType <= 5), "ERROR: Invalid AttributeNameType"

    return RecvPacket


def test_ThermalShutdownControl(testFixture, lowerLayer, mode=0):
    """ Test DSP0222 v1.2.0 Thermal Shutdown Control Request and Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / ThermalShutdownControl_Request(Operation=mode)

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[ThermalShutdownControl_Response].ResponseCode == 0)
    assert (RecvPacket[ThermalShutdownControl_Response].ReasonCode == 0)

    assert (RecvPacket[ThermalShutdownControl_Response].Reserved_0 == 0), "Reserved field NOT zero"
    assert (RecvPacket[ThermalShutdownControl_Response].Reserved_1 == 0), "Reserved field NOT zero"

    return RecvPacket


def test_get_asic_temperature(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get ASIC Temperature """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetAsicTemperature_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetAsicTemperature_Response].ResponseCode == 0)
    assert (RecvPacket[GetAsicTemperature_Response].ReasonCode == 0)
    return RecvPacket


def test_get_ambient_temperature(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 GetAmbientTemperature """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetAmbientTemperature_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetAmbientTemperature_Response].ResponseCode == 0)
    assert (RecvPacket[GetAmbientTemperature_Response].ReasonCode == 0)
    assert (RecvPacket[GetAmbientTemperature_Response].NumberOfSensors <= 3), "ERROR: Invalid NumberOfSensors"
    return RecvPacket


def test_get_transceiver_temperature(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get Transceiver Temperature """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetTransceiverTemperature_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetTransceiverTemperature_Response].ResponseCode == 0)
    assert (RecvPacket[GetTransceiverTemperature_Response].ReasonCode == 0)
    assert (RecvPacket[GetTransceiverTemperature_Response].Reserved == 0), "Reserved field NOT zero"
    return RecvPacket


def test_get_channel_configuration(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get Channel Configuration """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetChannelConfiguration_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetChannelConfiguration_Response].ResponseCode == 0)
    assert (RecvPacket[GetChannelConfiguration_Response].ReasonCode == 0)

    assert (RecvPacket[GetChannelConfiguration_Response].FabricType >= 1), "ERROR: Invalid FabricType"
    assert (RecvPacket[GetChannelConfiguration_Response].FabricType <= 3), "ERROR: Invalid FabricType"
    assert (RecvPacket[GetChannelConfiguration_Response].Reserved_1 == 0), "Reserved field NOT zero"

    return RecvPacket


def test_get_module_management_data(testFixture, lowerLayer, RequestedBank=0, RequestedPage=0, PageUpperFlag=0):
    """ Test DSP0222 v1.2.0 Get Module Management Data """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetModuleManagementData_Request()

    SendPacket[GetModuleManagementData_Request].RequestedBank = RequestedBank
    SendPacket[GetModuleManagementData_Request].RequestedPage = RequestedPage
    SendPacket[GetModuleManagementData_Request].PageUpperFlag = PageUpperFlag

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetModuleManagementData_Response].ResponseCode == 0)
    assert (RecvPacket[GetModuleManagementData_Response].ReasonCode == 0)
    return RecvPacket


def test_get_supported_media(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get Supported Media """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetSupportedMedia_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetSupportedMedia_Response].ResponseCode == 0)
    assert (RecvPacket[GetSupportedMedia_Response].ReasonCode == 0)
    return RecvPacket


def test_get_mc_mac_address(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Get MC MAC Address """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetMcMacAddress_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[GetMcMacAddress_Response].ResponseCode == 0)
    assert (RecvPacket[GetMcMacAddress_Response].ReasonCode == 0)
    return RecvPacket


def test_send_ncpldm_reply(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Send NCPLDM Reply """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SendNCPLDMReply_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[SendNCPLDMReply_Response].ResponseCode == 0)
    assert (RecvPacket[SendNCPLDMReply_Response].ReasonCode == 0)
    return RecvPacket


def test_settings_commit(testFixture, lowerLayer):
    """ Test DSP0222 v1.2.0 Settings Commit """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / SettingsCommit_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[SettingsCommit_Response].ResponseCode == 0)
    assert (RecvPacket[SettingsCommit_Response].ReasonCode == 0)
    return RecvPacket
