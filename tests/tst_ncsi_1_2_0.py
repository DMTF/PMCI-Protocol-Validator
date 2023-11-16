# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0222 v1.2.0 runtime test cases.
##############################################################################

from testframework.utilities import common_send_receive
from ncsi.dmtf import NCSI_HEADER
from ncsi.dmtf_1_2_0 import *


def verify_ncsi_header(response, request):
    """Verify the common response NC-SI header fields"""

    assert (response.MC_ID == request.MC_ID)
    assert (response.HeaderRevision == 0x01)
    assert (response.IID == request.IID)
    assert (response.PackageID == request.PackageID)
    assert (response.ChannelID == request.ChannelID)
    return


def test_GetNcCapabilitiesSettings(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get NC Capabilities Settings Request and Response"""

    # Assemble the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetNcCapabilitiesSettings_Request()

    # Send the request and get the response
    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    # Validate the response header
    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    # Validate the response fields
    assert (RecvPacket[GetNcCapabilitiesSettings_Response].ResponseCode == 0)
    assert (RecvPacket[GetNcCapabilitiesSettings_Response].ReasonCode == 0)
    assert (RecvPacket[GetNcCapabilitiesSettings_Response].Reserved_0 == 0)
    assert (RecvPacket[GetNcCapabilitiesSettings_Response].Reserved_1 == 0)

    # Return the full response packet for additional processing
    return RecvPacket


def test_GetPfAssignment(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get PF Assignment Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPfAssignment_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetPfAssignment_Response].ResponseCode == 0)
    assert (RecvPacket[GetPfAssignment_Response].ReasonCode == 0)

    return RecvPacket


def test_GetPartitionConfiguration(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get Partition Configuration Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPartitionConfiguration_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetPartitionConfiguration_Response].ResponseCode == 0)
    assert (RecvPacket[GetPartitionConfiguration_Response].ReasonCode == 0)
    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_0 == 0)
    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_1 == 0)
    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_2 == 0)
    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_3 == 0)
    assert (RecvPacket[GetPartitionConfiguration_Response].CfgData.Reserved_4 == 0)

    return RecvPacket


def test_GetBootConfig(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get Boot Configuration Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetBootConfig_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetBootConfig_Response].ResponseCode == 0)
    assert (RecvPacket[GetBootConfig_Response].ReasonCode == 0)
    assert (RecvPacket[GetBootConfig_Response].Reserved == 0)
    assert (RecvPacket[GetBootConfig_Response].ProtocolType in [0, 1, 2, 3, 4, 255])

    return RecvPacket


def test_GetPartitionStatistics(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get Partition Statistics Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPartitionStatistics_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetPartitionStatistics_Response].ResponseCode == 0)
    assert (RecvPacket[GetPartitionStatistics_Response].ReasonCode == 0)
    assert (RecvPacket[GetPartitionStatistics_Response].Reserved == 0)

    return RecvPacket


def test_GetPassThroughModeControl(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Ge tPass Through Mode Control Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPassThroughModeControl_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetPassThroughModeControl_Response].ResponseCode == 0)
    assert (RecvPacket[GetPassThroughModeControl_Response].ReasonCode == 0)
    assert (RecvPacket[GetPassThroughModeControl_Response].Data.Reserved_0 == 0)
    assert (RecvPacket[GetPassThroughModeControl_Response].Data.Reserved_1 == 0)
    assert (RecvPacket[GetPassThroughModeControl_Response].Data.Reserved_2 == 0)

    return RecvPacket


def test_GetVfAllocation(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get VF Allocation Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetVfAllocation_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetVfAllocation_Response].ResponseCode == 0)
    assert (RecvPacket[GetVfAllocation_Response].ReasonCode == 0)

    return RecvPacket


def test_GetInventoryInformation(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Get Inventory Information Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetInventoryInformation_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[GetInventoryInformation_Response].ResponseCode == 0)
    assert (RecvPacket[GetInventoryInformation_Response].ReasonCode == 0)
    assert (RecvPacket[GetInventoryInformation_Response].Data.AttributeNameType <= 5)

    return RecvPacket


def test_ThermalShutdownControl(testFixture, lowerLayer):
    """Test DSP0222 v1.2.0 Thermal Shutdown Control Request and Response"""

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / ThermalShutdownControl_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    verify_ncsi_header(RecvPacket[NCSI_HEADER], SendPacket[NCSI_HEADER])

    assert (RecvPacket[ThermalShutdownControl_Response].ResponseCode == 0)
    assert (RecvPacket[ThermalShutdownControl_Response].ReasonCode == 0)
    assert (RecvPacket[ThermalShutdownControl_Response].Reserved_0 == 0)
    assert (RecvPacket[ThermalShutdownControl_Response].Reserved_1 == 0)

    return RecvPacket
