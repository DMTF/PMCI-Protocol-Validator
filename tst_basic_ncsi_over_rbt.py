# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0222 basic test cases.
##############################################################################

import argparse

from scapy.interfaces import get_working_ifaces
from testframework.fixtures_rbt import c_RbtFixture
from testframework.utilities import common_send_receive
from tests.tst_ncsi import *


def test_get_partition_configuration(testFixture, lowerLayer):
    """ Test NC-SI v1.2.0 Get Partition Configuration command (0x2B) """

    from ncsi.dmtf_1_2_0 import GetPartitionConfiguration_Request, GetPartitionConfiguration_Response

    # Build the full request packet
    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / GetPartitionConfiguration_Request()

    # Run transaction
    RecvPacket = common_send_receive(testFixture.commObject, SendPacket)

    # Verify response fields
    assert (RecvPacket is not None), "Error: No response received"
    assert (RecvPacket[GetPartitionConfiguration_Response].ResponseCode == 0)
    assert (RecvPacket[GetPartitionConfiguration_Response].ReasonCode == 0)

    return RecvPacket


def run_test_cases(testFixture):
    """ Test cases """

    # Execute tests
    lowerLayerHeaders = testFixture.physicalTransportHeader

    # Package commands first...
    SavedChannelID = testFixture.ChannelID
    testFixture.ChannelID = 0x1F

    try: test_select_package(testFixture, lowerLayerHeaders)        # Package
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_asic_temperature(testFixture, lowerLayerHeaders)  # Package
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_ambient_temperature(testFixture, lowerLayerHeaders)  # Package
    except Exception as Ex: testFixture.logMessage(Ex)

    # Now try Channel commands...
    testFixture.ChannelID = SavedChannelID

    try: test_clear_initial_state(testFixture, lowerLayerHeaders)   # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_dell_oem_get_status(testFixture, lowerLayerHeaders)   # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_transceiver_temperature(testFixture, lowerLayerHeaders)  # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_channel_configuration(testFixture, lowerLayerHeaders)  # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_module_management_data(testFixture, lowerLayerHeaders)  # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_enable_channel(testFixture, lowerLayerHeaders)    # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_version_id(testFixture, lowerLayerHeaders)    # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_capabilities(testFixture, lowerLayerHeaders)  # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_parameters(testFixture, lowerLayerHeaders)    # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_link_status(testFixture, lowerLayerHeaders)   # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_get_partition_configuration(testFixture, lowerLayerHeaders)   # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_disable_channel(testFixture, lowerLayerHeaders)   # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    try: test_reset_channel(testFixture, lowerLayerHeaders)     # Channel
    except Exception as Ex: testFixture.logMessage(Ex)

    testFixture.ChannelID = 0x1F
    try:
        test_deselect_package(testFixture, lowerLayerHeaders)  # Package
    except Exception as Ex:
        testFixture.logMessage(Ex)
        pass

    testFixture.ChannelID = SavedChannelID
    return


def get_iface_index():
    """ Select a communication interface """

    # Process command line
    Parser = argparse.ArgumentParser(description="Test basic NC-SI commands")

    Parser.add_argument("-m", "--mac", type=str, required=True, help="Interface MAC address (hex format xx:xx:xx:xx:xx:xx)")
    Parser.add_argument("-p", "--pkg", type=int, default=0, help="NC-SI Package ID for tests")
    Parser.add_argument("-c", "--channel", type=int, default=0, help="NC-SI Channel ID for tests")

    Args = Parser.parse_args()

    PackageID = int(Args.pkg)
    ChannelID = int(Args.channel)

    try:
        ifaces = get_working_ifaces()
        IfaceInfo = next(iface for iface in ifaces if iface.mac == Args.mac.strip())
        Index = IfaceInfo.index
    except:
        Index = -1

    return (Index, PackageID, ChannelID)


if __name__ == "__main__":
    """ Application main() """

    # Select a communication interface
    (Index, PackageID, ChannelID) = get_iface_index()

    if Index < 0:
        print("ERROR: invalid interface selection\n")
        exit(1)

    # Initialize the RBT communications interface
    try:
        testFixture = c_RbtFixture(Index)
    except:
        print("ERROR: failed to initialize fixture\n")
        exit(2)

    # Run tests
    testFixture.PackageID = PackageID
    testFixture.ChannelID = ChannelID

    run_test_cases(testFixture)

    # Cleanup and exit
    print("")
    testFixture.commObject.Close()
    exit(0)
