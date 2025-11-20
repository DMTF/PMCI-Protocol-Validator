# Copyright Notice:
# Copyright 2023-2025 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Example of a basic PTTI session.
##############################################################################

import json

from pmci_protocol_validator.framework.fixture_ptti import PTTI_fixture
from pmci_protocol_validator.framework.utilities  import common_send_receive

from pmci_protocol_validator.ptti.classes.dsp0280 import *
from pmci_protocol_validator.pldm.classes.dsp0240_base import PLDM_HEADER
from pmci_protocol_validator.pldm.classes.dsp0240 import GetTID_Request

# Network parameters for Test Service connection
CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155


def main():
    """ Test script main() """

    # Create the test fixture object
    try:
        fixture = PTTI_fixture(CONNECTION_ADDRESS, CONNECTION_PORT)

        assert (fixture.tcp_address == CONNECTION_ADDRESS), "TPC address mismatch"
        assert (fixture.tcp_port == CONNECTION_PORT), "TPC port mismatch"

    except Exception as exceptionInfo:
        print("ERROR: c_PTTI_fixture(): TS connect error: " + str(exceptionInfo))
        return 99

    # 1. Connect
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=0)
    SendPacket = SendPacket / Connect_Request()

    SendPacket[Connect_Request].SecurityParameter = RawVal(b'\x31\x32\x33\x34\x35\x36')
    SendPacket[Connect_Request].SecurityParameterLength = len(SendPacket[Connect_Request].SecurityParameter)

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)

        if RecvPacket[TestServiceWrapper].Version != VERSION_COMPLIANCE or \
            RecvPacket[TestServiceWrapper].ProtocolType != 0xFF or \
            RecvPacket[TestServiceWrapper].Reserved_0 != 0 or \
            RecvPacket[TestServiceWrapper].Reserved_1 != 0:

            fixture.log_msg("ERROR: Connect(): Invalid field value")
            return 1

        fixture.test_client_id = RecvPacket[Connect_Response].TestClientID

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: Connect(): " + str(exceptionInfo))
        return 1

    # 2. Ping the Test Service (Query Status)
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / QueryStatus_Request(QueryType=0)

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: QueryStatus_Request(): " + str(exceptionInfo))
        return 2

    # 3. Query Capabilities
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / QueryCapabilities_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: QueryCapabilities_Request(): " + str(exceptionInfo))
        return 3

    # 4. Configure Test Service
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / ConfigureTestService_Request()

    TestConfiguration = [
        TestServiceCapabilityEntry(CapabilityID=1, CapabilityValue=15),
        TestServiceCapabilityEntry(CapabilityID=2, CapabilityValue=1000)
    ]

    SendPacket[ConfigureTestService_Request].NumberOfCapabilitiesFields = len(TestConfiguration)
    SendPacket[ConfigureTestService_Request].TestServiceCapabilities = TestConfiguration

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: ConfigureTestService_Request(): " + str(exceptionInfo))
        return 4

    # 5. Read back settings
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / QueryCapabilities_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: QueryCapabilities_Request(): " + str(exceptionInfo))
        return 5

    # 6. Query System Inventory
    SystemInventory = None
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / QuerySystemInventory_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

        if RecvPacket[QuerySystemInventory_Response].ResponseCode == 0:
            SystemInventory = json.loads(RecvPacket[QuerySystemInventory_Response].SystemInventory.decode("utf-8"))

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: QuerySystemInventory_Request(): " + str(exceptionInfo))
        return 6

    # 7. Collect inventory using a series of Query Partial System Inventory commands
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / QueryPartialSystemInventory_Request()

    SystemInventoryPartial = None
    DeviceIdentifier = 0
    inventory_text = b""
    fragment = 0

    try:
        while True:
            SendPacket[QueryPartialSystemInventory_Request].FragmentHandle = fragment

            RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
            fixture.verify_common_fields(RecvPacket, SendPacket)

            if RecvPacket[QueryPartialSystemInventory_Response].ResponseCode != 0:
                break

            inventory_text = inventory_text + RecvPacket[QueryPartialSystemInventory_Response].SystemInventory
            fragment = fragment + RecvPacket[QueryPartialSystemInventory_Response].FragmentLength

            if RecvPacket[QueryPartialSystemInventory_Response].NextFragmentHandle == 0:
                SystemInventoryPartial = json.loads(inventory_text.decode("utf-8"))

                try:
                    DeviceIdentifier = SystemInventory["Devices"][0]["GeneralDeviceIdentifier"]
                except:
                    pass
                break

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: QueryPartialSystemInventory_Request(): " + str(exceptionInfo))
        return 7

    # 8. Compare inventory JSON results from QuerySystemInventory and QueryPartialSystemInventory
    if SystemInventory != SystemInventoryPartial:
        fixture.log_msg("ERROR: Inventory content mismatch")

    # 9. Configure DUT
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / ConfigureDeviceUnderTest_Request(TargetIdentifier=DeviceIdentifier)

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: ConfigureDeviceUnderTest_Request(): " + str(exceptionInfo))
        return 9

    # Save the DUT Connection ID for future tests
    DUTConnectionID = RecvPacket[ConfigureDeviceUnderTest_Response].DUTConnectionID

    # 10. Register to Protocol
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / RegisterToProtocol_Request()

    SendPacket[RegisterToProtocol_Request].ProtocolType = 1  # PLDM Protocol
    SendPacket[RegisterToProtocol_Request].DUTConnectionID = DUTConnectionID

    RegisterList = [2, 4, 5, 6]  # Allowed PLDM Types

    SendPacket[RegisterToProtocol_Request].TypeCount = len(RegisterList)
    SendPacket[RegisterToProtocol_Request].TypeList = RegisterList

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: RegisterToProtocol_Request(): " + str(exceptionInfo))
        return 10

    # 11. Register Async Message Recipient
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / RegisterAsyncMessageRecipient_Request()

    SendPacket[RegisterAsyncMessageRecipient_Request].DUTConnectionID = DUTConnectionID
    SendPacket[RegisterAsyncMessageRecipient_Request].ProtocolType = 1  # PLDM Protocol AENs

    SendPacket[RegisterAsyncMessageRecipient_Request].TypeCount = len(RegisterList)
    SendPacket[RegisterAsyncMessageRecipient_Request].TypeList = RegisterList

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: RegisterAsyncMessageRecipient_Request(): " + str(exceptionInfo))
        return 11

    # 12. Query Status
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / QueryStatus_Request(QueryType=1)

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: QueryStatus_Request(): " + str(exceptionInfo))
        return 12

    # 13. Disconnect
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.test_client_id)
    SendPacket = SendPacket / Disconnect_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.show_pkt)
        fixture.verify_common_fields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.log_msg("ERROR: Disconnect(): " + str(exceptionInfo))
        return 13

    fixture.commObject.close()
    return 0


""" Example Test Client (TC) entry point """
if __name__ == '__main__':

    exit(main())
