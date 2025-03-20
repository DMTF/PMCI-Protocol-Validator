# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Example of a basic PTTI session.
##############################################################################

from testframework.fixture_ptti import c_PTTI_fixture
from testframework.utilities import common_send_receive

from ptti.dmtf import *
from pldm.dmtf import PLDM_HEADER
from pldm.type0 import GetTID_Request

# Network parameters for Test Service connection
CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155


def main():
    """ Test script main() """

    # Create the test fixture object
    try:
        fixture = c_PTTI_fixture(CONNECTION_ADDRESS, CONNECTION_PORT)

        assert (fixture.tcpAddress == CONNECTION_ADDRESS), "TPC address mismatch"
        assert (fixture.tcpPort == CONNECTION_PORT), "TPC port mismatch"

    except Exception as exceptionInfo:
        print("ERROR: c_PTTI_fixture(): TS connect error: " + str(exceptionInfo))
        return 99

    # 1. Connect
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=0)
    SendPacket = SendPacket / Connect_Request()

    SendPacket[Connect_Request].SecurityParameter = RawVal(b'\x31\x32\x33\x34\x35\x36')
    SendPacket[Connect_Request].SecurityParameterLength = len(SendPacket[Connect_Request].SecurityParameter)

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)
        fixture.testClientID = RecvPacket[Connect_Response].TestClientID

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: Connect(): " + str(exceptionInfo))
        return 1

    # 2. Ping the Test Service (Query Status)
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / QueryStatus_Request(QueryType=0)

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: QueryStatus_Request(): " + str(exceptionInfo))
        return 2

    # 3. Query Capabilities
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / QueryCapabilities_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: QueryCapabilities_Request(): " + str(exceptionInfo))
        return 3

    # 4. Configure Test Service
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / ConfigureTestService_Request()

    TestConfiguration = [
        TestServiceCapabilityEntry(CapabilityID=1, CapabilityValue=15),
        TestServiceCapabilityEntry(CapabilityID=2, CapabilityValue=1000)
    ]

    SendPacket[ConfigureTestService_Request].NumberOfCapabilitiesFields = len(TestConfiguration)
    SendPacket[ConfigureTestService_Request].TestServiceCapabilities = TestConfiguration

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: ConfigureTestService_Request(): " + str(exceptionInfo))
        return 4

    # 5. Read back settings
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / QueryCapabilities_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: QueryCapabilities_Request(): " + str(exceptionInfo))
        return 5

    # 6. Query System Inventory
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / QuerySystemInventory_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: QuerySystemInventory_Request(): " + str(exceptionInfo))
        return 6

    # 7. Configure DUT
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / ConfigureDeviceUnderTest_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: ConfigureDeviceUnderTest_Request(): " + str(exceptionInfo))
        return 7

    # Save the DUT Connection ID for future tests
    DUTConnectionID = RecvPacket[ConfigureDeviceUnderTest_Response].DUTConnectionID

    # 8. Register to Protocol
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / RegisterToProtocol_Request()

    SendPacket[RegisterToProtocol_Request].ProtocolType = 1  # PLDM Protocol
    SendPacket[RegisterToProtocol_Request].DUTConnectionID = DUTConnectionID

    RegisterList = [2, 4, 5, 6]  # Allowed PLDM Types

    SendPacket[RegisterToProtocol_Request].TypeCount = len(RegisterList)
    SendPacket[RegisterToProtocol_Request].TypeList = RegisterList

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: RegisterToProtocol_Request(): " + str(exceptionInfo))
        return 8

    # 9. Register Async Message Recipient
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / RegisterAsyncMessageRecipient_Request()

    SendPacket[RegisterAsyncMessageRecipient_Request].DUTConnectionID = DUTConnectionID
    SendPacket[RegisterAsyncMessageRecipient_Request].ProtocolType = 1  # PLDM Protocol AENs

    SendPacket[RegisterAsyncMessageRecipient_Request].TypeCount = len(RegisterList)
    SendPacket[RegisterAsyncMessageRecipient_Request].TypeList = RegisterList

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: RegisterAsyncMessageRecipient_Request(): " + str(exceptionInfo))
        return 9

    # 10. Query Status
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / QueryStatus_Request(QueryType=1)

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: QueryStatus_Request(): " + str(exceptionInfo))
        return 10

    # 11. Send a Test Message with a PLDM Get TID request
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / TestMessage_Request(DUTConnectionID=DUTConnectionID)
    SendPacket = SendPacket / PLDM_HEADER(Request=1, InstanceID=10)
    SendPacket = SendPacket / GetTID_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: TestMessage_Request(): " + str(exceptionInfo))
        return 11

    # 12. Disconnect
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=fixture.testClientID)
    SendPacket = SendPacket / Disconnect_Request()

    try:
        RecvPacket = common_send_receive(fixture.commObject, SendPacket, fixture.showPacket)
        fixture.VerifyCommonFields(RecvPacket, SendPacket)

    except Exception as exceptionInfo:
        fixture.logMessage("ERROR: Disconnect(): " + str(exceptionInfo))
        return 10

    return 0


""" Example Test Client (TC) entry point """
if __name__ == '__main__':

    exit(main())
