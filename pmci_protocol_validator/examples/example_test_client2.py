# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Example of a basic PTTI session.
##############################################################################

from pmci_protocol_validator.framework.fixture_ptti import PTTI_fixture
from pmci_protocol_validator.ptti.classes.dsp0280 import *
from pmci_protocol_validator.tests.tst_ptti_commands import *
from pmci_protocol_validator.pldm.classes.dsp0240_base import PLDM_HEADER
from pmci_protocol_validator.pldm.classes.dsp0240 import GetTID_Request

# Network parameters for Test Service connection
CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155


def main():
    """ Test script main() """

    try:
        fixture = PTTI_fixture(CONNECTION_ADDRESS, CONNECTION_PORT)

        assert (fixture.tcp_address == CONNECTION_ADDRESS), "TPC address mismatch"
        assert (fixture.tcp_port == CONNECTION_PORT), "TPC port mismatch"

    except Exception as exceptionInfo:
        print(f"ERROR: c_PTTI_fixture(): TS connect error: {str(exceptionInfo)}")
        return 99

    try:
        TSW = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=0)

        # 1. Connect
        testID = 1
        securityParameter = b'\x31\x32\x33\x34\x35\x36'
        Response = test_connect(fixture, TSW, securityParameter)

        fixture.test_client_id = Response[Connect_Response].TestClientID
        TSW.TestClientID = fixture.test_client_id

        # 2. Ping the Test Service (Query Status)
        testID = 2
        Response = test_query_status(fixture, TSW, 0)   # Ping test service

        # 3. Query Capabilities
        testID = 3
        Response = test_query_capabilities(fixture, TSW)

        # 4. Configure Test Service
        testID = 4
        TestConfiguration = [
            TestServiceCapabilityEntry(CapabilityID=1, CapabilityValue=15),
            TestServiceCapabilityEntry(CapabilityID=2, CapabilityValue=1000)
        ]

        Response = test_configure_test_service(fixture, TSW, TestConfiguration)

        # 5. Read back settings using Query Capabilities
        testID = 5
        Response = test_query_status(fixture, TSW, 1)

        # 6. Query System Inventory
        testID = 6
        Response = test_query_system_inventory(fixture, TSW)

        # 7. Configure DUT
        testID = 7
        Response = test_configure_device_under_test(fixture, TSW)
        DUTConnectionID = Response[ConfigureDeviceUnderTest_Response].DUTConnectionID

        # 8. Register to Protocol
        testID = 8

        RegisterProtocol = 1                # PLDM Protocol
        RegisterTypeList = [2, 4, 5, 6]     # Allowed PLDM Types

        test_register_to_protocol(fixture, TSW, DUTConnectionID, RegisterProtocol, RegisterTypeList)

        # 9. Register Async Message Recipient
        testID = 9

        RegisterProtocol = 1                # PLDM Protocol
        RegisterTypeList = [2, 4, 5, 6]     # Allowed PLDM Types

        test_register_async_message_recipient(fixture, TSW, DUTConnectionID, RegisterProtocol, RegisterTypeList)

        # 10. Query Status (again)
        testID = 10
        Response = test_query_status(fixture, TSW, 1)

        # 11. Send a Test Message with a PLDM Get TID request
        testID = 11

        maxWaitTime = 0
        testMessage = PLDM_HEADER(Request=1, InstanceID=10) / GetTID_Request()

        test_test_message(fixture, TSW, DUTConnectionID, maxWaitTime, testMessage)

        # 12. Disconnect
        testID = 12

        Response = test_disconnect(fixture, TSW)

    except Exception as exceptionInfo:
        fixture.log_msg(f"ERROR: test #{testID}: {str(exceptionInfo)}")
        return testID

    return 0


""" Example Test Client (TC) entry point """
if __name__ == '__main__':
    exit(main())
