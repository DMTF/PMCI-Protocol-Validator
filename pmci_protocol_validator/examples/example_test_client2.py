# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Example PTTI test session demonstrating the use of library helper functions.
##############################################################################

import json

from pmci_protocol_validator.framework.fixture_ptti import PTTI_fixture
from pmci_protocol_validator.ptti.classes.dsp0280 import *
from pmci_protocol_validator.ptti.lib.lib_dsp0280 import *


# Network parameters for Test Service connection
CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155


def main():
    """ Test script """

    fixture = None
    _client_id = 0

    try:
        # Set up test environment
        fixture = PTTI_fixture(CONNECTION_ADDRESS, CONNECTION_PORT)
        assert (fixture.tcp_address == CONNECTION_ADDRESS), "TPC address mismatch"
        assert (fixture.tcp_port == CONNECTION_PORT), "TPC port mismatch"

        # 1. Connect
        _security_parameter = b'\x31\x32\x33\x34\x35\x36'

        _rc, _client_id = ptti_connect(fixture, _security_parameter)
        assert _rc == True, "ERROR: Connect failed."

        # 2. Ping the Test Service (Query Status)
        _rc = ptti_query_status_ping(fixture, _client_id)
        assert _rc == True, "ERROR: Query Status Ping failed."

        # 3. Query Capabilities
        _rc, _caps_list = ptti_query_capabilities(fixture, _client_id)
        assert _rc == True, "ERROR: Query Capabilities failed."

        # 4. Configure Test Service
        _test_cfg = [
            TestServiceCapabilityEntry(CapabilityID=1, CapabilityValue=15),
            TestServiceCapabilityEntry(CapabilityID=2, CapabilityValue=1000)
        ]

        _rc = ptti_configure_test_service(fixture, _client_id, _test_cfg)
        assert _rc == True, "ERROR: Configure Test Service failed."

        # 5. Read back settings using Query Capabilities
        _rc, _caps_list = ptti_query_capabilities(fixture, _client_id)
        assert _rc == True, "ERROR: Query Capabilities failed."

        # 6. Query System Inventory
        _rc, _system_inventory = ptti_query_system_inventory(fixture, _client_id)
        assert _rc == True, "ERROR: Get System Inventory failed."
        _system_inventory = json.loads(_system_inventory)

        # 7. Query Partial System Inventory
        _device_id = 0

        _system_inventory_partial = ptti_query_partial_system_inventory_full(fixture, _client_id)

        if _system_inventory_partial != "":
            _system_inventory_partial = json.loads(_system_inventory_partial)

            try:
                _device_id = _system_inventory_partial["Devices"][0]["GeneralDeviceIdentifier"]
            except:
                pass

        # 8. Compare inventory JSON results from QuerySystemInventory and QueryPartialSystemInventory
        if _system_inventory != _system_inventory_partial:
            fixture.log_msg("ERROR: Inventory content mismatch")

        # 9. Configure DUT
        _rc, _dut_connect_id, _ =  ptti_configure_device_under_test(fixture, _client_id, _device_id, [])
        assert _rc == True, "ERROR: Configure Device Under Test failed."

        # 10. Register to Protocol
        _protocol_type = 1          # PLDM Protocol
        _type_list = [2, 4, 5, 6]   # Allowed PLDM Types

        _rc = ptti_register_to_protocol(fixture, _client_id, _dut_connect_id, _protocol_type, _type_list)
        assert _rc == True, "ERROR: Register to Protocol failed."

        # 11. Register Async Message Recipient
        _protocol_type = 1          # PLDM Protocol
        _type_list = [2, 4, 5, 6]   # Allowed PLDM Types

        _rc = ptti_register_async_message_recipient(fixture, _client_id, _dut_connect_id, _protocol_type, _type_list)
        assert _rc == True, "ERROR: Register to Async Message Recipient failed."

        # 12. Query Status (again)
        _rc, _device_list = ptti_query_status_device_list(fixture, _client_id)
        assert _rc == True, "ERROR: Query Status Device List failed."

        print("SUCCESS: All tests completed successfully")

    except Exception as exceptionInfo:
        print(f"FAILURE: {str(exceptionInfo)}")

    # Clean up and exit gracefully
    if fixture is not None:
        _rc = ptti_disconnect(fixture, _client_id)
        if _rc == False:
            "ERROR: DISCONNECT failed."

        fixture.commObject.close()

    return


""" Example Test Client (TC) entry point """
if __name__ == '__main__':
    main()
