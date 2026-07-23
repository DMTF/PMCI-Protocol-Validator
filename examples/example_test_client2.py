# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Example PTTI test session demonstrating the use of library helper functions.

File : example_test_client2.py

Brief : Example PTTI test session demonstrating the use of library helper functions.
"""

import json
import argparse
import pathlib

from pmci_protocol_validator.framework.ptti_context import PTTI_Context
from pmci_protocol_validator.ptti.dsp0280 import *
from pmci_protocol_validator.ptti.lib_dsp0280 import *
from pmci_protocol_validator.ptti.dsp0280_comm import PTTIMedium


def main(tcp_addr: str, tcp_port: int, tls_cert_fname: str = "", tls_hostname: str = "") -> None:
    """ Test script """

    comm_obj = None
    fixture = None

    try:
        # Set up test environment
        _tls_flags = PTTIMedium.TLS_ENABLE if tls_cert_fname != "" else PTTIMedium.TLS_DISABLE

        if tls_hostname == "":
            _tls_flags |= PTTIMedium.TLS_NO_HOSTNAME

        comm_obj = PTTIMedium(tcp_addr, tcp_port, _tls_flags, tls_cert_fname, tls_hostname)
        fixture = PTTI_Context(comm_obj, True)

        # 1. Connect
        _security_parameter = b'\x31\x32\x33\x34\x35\x36'

        _rc, fixture.test_client_id = ptti_connect(fixture, _security_parameter)
        assert _rc == True, "ERROR: Connect failed."

        # 1.5. Query Admin Message Support
        _rc, _bit_mask = ptti_query_admin_messages(fixture, fixture.test_client_id)
        assert _rc == True, "ERROR: Query Admin Message support failed."

        # 2. Ping the Test Service (Query Status)
        _rc = ptti_query_status_ping(fixture, fixture.test_client_id)
        assert _rc == True, "ERROR: Query Status Ping failed."

        # 3. Query Capabilities
        _rc, _caps_list = ptti_query_capabilities(fixture, fixture.test_client_id)
        assert _rc == True, "ERROR: Query Capabilities failed."

        # 4. Configure Test Service
        _test_cfg = [(1, 15), (2, 1000)]

        _rc = ptti_configure_test_service(fixture, fixture.test_client_id, _test_cfg)
        assert _rc == True, "ERROR: Configure Test Service failed."

        # 5. Read back settings using Query Capabilities
        _rc, _caps_list = ptti_query_capabilities(fixture, fixture.test_client_id)
        assert _rc == True, "ERROR: Query Capabilities failed."

        # 6. Query System Inventory
        _rc, _system_inventory = ptti_query_system_inventory(fixture, fixture.test_client_id)
        assert _rc == True, "ERROR: Get System Inventory failed."
        _system_inventory = json.loads(_system_inventory)

        # 7. Query Partial System Inventory
        _device_id = 0

        _system_inventory_partial = ptti_query_partial_system_inventory_full(fixture, fixture.test_client_id)

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
        _rc, _dut_connect_id, _ =  ptti_configure_device_under_test(fixture, fixture.test_client_id, _device_id, [])
        assert _rc == True, "ERROR: Configure Device Under Test failed."

        # 10. Register to Protocol
        _protocol_type = 1          # PLDM Protocol
        _type_list = [2, 4, 5, 6]   # Allowed PLDM Types

        _rc = ptti_register_to_protocol(fixture, fixture.test_client_id, _dut_connect_id, _protocol_type, _type_list)
        assert _rc == True, "ERROR: Register to Protocol failed."

        # 11. Register Async Message Recipient
        _protocol_type = 1          # PLDM Protocol
        _type_list = [2, 4, 5, 6]   # Allowed PLDM Types

        _rc = ptti_register_async_message_recipient(fixture, fixture.test_client_id, _dut_connect_id, _protocol_type, _type_list)
        assert _rc == True, "ERROR: Register to Async Message Recipient failed."

        # 12. Query Status (again)
        _rc, _device_list = ptti_query_status_device_list(fixture, fixture.test_client_id)
        assert _rc == True, "ERROR: Query Status Device List failed."

        print("SUCCESS: All tests completed successfully")

    except Exception as exceptionInfo:
        print(f"FAILURE: {str(exceptionInfo)}")

    finally:
        if comm_obj is not None:
            if fixture is not None:
                if ptti_disconnect(fixture, fixture.test_client_id) is False:
                    fixture.log_msg("ERROR: DISCONNECT failed.")

            comm_obj.close()

    return

def file_exists(filename: str) -> bool:
    """ Verify that specified file exists. """

    path = pathlib.Path(filename)
    return path.is_file()


""" Example Test Client (TC) entry point """
if __name__ == '__main__':

    # Get command line parameters
    parser = argparse.ArgumentParser()

    parser.add_argument("--tcp-addr", default="localhost", help="Connection host TCP address")
    parser.add_argument("--tcp-port", type=int, default=49155, help="Connection TCP port number")
    parser.add_argument("--tls-enable", nargs="+", help="Path to the TLS certificate file and certificate host name")
    parser.add_argument("--tls-no-host-verify", action="store_true", help="Disable TLS hostname verification")

    args = parser.parse_args()

    # Verify command line parameters
    if args.tls_enable is not None:
        if file_exists(args.tls_enable[0]) is False:
            parser.error(f"ERROR: TLS certificate file does not exist: {args.tls_enable[0]}")

        if args.tls_no_host_verify is False and len(args.tls_enable) < 2:
            parser.error("ERROR: TLS hostname required.")

    # Display the operational parameters
    print("\n\nDMTF DSP0280 Test Client Example\nCopyright (c) 2023-2026 DMTF. All rights reserved.\n")

    print(f"Connection host address: {args.tcp_addr}")
    print(f"Connection TCP port number: {args.tcp_port}")

    if args.tls_enable is not None:
        print(f"TLS enabled: TRUE")
        print(f"\tTLS certificate file: {args.tls_enable[0]}")
        print(f"\tTLS certificate host name: {"None" if len(args.tls_enable) < 2 else args.tls_enable[1]}")
        print(f"\tTLS no host verify: {args.tls_no_host_verify}\n")

    else:
        print(f"TLS enabled: FALSE\n")
        args.tls_enable = ["", ""]

    # Run application
    main(args.tcp_addr, args.tcp_port, args.tls_enable[0], args.tls_enable[1] if args.tls_no_host_verify is False else "")
