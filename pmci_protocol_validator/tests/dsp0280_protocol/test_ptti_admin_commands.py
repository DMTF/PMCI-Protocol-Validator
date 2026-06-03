# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Test cases for DSP0280 protocol

File : test_ptti_admin_commands.py

Brief : Test cases for DSP0280 protocol
"""

import json
import pytest

from pmci_protocol_validator.tests.conftest import SetupMode
from pmci_protocol_validator.ptti.lib.lib_dsp0280 import *


def _is_admin_message_supported(supported_admin_messages: bytes, command_code: int) -> bool:
    return (supported_admin_messages[command_code // 8] & (1 << (command_code % 8))) != 0


@pytest.mark.parametrize("setup", [SetupMode.COMM_CONNECTION], indirect=True) # Connect must start with only the transport connection established.
def test_ptti_connect(setup, context):

    _error_code, _recv_msg, _send_msg = ptti_connect_ex(context, context.security_parameter)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg) is True)
    assert (_recv_msg.haslayer(Connect_Response) is True)
    assert (_recv_msg[Connect_Response].CommandCode == Connect_Response.CommandValue)
    assert (_recv_msg[Connect_Response].ResponseCode == 0)
    assert (_recv_msg[Connect_Response].TestServiceVersion == VERSION_COMPLIANCE)
    assert (_recv_msg[Connect_Response].TestClientID != 0)

    context.set_test_client_id(_recv_msg[Connect_Response].TestClientID)
    return


def test_ptti_disconnect(setup, context):

    _client_id = context.test_client_id
    assert (_client_id != 0)

    _error_code, _recv_msg, _send_msg = ptti_disconnect_ex(context, _client_id)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg, _client_id) is True)
    assert (_recv_msg.haslayer(Disconnect_Response) is True)
    assert (_recv_msg[Disconnect_Response].CommandCode == Disconnect_Response.CommandValue)
    assert (_recv_msg[Disconnect_Response].ResponseCode == 0)

    context.clear_test_client_id()
    return


def test_ptti_query_admin_messages(setup, context):

    _error_code, _recv_msg, _send_msg = ptti_query_admin_messages_ex(context, context.test_client_id)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg, context.test_client_id) is True)
    assert (_recv_msg.haslayer(QueryAdminMessages_Response) is True)
    assert (_recv_msg[QueryAdminMessages_Response].CommandCode == QueryAdminMessages_Response.CommandValue)
    assert (_recv_msg[QueryAdminMessages_Response].ResponseCode == 0)

    _supported_admin_messages = _recv_msg[QueryAdminMessages_Response].SupportedAdminMessages
    assert (isinstance(_supported_admin_messages, bytes))
    assert (len(_supported_admin_messages) == 32)

    _mandatory_command_codes = [
        0x00,   # Connect
        0x01,   # Disconnect
        0x02,   # Query Admin Messages
        0x10,   # Query Capabilities
        0x11,   # Query Status
        0x20,   # Configure Test Service
        0x21,   # Configure Device Under Test
        0x23    # Register Async Message Recipient
    ]

    for _command_code in _mandatory_command_codes:
        assert (_is_admin_message_supported(_supported_admin_messages, _command_code) is True)

    # The spec requires support for at least one system inventory query command:
    # 0x12 = Query System Inventory, 0x13 = Query Partial System Inventory.
    assert (
        _is_admin_message_supported(_supported_admin_messages, 0x12) is True or
        _is_admin_message_supported(_supported_admin_messages, 0x13) is True
    )

    return


def test_ptti_query_capabilities(setup, context):

    _error_code, _recv_msg, _send_msg = ptti_query_capabilities_ex(context, context.test_client_id)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg, context.test_client_id) is True)
    assert (_recv_msg.haslayer(QueryCapabilities_Response) is True)
    assert (_recv_msg[QueryCapabilities_Response].CommandCode == QueryCapabilities_Response.CommandValue)
    assert (_recv_msg[QueryCapabilities_Response].ResponseCode == 0)
    assert (_recv_msg[QueryCapabilities_Response].Reserved == 0)
    assert (_recv_msg[QueryCapabilities_Response].NumberOfCapabilitiesFields ==
            len(_recv_msg[QueryCapabilities_Response].TestServiceCapabilities))

    ### TODO parameterze????

    _expected_capabilities = [1, 2, 3]

    for _capability in _recv_msg[QueryCapabilities_Response].TestServiceCapabilities:
        assert (_capability.CapabilityID in _expected_capabilities)

    return


def test_ptti_query_status_ping(setup, context):

    _error_code, _recv_msg, _send_msg = ptti_query_status_ex(context, context.test_client_id, 0)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg, context.test_client_id) is True)
    assert (_recv_msg.haslayer(QueryStatus_Response) is True)
    assert (_recv_msg[QueryStatus_Response].CommandCode == QueryStatus_Response.CommandValue)
    assert (_recv_msg[QueryStatus_Response].ResponseCode == 0)
    assert (_recv_msg[QueryStatus_Response].QueryType == 0)
    assert (_recv_msg[QueryStatus_Response].QueryResponseDataLength == 0)

    return


def test_query_status_device_list(setup, context):

    _error_code, _recv_msg, _send_msg = ptti_query_status_ex(context, context.test_client_id, 1)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg) is True)
    assert (_recv_msg.haslayer(QueryStatus_Response) is True)
    assert (_recv_msg[QueryStatus_Response].CommandCode == QueryStatus_Response.CommandValue)
    assert (_recv_msg[QueryStatus_Response].ResponseCode == 0)
    assert (_recv_msg[QueryStatus_Response].QueryType == 1)

    ### TODO Process QueryStatusDeviceData[]

###    assert (_recv_msg[QueryStatus_Response].QueryResponseDataLength == 0)
    return


def test_get_system_inventory(setup, context):

    _error_code, _recv_msg, _send_msg = ptti_query_system_inventory_ex(context, context.test_client_id)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg, context.test_client_id) is True)
    assert (_recv_msg.haslayer(QuerySystemInventory_Response) is True)
    assert (_recv_msg[QuerySystemInventory_Response].CommandCode == QuerySystemInventory_Response.CommandValue)
    assert (_recv_msg[QuerySystemInventory_Response].ResponseCode == 0)

    _system_inventory_json = json.loads(_recv_msg[QuerySystemInventory_Response].SystemInventory)

    assert (_system_inventory_json["SchemaDefinition"] == "SystemInventory.v1_0_0")
    assert (_system_inventory_json["ControlPlane"]["Manufacturer"])
    assert (_system_inventory_json["ControlPlane"]["Model"])
    assert (_system_inventory_json["ControlPlane"]["FirmwareVersions"])
    assert (_system_inventory_json["ControlPlane"]["Interfaces"])
    assert (_system_inventory_json["Devices"])

    return


def test_ptti_query_partial_system_inventory(setup, context):

    # Test guard only; the spec does not define a maximum fragment count.
    _max_partial_system_inventory_fragments = 256
    _fragment_handle = 0
    _system_inventory = b""

    for _ in range(_max_partial_system_inventory_fragments):
        _error_code, _recv_msg, _send_msg = ptti_query_partial_system_inventory_ex(
            context,
            context.test_client_id,
            _fragment_handle
        )

        assert (_error_code == 0), f"Comm Error {_error_code}"
        assert (_recv_msg is not None)
        assert (ptti_check_tsw(_recv_msg, context.test_client_id) is True)
        assert (_recv_msg.haslayer(QueryPartialSystemInventory_Response) is True)
        assert (_recv_msg[QueryPartialSystemInventory_Response].CommandCode ==
                QueryPartialSystemInventory_Response.CommandValue)
        assert (_recv_msg[QueryPartialSystemInventory_Response].ResponseCode == 0)

        _fragment_data = _recv_msg[QueryPartialSystemInventory_Response].SystemInventory
        assert (_fragment_data is not None)
        assert (isinstance(_fragment_data, bytes))

        assert (_recv_msg[QueryPartialSystemInventory_Response].FragmentLength == len(_fragment_data))

        _system_inventory += _fragment_data
        _fragment_handle = _recv_msg[QueryPartialSystemInventory_Response].NextFragmentHandle

        if _fragment_handle == 0:
            break
    else:
        pytest.fail("Query Partial System Inventory did not complete within the fragment limit.")

    _system_inventory_json = json.loads(_system_inventory.decode("utf-8"))

    assert (_system_inventory_json["SchemaDefinition"] == "SystemInventory.v1_0_0")
    assert (_system_inventory_json["ControlPlane"]["Manufacturer"])
    assert (_system_inventory_json["ControlPlane"]["Model"])
    assert (_system_inventory_json["ControlPlane"]["Interfaces"])
    assert (_system_inventory_json["Devices"])

    return


@pytest.mark.parametrize("expected_result, capabilities", [
    (0, []),
    (0, [(1, 90)])
])

def test_configure_test_service(setup, context, expected_result, capabilities):

    ### TODO Build proper capabilities list

    _error_code, _recv_msg, _send_msg = ptti_configure_test_service_ex(context, context.test_client_id, capabilities)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg) is True)
    assert (_recv_msg.haslayer(ConfigureTestService_Response) is True)
    assert (_recv_msg[ConfigureTestService_Response].CommandCode == ConfigureTestService_Response.CommandValue)
    assert (_recv_msg[ConfigureTestService_Response].ResponseCode == expected_result)

    if _recv_msg[ConfigureTestService_Response].ResponseCode == 0:

        ### TODO Read back value
        pass

    return


@pytest.mark.parametrize("expected_result, dut_id, protocol_type, types_list",[
    (0, 10, 0, [])
])

def test_register_to_protocol(setup, context, expected_result, dut_id, protocol_type, types_list):
    """
    NOTE: DSP0280 has deprecated this command. This test case is present for completeness.
    """

    _error_code, _recv_msg, _send_msg = ptti_register_to_protocol_ex(context, context.test_client_id, dut_id, protocol_type, types_list)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg) is True)
    assert (_recv_msg.haslayer(RegisterToProtocol_Response) is True)
    assert (_recv_msg[RegisterToProtocol_Response].CommandCode == RegisterToProtocol_Response.CommandValue)
    assert (_recv_msg[RegisterToProtocol_Response].ResponseCode == expected_result)

    assert (_recv_msg[RegisterToProtocol_Response].DUTConnectionID == dut_id)
    return


@pytest.mark.parametrize("expected_result, dut_id, protocol_type, types_list",[
    (0, 10, 2, [])
])

def test_register_async_message_recipient(setup, context, expected_result, dut_id, protocol_type, types_list):
    """
    NOTE: DSP0280 has deprecated the TypeCount and TypesList parameters. They are ingored by the Test Service.
    """

    _error_code, _recv_msg, _send_msg = ptti_register_async_message_recipient_ex(context, context.test_client_id, dut_id, protocol_type, types_list)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg) is True)
    assert (_recv_msg.haslayer(RegisterAsyncMessageRecipient_Response) is True)
    assert (_recv_msg[RegisterAsyncMessageRecipient_Response].CommandCode == RegisterAsyncMessageRecipient_Response.CommandValue)
    assert (_recv_msg[RegisterAsyncMessageRecipient_Response].ResponseCode == expected_result)

    assert (_recv_msg[RegisterAsyncMessageRecipient_Response].DUTConnectionID == dut_id)
    return


@pytest.mark.parametrize("expected_result, iana, payload", [
    (0x00, 0x1AB4, b''),
    (0x0D, 0x0001, b'\x00\x00')
    ])

def test_send_vendor_admin_msg(setup, context, expected_result, iana, payload):

    _error_code, _recv_msg, _send_msg = ptti_send_vendor_admin_msg_ex(context, context.test_client_id, iana, Packet(payload))

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg) is True)
    assert (_recv_msg.haslayer(VendorDefinedAdmin_Response) is True)

    assert (_recv_msg[VendorDefinedAdmin_Response].IANA == iana)
    assert (_recv_msg[VendorDefinedAdmin_Response].ResponseCode == expected_result)
    return
