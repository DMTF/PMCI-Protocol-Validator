# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

import json
import pytest

from pmci_protocol_validator.tests.conftest import SetupMode
from pmci_protocol_validator.ptti.lib.lib_dsp0280 import *

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

    for _capability in _recv_msg[QueryCapabilities_Response].TestServiceCapabilities:
        assert (_capability.CapabilityID > 0)

    return


def test_ptti_query_status_ping(setup, context):

    _query_type = 0
    _error_code, _recv_msg, _send_msg = ptti_query_status_ex(context, context.test_client_id, _query_type)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg, context.test_client_id) is True)
    assert (_recv_msg.haslayer(QueryStatus_Response) is True)
    assert (_recv_msg[QueryStatus_Response].CommandCode == QueryStatus_Response.CommandValue)
    assert (_recv_msg[QueryStatus_Response].ResponseCode == 0)
    assert (_recv_msg[QueryStatus_Response].QueryType == _query_type)
    assert (_recv_msg[QueryStatus_Response].QueryResponseDataLength == 0)

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
