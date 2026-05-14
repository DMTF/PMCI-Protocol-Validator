# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.mdimport pytest

import pytest
import json

from pmci_protocol_validator.ptti.lib.lib_dsp0280 import ptti_query_system_inventory_ex, ptti_check_tsw
from pmci_protocol_validator.ptti.classes.dsp0280 import QuerySystemInventory_Response


def test_get_system_inventory(setup, context):

    _error_code, _recv_msg, _send_msg = ptti_query_system_inventory_ex(context, context.test_client_id)

    assert (_error_code == 0), f"Comm Error {_error_code}"
    assert (_recv_msg is not None)
    assert (ptti_check_tsw(_recv_msg) is True)
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
