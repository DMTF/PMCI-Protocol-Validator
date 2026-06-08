# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Test cases for DSP0280 Test Service Wrapper (TSW)

File : test_ptti_tsw.py

Brief : Test cases for possible DSP0280 Test Service Wrapper (TSW) errors.
"""

import pytest
from scapy.packet import Raw

from tests.conftest import SetupMode
from pmci_protocol_validator.ptti.dsp0280 import TestServiceWrapper, QueryStatus_Request, QueryStatus_Response
from pmci_protocol_validator.framework.utilities import common_send_receive


@pytest.mark.parametrize("version", [0x00, 0x10, 0x11, 0x20])
def test_ptti_tsw_version(setup, context, version):

    _request = TestServiceWrapper(ProtocolType=0xFF, Version=version, Direction=0, TestClientID=context.test_client_id) / QueryStatus_Request(QueryType=0)

    _error_code, _response = common_send_receive(context, _request)

    assert (_error_code == 0)
    assert (_response is not None)
    assert (_response.haslayer(QueryStatus_Response) is True)

    if version == 0x11:
        assert (_response[QueryStatus_Response].ResponseCode == 0)
    else:
        assert (_response[QueryStatus_Response].ResponseCode == 8)

    return


@pytest.mark.parametrize("reserved_0", [0, 1])
@pytest.mark.parametrize("reserved_1", [0, 1])
@pytest.mark.parametrize("reserved_2", [0, 1])
def test_ptti_tsw_set_rsvd(setup, context, reserved_0, reserved_1, reserved_2):

    _request = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=context.test_client_id) / QueryStatus_Request(QueryType=0)

    _request[TestServiceWrapper].Reserved_0 = reserved_0
    _request[TestServiceWrapper].Reserved_1 = reserved_1
    _request[TestServiceWrapper].Reserved_2 = reserved_2

    _error_code, _response = common_send_receive(context, _request)

    assert (_error_code == 0)
    assert (_response is not None)
    assert (_response.haslayer(QueryStatus_Response) is True)

    if reserved_0 == 0 and reserved_1 == 0 and reserved_2 == 0:
        assert (_response[QueryStatus_Response].ResponseCode == 0)
    else:
        assert (_response[QueryStatus_Response].ResponseCode == 0x0b)

    return


@pytest.mark.parametrize ("expected_result, direction", [(0, 0), (0x011, 1), (0x011, 2), (0x011, 3)])
def test_ptti_tsw_direction(setup, context, expected_result, direction):

    _request = TestServiceWrapper(ProtocolType=0xFF, TestClientID=context.test_client_id) / QueryStatus_Request(QueryType=0)
    _request[TestServiceWrapper].Direction = direction

    _error_code, _response = common_send_receive(context, _request)

    assert (_error_code == 0)
    assert (_response is not None)
    assert (_response.haslayer(QueryStatus_Response) is True)
    assert (_response[QueryStatus_Response].ResponseCode == expected_result)

    return


@pytest.mark.parametrize ("expected_result, length", [(0, 0), (1, -3), (0, 10)])
def test_ptti_tsw_length(setup, context, expected_result, length):

    _request = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=context.test_client_id) / QueryStatus_Request(QueryType=0)

    if length > 0:     # Append extra data
        _request = _request / Raw(bytes(length))
    elif length < 0:   # Truncate packet
        _request = Raw(bytes(_request)[:length])

    _error_code, _response = common_send_receive(context, _request)

    assert (_error_code == expected_result)

    if expected_result == 0:
        assert (_response is not None)
        assert (_response.haslayer(QueryStatus_Response) is True)
        assert (_response[QueryStatus_Response].ResponseCode == 0)

    return
