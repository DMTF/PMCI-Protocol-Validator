# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Helper functions for DSP0280 functions.
##############################################################################

from pmci_protocol_validator.framework.context import FwkContext
from pmci_protocol_validator.framework.utilities import common_send_receive
from pmci_protocol_validator.ptti.classes.dsp0280 import *


def ptti_check_tsw(wrapper: Packet, client_id: int =None) -> bool:
    """ Generic library function for Test Wrapper verification """

    if wrapper.haslayer(TestServiceWrapper) is True:

        if wrapper.Version == VERSION_COMPLIANCE and \
            wrapper.Reserved_0 == 0 and \
            wrapper.Reserved_1 == 0 and \
            wrapper.Reserved_3 == 0:

            _client_id_ok = True if client_id is None else wrapper.TestClientID == client_id
            return _client_id_ok

    return False


def ptti_connect_ex(fwk_ctx: FwkContext, sec_prm: bytes) -> tuple[int, Packet|None, Packet]:
    """ Advanced function for sending/receiving a CONNECT message. The caller is responsible for checking the response. """

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=0) / Connect_Request()

    _send_msg[Connect_Request].SecurityParameter = RawVal(sec_prm)
    _send_msg[Connect_Request].SecurityParameterLength = len(sec_prm)

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_connect(fwk_ctx: FwkContext, sec_prm: bytes) -> tuple[bool, int]:
    """ Simplified method for sending/receiving a CONNECT message including checking response parameters """

    _error_code, _recv_msg, _ = ptti_connect_ex(fwk_ctx, sec_prm)

    if _error_code == 0 and _recv_msg is not None:

        if ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(Connect_Response) is True and \
            _recv_msg[Connect_Response].CommandCode == Connect_Response.CommandValue and \
            _recv_msg[Connect_Response].ResponseCode == 0 and \
            _recv_msg[Connect_Response].TestServiceVersion == VERSION_COMPLIANCE:

            return True, _recv_msg[Connect_Response].TestClientID

    return False, 0


def ptti_disconnect_ex(fwk_ctx: FwkContext, connect_id: int) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id) / Disconnect_Request()

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_disconnect(fwk_ctx: FwkContext, connect_id: int) -> bool:

    _error_code, _recv_msg, _ = ptti_disconnect_ex(fwk_ctx, connect_id)

    return _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg, connect_id) is True and \
            _recv_msg.haslayer(Disconnect_Response) is True and \
            _recv_msg[Disconnect_Response].CommandCode == Disconnect_Response.CommandValue and \
            _recv_msg[Disconnect_Response].ResponseCode == 0


def ptti_query_admin_messages_ex(fwk_ctx: FwkContext, connect_id: int) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id) / QueryAdminMessages_Request()

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_query_admin_messages(fwk_ctx: FwkContext, connect_id: int) -> tuple[bool, bytes]:

    _error_code, _recv_msg, _ = ptti_query_admin_messages_ex(fwk_ctx, connect_id)

    if _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg, connect_id) is True and \
            _recv_msg.haslayer(QueryAdminMessages_Response) is True and \
            _recv_msg[QueryAdminMessages_Response].CommandCode == QueryAdminMessages_Response.CommandValue and \
            _recv_msg[QueryAdminMessages_Response].ResponseCode == 0:

        return True, _recv_msg[QueryAdminMessages_Response].SupportedAdminMessages

    return False, b"\x00" * 32


def ptti_query_status_ex(fwk_ctx: FwkContext, connect_id: int, queryType: int) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id)
    _send_msg = _send_msg / QueryStatus_Request(QueryType=queryType)

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_query_status_ping(fwk_ctx: FwkContext, connect_id: int) -> bool:

    _error_code, _recv_msg, _ = ptti_query_status_ex(fwk_ctx, connect_id, 0)

    return _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg, connect_id) is True and \
            _recv_msg.haslayer(QueryStatus_Response) is True and \
            _recv_msg[QueryStatus_Response].CommandCode == QueryStatus_Response.CommandValue and \
            _recv_msg[QueryStatus_Response].ResponseCode == 0


def ptti_query_status_device_list(fwk_ctx: FwkContext, connect_id: int) -> tuple[bool, list]:

    _error_code, _recv_msg, _ = ptti_query_status_ex(fwk_ctx, connect_id, 1)

    if _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(QueryStatus_Response) is True and \
            _recv_msg[QueryStatus_Response].CommandCode == QueryStatus_Response.CommandValue and \
            _recv_msg[QueryStatus_Response].ResponseCode == 0:

        return True, _recv_msg[QueryStatus_Response].QueryStatusDeviceData

    return False, []


def ptti_query_capabilities_ex(fwk_ctx: FwkContext, connect_id: int) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id) / QueryCapabilities_Request()

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_query_capabilities(fwk_ctx: FwkContext, connect_id: int) -> tuple[bool, list]:

    _error_code, _recv_msg, _ = ptti_query_capabilities_ex(fwk_ctx, connect_id)

    if _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(QueryCapabilities_Response) is True and \
            _recv_msg[QueryCapabilities_Response].CommandCode == QueryCapabilities_Response.CommandValue and \
            _recv_msg[QueryCapabilities_Response].ResponseCode == 0:

        return True, _recv_msg[QueryCapabilities_Response].TestServiceCapabilities

    return False, []


def ptti_configure_test_service_ex(fwk_ctx: FwkContext, connect_id: int, cfg_prm_list: list) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id)
    _send_msg = _send_msg / ConfigureTestService_Request(TestServiceCapabilities=cfg_prm_list)

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_configure_test_service(fwk_ctx: FwkContext, connect_id: int, cfg_prm_list: list) -> bool:

    _error_code, _recv_msg, _ = ptti_configure_test_service_ex(fwk_ctx, connect_id, cfg_prm_list)

    return _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(ConfigureTestService_Response) is True and \
            _recv_msg[ConfigureTestService_Response].CommandCode == ConfigureTestService_Response.CommandValue and \
            _recv_msg[ConfigureTestService_Response].ResponseCode == 0


def ptti_query_system_inventory_ex(fwk_ctx: FwkContext, connect_id: int) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id) / QuerySystemInventory_Request()

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_query_system_inventory(fwk_ctx: FwkContext, connect_id: int) -> tuple[bool, str]:

    _error_code, _recv_msg, _ = ptti_query_system_inventory_ex(fwk_ctx, connect_id)

    if _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(QuerySystemInventory_Response) is True and \
            _recv_msg[QuerySystemInventory_Response].CommandCode == QuerySystemInventory_Response.CommandValue and \
            _recv_msg[QuerySystemInventory_Response].ResponseCode == 0:

        return True, _recv_msg[QuerySystemInventory_Response].SystemInventory

    return False, ""


def ptti_query_partial_system_inventory_ex(fwk_ctx: FwkContext, connect_id: int, frag_handle: int) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id)
    _send_msg = _send_msg / QueryPartialSystemInventory_Request(FragmentHandle=frag_handle)

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_query_partial_system_inventory(fwk_ctx: FwkContext, connect_id: int, frag_handle: int) -> tuple[bool, str, int]:

    _error_code, _recv_msg, _ = ptti_query_partial_system_inventory_ex(fwk_ctx, connect_id, frag_handle)

    if _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(QueryPartialSystemInventory_Response) is True and \
            _recv_msg[QueryPartialSystemInventory_Response].CommandCode == QueryPartialSystemInventory_Response.CommandValue and \
            _recv_msg[QueryPartialSystemInventory_Response].ResponseCode == 0:

        _text = _recv_msg[QueryPartialSystemInventory_Response].SystemInventory
        _next_frag_handle = _recv_msg[QueryPartialSystemInventory_Response].NextFragmentHandle
        return True, _text.decode("utf-8"), _next_frag_handle

    return False, "", 0


def ptti_query_partial_system_inventory_full(fwk_ctx: FwkContext, connect_id: int) -> str:
    """ Collect the full system inventory using a sequence of QueryPartialSystemInventory commands """

    _inventory_text = ""
    _next_frag_handle = 0

    while True:
        _rc, _inventory_frag, _next_frag_handle = ptti_query_partial_system_inventory(fwk_ctx, connect_id, _next_frag_handle)

        if _rc == True:
            _inventory_text += _inventory_frag

            if _next_frag_handle == 0:
                break
        else:
            break

    return _inventory_text


def ptti_configure_device_under_test_ex(fwk_ctx: FwkContext, connect_id: int, target_id: int, id_list: list) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id)
    _send_msg = _send_msg / ConfigureDeviceUnderTest_Request(TargetIdentifier=target_id, IdentifierList=id_list)

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_configure_device_under_test(fwk_ctx: FwkContext, connect_id: int, target_id: int, id_list: list) -> tuple[bool, int, list]:

    _error_code, _recv_msg, _ = ptti_configure_device_under_test_ex(fwk_ctx, connect_id, target_id, id_list)

    if _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(ConfigureDeviceUnderTest_Response) is True and \
            _recv_msg[ConfigureDeviceUnderTest_Response].CommandCode == ConfigureDeviceUnderTest_Response.CommandValue and \
            _recv_msg[ConfigureDeviceUnderTest_Response].ResponseCode == 0:

        _dut_connect_id = _recv_msg[ConfigureDeviceUnderTest_Response].DUTConnectionID

        return True, _dut_connect_id, _recv_msg[ConfigureDeviceUnderTest_Response].IdentifierList

    return False, 0, []


def ptti_register_to_protocol_ex(fwk_ctx: FwkContext, connect_id: int, dut_id: int, protocol_type: int, types_list: list) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id) / RegisterToProtocol_Request()

    _send_msg[RegisterToProtocol_Request].ProtocolType = protocol_type
    _send_msg[RegisterToProtocol_Request].DUTConnectionID = dut_id
    _send_msg[RegisterToProtocol_Request]. TypeList = types_list

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_register_to_protocol(fwk_ctx: FwkContext, connect_id: int, dut_id: int, protocol_type: int, types_list: list) -> bool:

    _error_code, _recv_msg, _ = ptti_register_to_protocol_ex(fwk_ctx, connect_id, dut_id, protocol_type, types_list)

    return _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(RegisterToProtocol_Response) is True and \
            _recv_msg[RegisterToProtocol_Response].CommandCode == RegisterToProtocol_Response.CommandValue and \
            _recv_msg[RegisterToProtocol_Response].ResponseCode == 0 and \
            _recv_msg[RegisterToProtocol_Response].DUTConnectionID == dut_id


def ptti_register_async_message_recipient_ex(fwk_ctx: FwkContext, connect_id: int, dut_id: int, protocol_type: int, types_list: list) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=0xFF, Direction=0, TestClientID=connect_id) / RegisterAsyncMessageRecipient_Request()

    _send_msg[RegisterAsyncMessageRecipient_Request].ProtocolType = protocol_type
    _send_msg[RegisterAsyncMessageRecipient_Request].DUTConnectionID = dut_id
    _send_msg[RegisterAsyncMessageRecipient_Request]. TypeList = types_list

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_register_async_message_recipient(fwk_ctx: FwkContext, connect_id: int, dut_id: int, protocol_type: int, types_list: list) -> bool:

    _error_code, _recv_msg, _ = ptti_register_async_message_recipient_ex(fwk_ctx, connect_id, dut_id, protocol_type, types_list)

    return _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(RegisterAsyncMessageRecipient_Response) is True and \
            _recv_msg[RegisterAsyncMessageRecipient_Response].CommandCode == RegisterAsyncMessageRecipient_Response.CommandValue and \
            _recv_msg[RegisterAsyncMessageRecipient_Response].ResponseCode == 0 and \
            _recv_msg[RegisterAsyncMessageRecipient_Response].DUTConnectionID == dut_id


def ptti_send_test_message_ex(fwk_ctx: FwkContext, connect_id: int, max_wait_time: int, dut_id: int, protocol_type: int, payload: Packet) -> tuple[int, Packet|None, Packet]:

    _send_msg = TestServiceWrapper(ProtocolType=protocol_type, Direction=0, TestClientID=connect_id)
    _send_msg = _send_msg / TestMessage_Request(DUTConnectionID=dut_id, MaximumWaitTime=max_wait_time )
    _send_msg = _send_msg / payload

    _error_code, _recv_msg = common_send_receive(fwk_ctx, _send_msg)
    return _error_code, _recv_msg, _send_msg


def ptti_send_test_message(fwk_ctx: FwkContext, connect_id: int, max_wait_time: int, dut_id: int, protocol_type: int, payload: Packet) -> tuple[bool, int, Packet|None]:

    _error_code, _recv_msg, _ = ptti_send_test_message_ex(fwk_ctx, connect_id, max_wait_time, dut_id, protocol_type, payload)

    if _error_code == 0 and \
            _recv_msg is not None and \
            ptti_check_tsw(_recv_msg) is True and \
            _recv_msg.haslayer(TestMessage_Response) is True and \
            _recv_msg[TestMessage_Response].ResponseCode == 0 and \
            _recv_msg[TestMessage_Response].DUTConnectionID == dut_id:

        return True, _recv_msg[TestMessage_Response].ElapsedTime, _recv_msg[TestMessage_Response].payload

    return False, 0, None
