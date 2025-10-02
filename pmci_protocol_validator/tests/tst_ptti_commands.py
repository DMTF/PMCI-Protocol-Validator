# Copyright Notice:
# Copyright 2024-2025 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0280 basic positive test cases.
##############################################################################

from pmci_protocol_validator.framework.fixture_ptti import PTTI_fixture
from pmci_protocol_validator.framework.utilities import common_send_receive
from pmci_protocol_validator.ptti.classes.dsp0280 import *


def test_connect(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, secPrm: bytes):
    """ Test DSP0280 Connect request """

    SendPacket = lowerLayerHeaders / Connect_Request()

    SendPacket[Connect_Request].SecurityParameter = RawVal(secPrm)
    SendPacket[Connect_Request].SecurityParameterLength = len(secPrm)

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)

    assert (RecvPacket[TestServiceWrapper].Version == VERSION_COMPLIANCE), "Incorrect PTTI version"
    assert (RecvPacket[TestServiceWrapper].ProtocolType == 0xFF), "Protocol mismatch"
    assert (RecvPacket[TestServiceWrapper].Reserved_0 == 0), "Reserved field NOT zero"
    assert (RecvPacket[TestServiceWrapper].Reserved_1 == 0), "Reserved field NOT zero"

    return RecvPacket


def test_query_status(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, queryType: int):
    """ Test DSP0280 QueryStatus request """

    SendPacket = lowerLayerHeaders / QueryStatus_Request(QueryType=queryType)

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)
    testFixture.verify_common_fields(RecvPacket, SendPacket)

    return RecvPacket


def test_query_capabilities(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper):
    """ Test DSP0280 QueryCapabilities request """

    SendPacket = lowerLayerHeaders / QueryCapabilities_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)
    testFixture.verify_common_fields(RecvPacket, SendPacket)

    return RecvPacket


def test_configure_test_service(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, cfgPrmsList: list):
    """ Test DSP0280 ConfigureTestService request """

    SendPacket = lowerLayerHeaders / ConfigureTestService_Request()

    SendPacket[ConfigureTestService_Request].NumberOfCapabilitiesFields = len(cfgPrmsList)
    SendPacket[ConfigureTestService_Request].TestServiceCapabilities = cfgPrmsList

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)
    testFixture.verify_common_fields(RecvPacket, SendPacket)

    return RecvPacket


def test_query_system_inventory(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper):
    """ Test DSP0280 QuerySystemInventory request """

    SendPacket = lowerLayerHeaders / QuerySystemInventory_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)
    testFixture.verify_common_fields(RecvPacket, SendPacket)

    return RecvPacket


def test_configure_device_under_test(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, tid: int = 0):
    """ Test DSP0280 ConfigureDeviceUnderTest request """

    SendPacket = lowerLayerHeaders / ConfigureDeviceUnderTest_Request()
    SendPacket[ConfigureDeviceUnderTest_Request].TargetIdentifier = tid

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)
    testFixture.verify_common_fields(RecvPacket, SendPacket)

    return RecvPacket


def test_register_to_protocol(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, connectionID: int, protocolType: int, typesList: list):
    """ Test DSP0280 RegisterToProtocol request """

    SendPacket = lowerLayerHeaders / RegisterToProtocol_Request()

    SendPacket[RegisterToProtocol_Request].ProtocolType = protocolType
    SendPacket[RegisterToProtocol_Request].DUTConnectionID = connectionID

    SendPacket[RegisterToProtocol_Request].TypeCount = len(typesList)
    SendPacket[RegisterToProtocol_Request].TypeList = typesList

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)
    testFixture.verify_common_fields(RecvPacket, SendPacket)

    return RecvPacket


def test_register_async_message_recipient(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, connectionID: int, protocolType: int, typesList: list):
    """ Test DSP0280 RegisterAsyncMessageRecipient request """

    SendPacket = lowerLayerHeaders / RegisterAsyncMessageRecipient_Request()

    SendPacket[RegisterAsyncMessageRecipient_Request].ProtocolType = protocolType
    SendPacket[RegisterAsyncMessageRecipient_Request].DUTConnectionID = connectionID

    SendPacket[RegisterAsyncMessageRecipient_Request].TypeCount = len(typesList)
    SendPacket[RegisterAsyncMessageRecipient_Request].TypeList = typesList

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)
    testFixture.verify_common_fields(RecvPacket, SendPacket)

    return RecvPacket


def test_test_message(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, connectID: int, maxWaitTime: int, testMessage: Packet):
    """ Test DSP0280 TestMessage request """

    SendPacket = lowerLayerHeaders / TestMessage_Request(DUTConnectionID=connectID, MaximumWaitTime=maxWaitTime)
    SendPacket = SendPacket / testMessage

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)
    testFixture.verify_common_fields(RecvPacket, SendPacket)

    return RecvPacket


def test_disconnect(testFixture: PTTI_fixture, lowerLayerHeaders: TestServiceWrapper):
    """ Test DSP0280 Disconnect request """

    SendPacket = lowerLayerHeaders / Disconnect_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.show_pkt)
    testFixture.verify_common_fields(RecvPacket, SendPacket)

    return RecvPacket
