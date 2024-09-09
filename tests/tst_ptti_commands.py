# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0280 basic positive test cases.
##############################################################################

from testframework.fixture_ptti import c_PTTI_fixture
from testframework.utilities import common_send_receive
from ptti.dmtf import *


def test_Connect(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, secPrm: bytes):
    """ Test DSP0280 Connect request """

    SendPacket = lowerLayerHeaders / Connect_Request()

    SendPacket[Connect_Request].SecurityParameter = RawVal(secPrm)
    SendPacket[Connect_Request].SecurityParameterLength = len(secPrm)

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket


def test_QueryStatus(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, queryType: int):
    """ Test DSP0280 QueryStatus request """

    SendPacket = lowerLayerHeaders / QueryStatus_Request(QueryType=queryType)

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket


def test_QueryCapabilities(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper):
    """ Test DSP0280 QueryCapabilities request """

    SendPacket = lowerLayerHeaders / QueryCapabilities_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket


def test_ConfigureTestService(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, cfgPrmsList: list):
    """ Test DSP0280 ConfigureTestService request """

    SendPacket = lowerLayerHeaders / ConfigureTestService_Request()

    SendPacket[ConfigureTestService_Request].NumberOfCapabilitiesFields = len(cfgPrmsList)
    SendPacket[ConfigureTestService_Request].TestServiceCapabilities = cfgPrmsList

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket


def test_QuerySystemInventory(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper):
    """ Test DSP0280 QuerySystemInventory request """

    SendPacket = lowerLayerHeaders / QuerySystemInventory_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket


def test_ConfigureDeviceUnderTest(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper):
    """ Test DSP0280 ConfigureDeviceUnderTest request """

    SendPacket = lowerLayerHeaders / ConfigureDeviceUnderTest_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket


def test_RegisterToProtocol(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, connectionID: int, protocolType: int, typesList: list):
    """ Test DSP0280 RegisterToProtocol request """

    SendPacket = lowerLayerHeaders / RegisterToProtocol_Request()

    SendPacket[RegisterToProtocol_Request].ProtocolType = protocolType
    SendPacket[RegisterToProtocol_Request].DUTConnectionID = connectionID

    SendPacket[RegisterToProtocol_Request].TypeCount = len(typesList)
    SendPacket[RegisterToProtocol_Request].TypeList = typesList

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket


def test_RegisterAsyncMessageRecipient(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, connectionID: int, protocolType: int, typesList: list):
    """ Test DSP0280 RegisterAsyncMessageRecipient request """

    SendPacket = lowerLayerHeaders / RegisterAsyncMessageRecipient_Request()

    SendPacket[RegisterAsyncMessageRecipient_Request].ProtocolType = protocolType
    SendPacket[RegisterAsyncMessageRecipient_Request].DUTConnectionID = connectionID

    SendPacket[RegisterAsyncMessageRecipient_Request].TypeCount = len(typesList)
    SendPacket[RegisterAsyncMessageRecipient_Request].TypeList = typesList

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket


def test_TestMessage(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper, connectID: int, maxWaitTime: int, testMessage: Packet):
    """ Test DSP0280 TestMessage request """

    SendPacket = lowerLayerHeaders / TestMessage_Request(DUTConnectionID=connectID, MaximumWaitTime=maxWaitTime)
    SendPacket = SendPacket / testMessage

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket


def test_Disconnect(testFixture: c_PTTI_fixture, lowerLayerHeaders: TestServiceWrapper):
    """ Test DSP0280 Disconnect request """

    SendPacket = lowerLayerHeaders / Disconnect_Request()

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)
    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    return RecvPacket
