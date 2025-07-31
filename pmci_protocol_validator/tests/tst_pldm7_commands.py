# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0242 test cases.
##############################################################################

from testframework.utilities import common_send_receive
from pldm.type7 import *    # noqa:F403


def test_DfOpen(testFixture, lowerLayer, FileId, OpenWrite=False, OpenExclusive=False, OpenFIFO=False, OpenPushed=False):
    """ Test DSP0242 DfOpen Request & Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DfOpen_Request()

    SendPacket[DfOpen_Request].FileIdentifier = FileId
    SendPacket[DfOpen_Request].DfOpenReadWrite = 1 if OpenWrite else 0
    SendPacket[DfOpen_Request].DfOpenExclusive = 1 if OpenExclusive else 0
    SendPacket[DfOpen_Request].DfOpenRegFIFO = 1 if OpenFIFO else 0
    SendPacket[DfOpen_Request].DfOpenPolledPushed = 1 if OpenPushed else 0

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DfOpen_Response].Reserved == 0), "Reserved field NOT zero"
    assert (RecvPacket[DfOpen_Response].CompletionCode == 0)
    return RecvPacket


def test_DfClose(testFixture, lowerLayer, FileDescriptor, SetZeroLength=False):
    """ Test DSP0242 DfClose Request & Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DfClose_Request()

    SendPacket[DfOpen_Request].FileDescriptor = FileDescriptor
    SendPacket[DfClose_Request].ZeroLength = 1 if SetZeroLength else 0

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DfClose_Response].CompletionCode == 0)
    return RecvPacket


def test_DfHeartbeat(testFixture, lowerLayer, FileDescriptor, MaxInterval=0):
    """ Test DSP0242 DfHeartbeat Request & Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DfHeartbeat_Request()

    SendPacket[DfOpen_Request].FileDescriptor = FileDescriptor
    SendPacket[DfOpen_Request].RequestorMaxInterval = MaxInterval

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DfHeartbeat_Response].CompletionCode == 0)
    return RecvPacket


def test_DfProperties(testFixture, lowerLayer, FileDescriptor, Property=0):
    """ Test DSP0242 DfProperties Request & Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DfProperties_Request()

    SendPacket[DfProperties_Request].FileDescriptor = FileDescriptor
    SendPacket[DfProperties_Request].MaxConcurrentMedium = 1 if Property & 0x01 else 0
    SendPacket[DfProperties_Request].MaxFileDescriptors = 1 if Property & 0x02 else 0

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DfProperties_Response].CompletionCode == 0)
    return RecvPacket


def test_DfGetFileAttribute(testFixture, lowerLayer, FileId, Attribute):
    """ Test DSP0242 DfGetFileAttribute Request & Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DfGetFileAttribute_Request()

    SendPacket[DfGetFileAttribute_Request].FileIdentifier = FileId
    SendPacket[DfGetFileAttribute_Request].ClientDeleteOnly = 1 if Attribute & 0x0001 else 0
    SendPacket[DfGetFileAttribute_Request].RequestCI = 1 if Attribute & 0x0100 else 0
    SendPacket[DfGetFileAttribute_Request].ReqMaxPoll = 1 if Attribute & 0x0200 else 0

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DfGetFileAttribute_Response].CompletionCode == 0)
    return RecvPacket


def test_DfSetFileAttribute(testFixture, lowerLayer, FileId, AttributeSet=0, Value=0):
    """ Test DSP0242 DfSetFileAttribute Request & Response """

    SendPacket = lowerLayer / testFixture.get_ncsi_header()
    SendPacket = SendPacket / DfSetFileAttribute_Request()

    SendPacket[DfSetFileAttribute_Request].FileIdentifier = FileId
    SendPacket[DfSetFileAttribute_Request].ClientZeroLengthOnly = 1 if AttributeSet & 0x0001 else 0
    SendPacket[DfSetFileAttribute_Request].FileAttributeValue = Value

    RecvPacket = common_send_receive(testFixture.commObject, SendPacket, testFixture.showPacket)

    testFixture.VerifyCommonFields(RecvPacket, SendPacket)

    assert (RecvPacket[DfSetFileAttribute_Response].CompletionCode == 0)
    return RecvPacket
