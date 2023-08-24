# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Example DSP0280 Test Service Client.
##############################################################################

from scapy.all import *  # pylint: disable=unused-import, unused-wildcard-import
from ptti.dmtf import *    # pylint: disable=unused-import, unused-wildcard-import
from ptti.binding import PTTIMedium
from pldm.dmtf import PLDM_HEADER
from pldm.type0 import GetTID_Request, GetTID_Response


# Network parameters for server connection
CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155


def main():
    """ main() test application """

    # Initialize the network interface
    try:
        commObject = PTTIMedium(CONNECTION_ADDRESS, CONNECTION_PORT)
    except:
        return 9

    ### Test service configuration per DMTF0280 section 8.3.1 ###

    # 1. Connect
    Request = Connect_Request()
    Request[Connect_Request].SecurityParameter=RawVal(b'\x31\x32\x33\x34\x35\x36')
    Request[Connect_Request].SecurityParameterLength = len(Request[Connect_Request].SecurityParameter)

    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0) / Request

    print(">>> " + str(raw(SendPacket).hex(" ", 1)))

    (rc, RecvPacket) = send_recv_msg(commObject, SendPacket)

    if rc is False or RecvPacket is None:
        return 1

    print("<<< " + str(raw(RecvPacket).hex(" ", 1)))

    CommandCode = RecvPacket[Connect_Response].CommandCode
    ResponseCode = RecvPacket[Connect_Response].ResponseCode
    TestServiceVersion = RecvPacket[Connect_Response].TestServiceVersion
    TestClientID = RecvPacket[Connect_Response].TestClientID

    # 2. Query Capabilities
    Request = QueryCapabilities_Request()
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0) / Request
    (rc, RecvPacket) = send_recv_msg(commObject, SendPacket)
    if rc is False:
        return 2

    # 3. Configure Test Service
    Request = ConfigureTestService_Request()
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0) / Request
    (rc, RecvPacket) = send_recv_msg(commObject, SendPacket)
    if rc is False:
        return 3

    # 4. Query System Inventory
    Request = QuerySystemInventory_Request()
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0) / Request
    (rc, RecvPacket) = send_recv_msg(commObject, SendPacket)
    if rc is False:
        return 4

    # 5. Configure DUT
    Request = ConfigureDeviceUnderTest_Request()
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0) / Request
    (rc, RecvPacket) = send_recv_msg(commObject, SendPacket)
    if rc is False:
        return 5

    # 6. Register to Protocol
    Request = RegisterToProtocol_Request()
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0) / Request
    (rc, RecvPacket) = send_recv_msg(commObject, SendPacket)
    if rc is False:
        return 6

    # 7. Register Async Message Recipient
    Request = RegisterAsyncMessageRecipient_Request()
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0) / Request
    (rc, RecvPacket) = send_recv_msg(commObject, SendPacket)
    if rc is False:
        return 7

    # Send a Test Message with a PLDM Get TID request
    TestWrapper = TestServiceWrapper(ProtocolType=0x01, Direction=0, TestClientID=TestClientID)
    TestMessageRequest = TestMessage_Request(DUTConnectionID=0x55aa55aa)
    PldmHeader = PLDM_HEADER(Request=1, InstanceID=10)
    PldmRequest = GetTID_Request()

    SendPacket = TestWrapper / TestMessageRequest / PldmHeader / PldmRequest

    (rc, rxdata) = send_recv_msg(commObject, SendPacket)

    Response = PLDM_HEADER(raw(rxdata[TestMessage_Response].payload))
    Response.show2()

    # Send a Vendor Defined Admin message
    TestWrapper = TestServiceWrapper(ProtocolType=0xF1, Direction=0)
    Request = VendorDefinedAdmin_Request(IANA=0x1234)
    SendPacket = TestWrapper / Request

    (rc, rxdata) = send_recv_msg(commObject, SendPacket)

    # 8. Disconnect
    Request = Disconnect_Request()
    SendPacket = TestServiceWrapper(ProtocolType=0xFF, Direction=0) / Request
    (rc, RecvPacket) = send_recv_msg(commObject, SendPacket)

    if rc is False:
        return 8

    return 0


def send_recv_msg(commObject, SendPacket):
    """Helper function to send requests and receive responses"""

    SendPacket.show2()
    commObject.Write(SendPacket)

    (ErrorCode, RecvPacket) = commObject.Read()

    if ErrorCode == 0 and RecvPacket is not None:
        RecvPacket.show2()
        return (True, RecvPacket)

    return (False, None)

#
# Call main() if this Python script is the main script.
if __name__ == '__main__':
    exit(main())
