# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Display the DSP0280 request and response classes.
##############################################################################

import sys
import binascii

from scapy.packet import Raw
from ptti.dmtf import *

show_ptti_packets = [
    "Connect_Request",
    "Connect_Response",
    "Disconnect_Request",
    "Disconnect_Response",
    "QueryCapabilities_Request",
    "QueryCapabilities_Response",
    "QueryStatus_Request",
    "QueryStatus_Response",
    "QuerySystemInventory_Request",
    "QuerySystemInventory_Response",
    "ConfigureTestService_Request",
    "ConfigureTestService_Response",
    "ConfigureDeviceUnderTest_Request",
    "ConfigureDeviceUnderTest_Response",
    "RegisterToProtocol_Request",
    "RegisterToProtocol_Response",
    "RegisterAsyncMessageRecipient_Request",
    "RegisterAsyncMessageRecipient_Response",
    "LogEvent_Request",
    "LogEvent_Response",
    "VendorDefinedAdmin_Request",
    "VendorDefinedAdmin_Response",
    "TestMessage_Request",
    "TestMessage_Response"
]


def get_class_instance(name: str):
    """ Create a class instance given the class name """

    try:
        identifier = getattr(sys.modules[__name__], name)
    except AttributeError:
        raise NameError("%s doesn't exist." % name)
    return identifier


def show_class(cls_name: str):
    """ Print the packet format """

    request = get_class_instance(cls_name)

    if "_Request" in cls_name:
        DirectionFlag = 0
    else:
        DirectionFlag = 1

    request_pkt = TestServiceWrapper(Direction=DirectionFlag) / request()
    request_pkt.show2()

    display = Raw(request_pkt)

    if len(display.fields) > 0:
        print("  Raw: " + str(binascii.b2a_hex(display.fields['load'], " ")) + "\n")

    else:
        CommandValue = int(request_pkt.CommandValue).to_bytes(1, 'little')
        print("  Raw: " + str(binascii.b2a_hex(CommandValue, " ")) + "\n")


def show_packets():
    """ Iterate the command/response list and print the packet contents """

    for cmd in show_ptti_packets:
        show_class(cmd)


if __name__ == '__main__':
    """ Application main entry point """

    show_packets()
