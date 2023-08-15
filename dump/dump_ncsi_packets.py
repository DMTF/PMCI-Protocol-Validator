##############################################################################
#  File Abstract:
#  Display the default NC-SI request and response packets.
##############################################################################

import sys
import binascii
from scapy.packet import Raw

from ncsi.dmtf import *  # pylint: disable=unused-import, unused-wildcard-import


test_ncsi_commands = [
    "ClearInitialState",
    "ResetChannel",
    "SelectPackage",
    "DeselectPackage",
    "EnableChannel",
    "DisableChannel",
    "EnableChannelNetworkTx",
    "DisableChannelNetworkTx",
    "AenEnable",
    "SetLink",
    "GetLinkStatus",
    "SetVlanFilter",
    "EnableVlan",
    "DisableVlan",
    "SetMACAddress",
    "EnableBroadcastFilter",
    "DisableBroadcastFilter",
    "EnableGlobalMulticastFilter",
    "DisableGlobalMulticastFilter",
    "SetNCSIFlowControl",
    "GetVersionID",
    "GetCapabilities",
    "GetParameters",
    "GetControllerPacketStatistics",
    "GetNCSIStatistics",
    "GetNCSIPassthroughStatistics",
    "GetPackageStatus"
]


def get_class_instance(name):
    """Create a class instance given the class name"""

    try:
        identifier = getattr(sys.modules[__name__], name)

    except AttributeError:
        raise NameError("%s doesn't exist." % name)

    return identifier


def dump_class(cls_name):
    """Print the Request and Response packet formats"""

    request = get_class_instance(cls_name + "_Request")
    request_pkt = request()

    print("### " + cls_name + " Request ###")
    request_pkt.show2()

    display = Raw(request_pkt)
    print("   Raw: " + str(binascii.b2a_hex(display.fields['load'], " ")) + "\n")

    response = get_class_instance(cls_name + "_Response")
    response_pkt = response()

    print("### " + cls_name + " Response ###")
    response_pkt.show2()

    display = Raw(response_pkt)
    print("   Raw: " + str(binascii.b2a_hex(display.fields['load'], " ")) + "\n")


def dump_packets():
    """Iterates list of commands/responses and prints the packet data"""

    for cmd in test_ncsi_commands:
        dump_class(cmd)
