# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Display the default PLDM Type 5 request and response packets.
##############################################################################

import sys
import binascii
from scapy.packet import Raw

from pldm.dmtf import PLDM_HEADER
from pldm.type5 import *


test_pldm5_commands = [
    # Inventory commands
    "QueryDeviceIdentifiers",
    "GetFirmwareParameters",
    "QueryDownstreamDevices",
    "QueryDownstreamIdentifiers",
    "GetDownstreamFirmwareParameters",

    # Update commands
    "RequestUpdate",
    "GetPackageData",
    "GetDeviceMetaData",
    "PassComponentTable",
    "UpdateComponent",
    "RequestFirmwareData",
    "TransferComplete",
    "VerifyComplete",
    "ApplyComplete",
    "GetMetaData",
    "ActivateFirmware",
    "GetStatus",
    "CancelUpdateComponent",
    "CancelUpdate",
    "ActivatePendingComponentImageSet",
    "ActivatePendingComponentImage",
    "RequestDownstreamDeviceUpdate",
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
    response = get_class_instance(cls_name + "_Response")

    request_pkt = PLDM_HEADER() / request()
    response_pkt = PLDM_HEADER() / response()

    print("### " + cls_name + " Request ###")
    request_pkt.show2()

    display = Raw(request_pkt)
    print("   Raw: " + str(binascii.b2a_hex(display.fields['load'], " ")) + "\n")

    print("### " + cls_name + " Response ###")
    response_pkt.show2()

    display = Raw(response_pkt)
    print("   Raw: " + str(binascii.b2a_hex(display.fields['load'], " ")) + "\n")


def dump_packets():
    """Iterates list of commands/responses and prints the packet data"""

    for cmd in test_pldm5_commands:
        dump_class(cmd)
