##############################################################################
#  File Abstract:
#  Display the default PLDM Type 6 request and response packets.
##############################################################################

import sys
import binascii
from scapy.packet import Raw, raw
from pldm.type6 import *  # pylint: disable=unused-import, unused-wildcard-import


test_pldm6_commands = [
    "NegotiateRedfishParameters",
    "NegotiateMediumParameters",
    "GetSchemaDictionary",
    "GetSchemaURI",
    "GetResourceETag",
    "MultipartSend",
    "MultipartReceive",
    "GetOEMCount",
    "GetOEMName",
    "GetRegistryCount",
    "GetRegistryDetails",
    "SelectRegistryVersion",
    "GetMessageRegistry",
    "GetSchemaFile",

    # RDE
    "RDEOperationInit",
    "SupplyCustomRequestParameters",
    "RetrieveCustomResponseParameters",
    "RDEOperationComplete",
    "RDEOperationStatus",
    "RDEOperationKill",
    "RDEOperationEnumerate",
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

    request_pkt = get_class_instance(cls_name + "_Request")()
    response_pkt = get_class_instance(cls_name + "_Response")()

    print("### " + cls_name + " Request ###")
    request_pkt.show2()

    display = Raw(request_pkt)
    print("   Raw: " + str(binascii.b2a_hex(raw(display), " ")) + "\n")

    print("### " + cls_name + " Response ###")
    response_pkt.show2()

    display = Raw(response_pkt)
    print("   Raw: " + str(binascii.b2a_hex(raw(display), " ")) + "\n")


def dump_packets():
    """Iterates list of commands/responses and prints the packet data"""

    for cmd in test_pldm6_commands:
        dump_class(cmd)
