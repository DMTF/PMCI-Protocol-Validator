##############################################################################
#  File Abstract:
#  Display PLDM over NC-SI request and response packets
##############################################################################

import sys
import binascii
from scapy.packet import Raw

from ncsi.dmtf import NCSI_HEADER
from ncsi.pldm_payload import NcsiPldm_Request
from pldm.dmtf import PLDM_HEADER
from pldm.type0 import *  # pylint: disable=unused-import, unused-wildcard-import


test_pldm0_commands = [
    "SetTID",
    "GetTID",
    "GetPldmVersion",
    "GetPldmTypes",
    "GetPldmCommands",
]


def get_class_instance(name):
    """Get class instance"""

    try:
        identifier = getattr(sys.modules[__name__], name)
    except AttributeError:
        raise NameError("%s doesn't exist." % name)
    return identifier


def test_command(pldm_command, InstanceID):
    """OEM test command class"""

    print("### %s_Request ###" % pldm_command)
    command_request = get_class_instance(pldm_command + "_Request")

    requestPacket = NCSI_HEADER(ChannelID=3) / NcsiPldm_Request()
    requestPacket = requestPacket / PLDM_HEADER(PldmType=0,InstanceID=InstanceID)
    requestPacket = requestPacket / command_request()

    requestPacket.show2()

    buffer = Raw(requestPacket)
    print("Raw: " + str(binascii.b2a_hex(buffer.fields['load'], " ")))


def dump_packets():
    """Iterates list of commands/responses and prints the packet data"""

    InstanceID = 0

    for entry in test_pldm0_commands:
        InstanceID += 1
        test_command(entry, InstanceID)
