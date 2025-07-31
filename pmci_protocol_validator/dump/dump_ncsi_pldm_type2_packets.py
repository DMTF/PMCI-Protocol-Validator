# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Display PLDM Type 2 over NC-SI request and response packets.
##############################################################################

import pytest
import sys
import binascii
from scapy.packet import Raw

from ncsi.dmtf import NCSI_HEADER
from ncsi.pldm_payload import NcsiPldm_Request
from pldm.dmtf import PLDM_HEADER
from pldm.type2 import *

test_data = [0]

test_pldm2_commands = [
    "GetTerminusUID",
    "SetEventReceiver",
    "GetEventReceiver",
    "PlatformEventMessage",
    "PollForPlatformEventMessage",
    "EventMessageSupported",
    "EventMessageBufferSize",

    # Numeric Sensor commands
    "SetNumericSensorEnable",
    "GetSensorReading",
    "GetSensorThresholds",
    "SetSensorThresholds",
    "RestoreSensorThresholds",
    "GetSensorHysteresis",
    "SetSensorHysteresis",
    "InitNumericSensor",

    # State Sensor commands
    "SetStateSensorEnables",
    "GetStateSensorReadings",
    "InitStateSensor",

    # PLDM Effecter commands
    "SetNumericEffecterEnable",
    "SetNumericEffecterValue",
    "GetNumericEffecterValue",
    "SetStateEffecterEnables",
    "SetStateEffecterStates",
    "GetStateEffecterStates",

    # PLDM Event Log commands
    "GetPLDMEventLogInfo",
    "EnablePLDMEventLogging",
    "ClearPLDMEventLog",
    "GetPLDMEventLogTimestamp",
    "SetPLDMEventLogTimestamp",
    "ReadPLDMEventLog",
    "GetPLDMEventLogPolicyInfo",
    "SetPLDMEventLogPolicy",
    "FindPLDMEventLogEntry",

    # PDR Repository commands
    "GetPDRRepositoryInfo",
    "GetPDR",
    "FindPDR",
    "RunInitAgent",
    "GetPDRRepositorySignature",
]


def get_class_instance(name):
    try:
        identifier = getattr(sys.modules[__name__], name)

    except AttributeError:
        raise NameError("%s doesn't exist." % name)

    return identifier


@pytest.mark.parametrize("pldm_command", test_pldm2_commands)
@pytest.mark.parametrize("InstanceID", test_data)
def test_command(pldm_command, InstanceID):

    print("### %s_Request ###" % pldm_command)
    command_request = get_class_instance(pldm_command + "_Request")

    requestPacket = NCSI_HEADER(ChannelID=3) / NcsiPldm_Request()
    requestPacket = requestPacket / PLDM_HEADER(PldmType=0, InstanceID=InstanceID)
    requestPacket = requestPacket / command_request()

    requestPacket.show2()

    buffer = Raw(requestPacket)
    print("Raw: " + str(binascii.b2a_hex(buffer.fields['load'], " ")))


def dump_packets():
    """Iterates list of commands/responses and prints the packet data"""

    InstanceID = 0

    for entry in test_pldm2_commands:
        InstanceID += 1
        test_command(entry, InstanceID)
