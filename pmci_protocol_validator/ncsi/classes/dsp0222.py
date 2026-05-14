# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Scapy classes for DSP0222

File : dsp0222.py

Brief : Contains all of the base NC-SI protocol functionality as well as the
DMTF defined commands. OEM commands are in separate files.
"""

import struct
from scapy.all import *
from scapy.fields import *
from scapy.packet import Packet

from pmci_protocol_validator.ncsi.classes.dsp0222_enums import *


# Conformant to DSP0222 version 1.1.0
DSP0222_COMPLIANCE_VERSION = int.from_bytes([1, 1, 0, 0], 'big')


### Key:Value store for the commands/classes
NCSI_COMMANDS_VALUE = {}    # Dictionary of NC-SI Commands for DMTF commands
OEM_COMMANDS = {}           # OEM specific dictionary sorted first by IANA
OEM_COMMAND_DECODERS = (
    {}
)  # hosts OEM specific functions for finding the correct class when decoding


# Global Instance ID
CurrentIID = 0xFF   # start at MAX, so 1st one actually used is 1


def getNextIID():
    global CurrentIID

    if CurrentIID > 0xFE or CurrentIID < 1:
        CurrentIID = 1
    else:
        CurrentIID += 1

    return CurrentIID


def getNextNcsiHeader(packageID=0, channelID=0):
    return NCSI_HEADER(PackageID=packageID, ChannelID=channelID, IID=getNextIID())


def validateRegisteredClass(cls):
    """called when NC-SI command is registed
    to build a sample packet, to ensure it was created properly,
    for example if the bitfields aren't quite right, this will assert
    """
    try:
        testInst = cls()
        raw(testInst)  # this will try to build the packet

    except Exception as Ex:
        print(str(Ex))
        assert (
            False
        ), "{} seems to be invalid.  Check bitfields and other stuff to make sure they are accurate".format(
            cls.__name__
        )


def register_ncsi_oem_classFinders(IANA, buildFnPtr, dissectorFnPtr):
    """OEM Commands are not defined consistently (big surprise), so this
    allows me to register functions specific to an OEM IANA to build a OEM command Packet
    from either code, or from a binary source.  1st Function takes the registered  class
    and looks at the data within it to return a unique ID for lookup in the class dictionary
    2nd function does the same thing, but from a binary stream (as in read from the wire or PCAP file)
    """
    if IANA in OEM_COMMAND_DECODERS:
        assert (
            False
        ), "Duplicate OEM NC-SI class finder being registered: IANA={}".format(
            hex(IANA)
        )

    OEM_COMMAND_DECODERS[IANA] = (buildFnPtr, dissectorFnPtr)


def register_ncsi_oem_class(cls):
    Command = cls.CommandValue
    assert (
        Command == 0x50 or Command == 0xD0
    ), "Trying to register a non OEM Command in register oem command function"

    Name = cls.__name__
    IANA = cls.OEM_IANA
    assert IANA in OEM_COMMAND_DECODERS, "No class finder found for IANA {}".format(
        hex(IANA)
    )
    buildFnPtr, _ = OEM_COMMAND_DECODERS[IANA]

    Identifier = buildFnPtr(
        cls
    )  # OEMs do things differently, so provide custom fn to figure this out
    if IANA not in OEM_COMMANDS:
        OEM_COMMANDS[IANA] = {
            "OEM_COMMANDS_VALUE": {},
            "OEM_COMMANDS_NAME": {},
        }  # key off of IANA

    valMap = OEM_COMMANDS[IANA]["OEM_COMMANDS_VALUE"]

    if Identifier in valMap:
        assert False, "Duplicate OEM NC-SI Identifier: IANA={} {} from {}".format(
            hex(IANA), hex(Identifier), Name
        )

    valMap[Identifier] = cls

    # quick check to make sure it is a valid packet
    validateRegisteredClass(cls)


def register_ncsi_class(cls):
    CommandVal = cls.CommandValue
    Name = cls.__name__

    if (
        CommandVal == 0x50 or CommandVal == 0xD0 and Name != "OEMCommand_Response"
    ):  # is an OEM command, handle a bit differently
        return register_ncsi_oem_class(cls)

    if CommandVal in NCSI_COMMANDS_VALUE:
        prevName = NCSI_COMMANDS_VALUE[CommandVal].__name__
        assert False, "Duplicate NC-SI Command: {} from {} prevous was from {}".format(
            hex(CommandVal), Name, prevName
        )

    NCSI_COMMANDS_VALUE[CommandVal] = cls
    # quick check to make sure it is a valid packet
    validateRegisteredClass(cls)


def getNcsiClassFromRaw(rawPacket):
    """figures out which class to return based upon a raw series of bytes"""
    (Command,) = struct.unpack("B", bytes([rawPacket[4]]))
    if Command == 0x50 or Command == 0xD0:
        if Command == 0x50:
            (IANA,) = struct.unpack("!I", rawPacket[16:20])
        else:
            (IANA,) = struct.unpack("!I", rawPacket[20:24])

        if IANA not in OEM_COMMAND_DECODERS:
            assert (
                False
            ), "OEM NC-SI Command found, but IANA: {} not registered.".format(hex(IANA))
        _, dissectorFnPtr = OEM_COMMAND_DECODERS[IANA]
        OemCommandId = dissectorFnPtr(rawPacket)

        if OemCommandId not in OEM_COMMANDS[IANA]["OEM_COMMANDS_VALUE"]:
            # have found an OEM command that is unknown, so have the
            # generic OEM Response (command code = 0xD0) decoder handle it.
            Command = 0xD0

        else:
            return OEM_COMMANDS[IANA]["OEM_COMMANDS_VALUE"][OemCommandId]

    if Command not in NCSI_COMMANDS_VALUE:
        assert False, "NC-SI Command {} not registered.".format(hex(Command))

    return NCSI_COMMANDS_VALUE[Command]


class NcsiReversePadField(ReversePadField):
    """customize behavior of the ReversePadField to store the payload length
    in the packet, so it can be used in calculating the length of the packet
    later in the process.  VERY important to have this at end of a NC-SI
    packet class defintion, unless that packet does not have a checksum -
    such as OEM commands, in which case the payload.packet_len field
    must be set someplace else.  the payload.packet_len field is key to
    building the NC-SI header, checksum and padding.
    """

    def addfield(
        self,
        pkt,  # type: BasePacket
        s,  # type: bytes
        val,  # type: Any
    ):
        # type: (...) -> bytes

        if scapy.__version__ >= "2.4.5":
            sval = self.fld.addfield(pkt, b"", val)
        else:
            sval = self._fld.addfield(pkt, b"", val)

        pkt.payload_len = len(s)

        return s + struct.pack("%is" % (self.padlen(len(s), pkt)), self._padwith) + sval


# DSP0222 - Table 10
class NCSI_HEADER(Packet):
    """The NC-SI Header layer definition"""

    name = "NC-SI Header"
    fields_desc = [
        XByteField("MC_ID", 0x00),
        XByteField("HeaderRevision", 0x01),
        XByteField("NcsiHeaderReserved_1", 0x00),
        XByteField("IID", 0x01),
        XByteField("Command", None),
        XBitField("PackageID", 0x00, 3),
        XBitField("ChannelID", 0x00, 5),
        BitField("Flags", 0x0, 4),
        BitField("PayloadLength", None, 12),
        XLongField("NcsiHeaderReserved_2", 0x0000000000000000)
    ]

    NCSI_HEADER_LENGTH = 16

    def guess_payload_class(self, payload):
        """Find out what class to return based upon the Command for
        regular DMTF commands, and dig deeper for OEM
        """

        CommandVal = self.Command
        if CommandVal == 0x50 or CommandVal == 0xD0:
            # is an OEM command, so throw together a raw OEM command header and
            # append the payload, and let the getNcsiClassFromRaw do the work
            tPacket = NCSI_HEADER(Command=CommandVal)
            rawData = raw(tPacket) + payload
            return getNcsiClassFromRaw(rawData)

        if CommandVal not in NCSI_COMMANDS_VALUE:
            assert False, "NC-SI Command {} not registered.".format(hex(CommandVal))

        return NCSI_COMMANDS_VALUE[CommandVal]

    def _updatePayloadLengthAndCommand(self, pkt, pay):
        """if the payload length is not specified (default)
        then calculate it and insert into raw packet
        """
        # pylint: disable=access-member-before-definition
        if (
            self.Command is None
        ):  # only update if you didn't specify when creating NCSI_HEADER
            encodedCommand = struct.pack("B", self.payload.CommandValue)
            pkt = pkt[:4] + encodedCommand + pkt[5:]
            self.Command = self.payload.CommandValue

        if self.PayloadLength is None:  # if you overrode length, then leave as is
            rsvdVal = (
                self.NcsiHeaderReserved_2 << 12
            )  # include the reserved in encoding - in case you want to try and twiddle it

            payloadLen = self.payload.payload_len + rsvdVal
            encodedPayloadLen = struct.pack("!H", payloadLen)
            pkt = pkt[:6] + encodedPayloadLen + pkt[8:]  # change the packet length bits

        return pkt

    @staticmethod
    def ncsi_checksum(pkt):
        if len(pkt) % 2 == 1:
            pkt += b"\0"
        pkt_buffer = memoryview(pkt)
        two_bytes_struct = struct.Struct(">H")
        two_bytes_pkt = []
        while pkt_buffer:
            two_bytes_pkt += two_bytes_struct.unpack_from(pkt_buffer)
            pkt_buffer = pkt_buffer[two_bytes_struct.size:]

        checksum_value = 2**32 - sum(two_bytes_pkt)
        return checksum_value & 0xFFFFFFFF

    def insertChecksum(self, pkt, pay):
        """ Inserts the checksum into the packet """

        # This was written for readability, not minimal lines of code.
        # If an OEM command that does not use a Checksum, then will not add it.
        # It is done here rather than in payload because need checksum header
        # and payload

        addChecksum = True

        if self.payload.getChecksumLen() < 1:
            addChecksum = False

        if hasattr(self.payload, "Checksum"):
            if None != self.payload.Checksum:
                addChecksum = False

        if True == addChecksum:
            pktForChecksum = (
                pkt + pay[: self.payload.payload_len]
            )  # only up till padding
            chksumLen = self.payload.getChecksumLen()
            chkSumLoc = len(pay) - chksumLen
            upTillChksum = pay[:chkSumLoc]
            checksumVal = NCSI_HEADER.ncsi_checksum(pktForChecksum)
            chksum = struct.pack("!L", checksumVal)
            afterChksum = pay[chkSumLoc + chksumLen:]
            retPkt = pkt + upTillChksum + chksum + afterChksum

        else:  # if no checksum, still need to combine packet and payload
            retPkt = pkt + pay

        return retPkt

    def post_build(self, pkt, pay):
        """called by scapy framework, this is where
        the payload length is updated, and the
        checksum inserted
        """
        if self.payload.name != "NoPayload":
            updatedPacket = self._updatePayloadLengthAndCommand(pkt, pay)
            return self.insertChecksum(updatedPacket, pay)

        return pkt + pay

    def extract_padding(self, s):  # all payloads need to do this
        return s, ""


class NCSI_PAYLOAD(Packet):
    """Base class for all NC-SI Commands and Responses. It handles much
    of the custom stuff for calculating the payload length, padding
    and checksums, so the classes for each individual Command and
    Response do not need to do anything extra
    """

    __slots__ = ["payload_len"]
    name = "NC-SI Payload"

    fields_desc = []

    def getChecksumLen(self):
        """Checksum length is always 4 except for old OEM"""
        return 4


""" ------------------- NC-SI Commands ------------------- """

# DSP0222 - Table 25
class ClearInitialState_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Clear Initial State Request"""

    name = "Clear Initial State Request"
    CommandValue = 0x00

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)  # Inserts PAD and Checksum Fields
    ]


# DSP0222 - Table 26
class ClearInitialState_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Clear Initial State Response"""

    name = "Clear Initial State Response"
    CommandValue = 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 27
class SelectPackage_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Select Package Request"""

    name = "Select Package Request"
    CommandValue = 0x01

    fields_desc = [
        X3BytesField("SelectPackageReserved_1", 0),
        BitField("HardwareArbitrationReserved_2", 0, 6),
        BitField("DelayedResponseEnable", 0, 1),
        BitField("HardwareArbitrationDisable", 0, 1),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 28
class SelectPackage_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Select Package Response"""

    name = "Select Package Response"
    CommandValue = 0x81

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 30
class DeselectPackage_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Deselect Package Request"""

    name = "Deselect Package Request"
    CommandValue = 0x02

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 31
class DeselectPackage_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Deselect Package Response"""

    name = "Deselect Package Response"
    CommandValue = 0x82

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  32
class EnableChannel_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable Channel Request"""

    name = "Enable Channel Request"
    CommandValue = 0x03

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 33
class EnableChannel_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable Channel Response"""

    name = "Enable Channel Response"
    CommandValue = 0x83

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 34
class DisableChannel_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Disable Channel Request"""

    name = "Disable Channel Request"
    CommandValue = 0x04

    fields_desc = [
        BitField("Reserved", 0, 31),
        BitField("ALD", 0, 1),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 35
class DisableChannel_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Disable Channel Response"""

    name = "Disable Channel Response"
    CommandValue = 0x84

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 37
class ResetChannel_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Reset Channel Request"""

    name = "Reset Channel Request"
    CommandValue = 0x05

    fields_desc = [
        XIntField("Reserved", 0x00000000),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 37
class ResetChannel_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Reset Channel Response"""

    name = "Reset Channel Response"
    CommandValue = 0x85

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 38
class EnableChannelNetworkTx_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable Channel Network TX Request"""

    name = "Enable Channel Network TX Request"
    CommandValue = 0x06

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 39
class EnableChannelNetworkTx_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable Channel Network TX Response"""

    name = "Enable Channel Network TX Response"
    CommandValue = 0x86

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 40
class DisableChannelNetworkTx_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Disable Channel Network TX Request"""

    name = "Disable Channel Network TX Request"
    CommandValue = 0x07

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 41
class DisableChannelNetworkTx_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Disable Channel Network TX Response"""

    name = "Disable Channel Network TX Response"
    CommandValue = 0x87

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 42
class AenEnable_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 AEN Enable Request"""

    name = "AEN Enable Request"
    CommandValue = 0x08

    fields_desc = [
        BitField("AEN_Reserved_2", 0, 24),
        BitField("AEN_MC_ID", 0, 8),

        # ''' DSP0222 1.2.0 AEN control '''
        # XBitField("OEM", 0, 16),
        # BitField("AEN_Reserved", 0, 6),
        # BitField("ThermalShutdown", 0, 1),
        # BitField("PartitionLinkStatus", 0, 1),
        # BitField("RequestDataTransfer", 0, 1),
        # BitField("TransceiverEvent", 0, 1),
        # BitField("FibreChannelLinkStatus", 0, 1),
        # BitField("InfiniBandLinkStatus", 0, 1),
        # BitField("DelayedResponseReady", 0, 1),
        # BitField("HostNcDriverStatus", 0, 1),
        # BitField("ConfigurationRequired", 0, 1),
        # BitField("LinkStatusChange", 0, 1),

        # ''' DSP0222 1.1.0 AEN control '''
        XBitField("OEM", 0, 16),
        BitField("AEN_Reserved_1", 0, 13),
        BitField("HostNcDriverStatus", 0, 1),
        BitField("ConfigurationRequired", 0, 1),
        BitField("LinkStatusChange", 0, 1),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 44
class AenEnable_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 AEN Enable Response"""

    name = "AEN Enable Response"
    CommandValue = 0x88

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 45
class SetLink_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Set Link Request"""

    name = "Set Link Request"
    CommandValue = 0x09

    fields_desc = [
        # Link Settings
        # Byte 3
        BitField("SetLinkReserved_2", 0, 1),
        BitEnumField("ParallelDetect", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
        BitEnumField("LinkTraining", 0, 1, ENABLE_DISABLE),    # NC-SI 1.2
        BitEnumField("EnergyEfficientEthernet", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
        BitField("FecReserved", 0, 2),    # NC-SI 1.2
        BitField("FecRS_FEC", 0, 1),      # NC-SI 1.2
        BitField("FecBASE_R_FEC", 0, 1),  # NC-SI 1.2

        #Byte 2
        BitField("Enable_PAM_4", 0, 1),  # NC-SI 1.2
        BitField("Enable_NRZ", 0, 1),    # NC-SI 1.2
        BitField("SetLinkReserved_1", 0, 2),
        BitEnumField("Enable800Gbps", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
        BitEnumField("Enable400Gbps", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
        BitEnumField("Enable200Gbps", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
        BitEnumField("Enable5Gbps", 0, 1, ENABLE_DISABLE),

        # Byte 1
        BitEnumField("Enable2_5Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable100Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable50Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("EnableOEM", 0, 1, ENABLE_DISABLE),
        BitEnumField("EnableAsymmetricPause", 0, 1, ENABLE_DISABLE),
        BitEnumField("PauseCapability", 0, 1, {0: "Enable", 1: "Disable"}),
        BitEnumField("EnableFullDuplex", 0, 1, ENABLE_DISABLE),
        BitEnumField("EnableHalfDuplex", 0, 1, ENABLE_DISABLE),

        #  Byte 0
        BitEnumField("Enable40Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable25Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable20Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable10Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable1Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable100Mbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable10Mbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("AutoNegotiation", 0, 1, ENABLE_DISABLE),

        # OEM Link Settings
        XIntField("OEM_Settings", 0x00000000),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 48
class SetLink_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Set Link Response"""

    name = "Set Link Response"
    CommandValue = 0x89

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField(
            "ReasonCode",
            0x0000,
            {**STANDARD_REASON_CODE_VALUES, **LINK_SETTINGS_REASON_CODES},
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 50
class GetLinkStatus_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Link Status Request"""

    name = "Get Link Status Request"
    CommandValue = 0x0A

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 51
class GetLinkStatus_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Link Status Response"""

    name = "Get Link Status Response"
    CommandValue = 0x8A

    class Data(Packet):
        name = "Get Link Status Data"

        fields_desc = [
            # Link Status field
            BitEnumField(
                "ExtendedSpeedAndDuplex",
                0,
                8,
                {
                    0x00: "Auto-negotiation not complete",
                    0x01: "10BASE-T half-duplex",
                    0x02: "10BASE-T full-duplex",
                    0x03: "100BASE-TX half-duplex",
                    0x04: "100BASE-T4",
                    0x05: "100BASE-TX full-duplex",
                    0x06: "1000BASE-T half-duplex",
                    0x07: "1000BASE-T full-duplex",
                    0x08: "10G-BASE-T support or 10 Gbps",
                    0x09: "20 Gbps",
                    0x0A: "25 Gbps",
                    0x0B: "40 Gbps",
                    0x0C: "50 Gbps",
                    0x0D: "100 Gbps",
                    0x0E: "2.5 Gbps",
                    0x0F: "5 Gbps",
                    0x10: "1 Gbps (for non Base-T)",
                    0x11: "200 Gbps",
                    0x12: "400 Gbps",
                    0x13: "800 Gbps"
                },
            ),

            BitEnumField("ModulationScheme", 0, 2, {1: "NRZ", 2: "PAM-4"}),
            BitEnumField("OemLinkSpeedValid", 0, 1, VALID_NOT_VALID),
            BitEnumField("SerDesLink", 0, 1, {0: "SerDes is not used", 1: "SerDes is not used"}),
            BitEnumField(
                "LinkPartnerAdvertisedFlowControl",
                0,
                2,
                {
                    0: "Link partner is not pause capable or this is not an Ethernet link",
                    1: "Link partner supports symmetric pause",
                    2: "Link partner supports asymmetric pause toward link partner",
                    3: "Link partner supports both symmetric and asymmetric pause"
                }
            ),
            BitEnumField("RxFlowControlFlag", 0, 1, ENABLE_DISABLE),
            BitEnumField("TxFlowControlFlag", 0, 1, ENABLE_DISABLE),

            BitEnumField("LinkPartnerAdvertisedSpeedAndDuplex10THD", 0, 1, CAPABLE_NOT_CAPABLE),
            BitEnumField("LinkPartnerAdvertisedSpeedAndDuplex10TFD", 0, 1, CAPABLE_NOT_CAPABLE),
            BitEnumField("LinkPartnerAdvertisedSpeedAndDuplex100TXHD", 0, 1, CAPABLE_NOT_CAPABLE),
            BitEnumField("LinkPartnerAdvertisedSpeedAndDuplex100TXFD", 0, 1, CAPABLE_NOT_CAPABLE),
            BitEnumField("LinkPartnerAdvertisedSpeedAndDuplex100T4", 0, 1, CAPABLE_NOT_CAPABLE),
            BitEnumField("LinkPartnerAdvertisedSpeedAndDuplex1000THD", 0, 1, CAPABLE_NOT_CAPABLE),
            BitEnumField("LinkPartnerAdvertisedSpeedAndDuplex1000TFD", 0, 1, CAPABLE_NOT_CAPABLE),
            BitField("LinkStatusReserved_1", 0, 1),

            BitEnumField("ParallelDetectionFlag", 0, 1, {0: "Not used to obtain link", 1: "Used to obtain link", }),
            BitEnumField("AutoNegotiateComplete", 0, 1, COMPLETE_NOT_COMPLETE),
            BitEnumField("AutoNegotiateFlag", 0, 1, ENABLE_DISABLE),
            BitEnumField(
                "SpeedAndDuplex",
                0,
                4,
                {
                    0x00: "Auto-negotiate not complete",
                    0x01: "10BASE-T half-duplex",
                    0x02: "10BASE-T full-duplex",
                    0x03: "100BASE-TX half-duplex",
                    0x04: "100BASE-T4",
                    0x05: "100BASE-TX full-duplex",
                    0x06: "1000BASE-T half-duplex",
                    0x07: "1000BASE-T full-duplex",
                    0x08: "10G-BASE-T support or 10 Gbps",
                    0x09: "20 Gbps (optional for NC-SI 1.1, Reserved for NC-SI 1.0)",
                    0x0A: "25 Gbps (optional for NC-SI 1.1, Reserved for NC-SI 1.0)",
                    0x0B: "40 Gbps (optional for NC-SI 1.1, Reserved for NC-SI 1.0)",
                    0x0C: "50 Gbps (optional for NC-SI 1.1, Reserved for NC-SI 1.0)",
                    0x0D: "100 Gbps (optional for NC-SI 1.1, Reserved for NC-SI 1.0)",
                    0x0E: "2.5 Gbps (optional for NC-SI 1.1, Reserved for NC-SI 1.0)",
                    0x0F: "Use values defined in Extended Speed and Duplex field"
                }
            ),
            BitEnumField("LinkFlag", 0, 1, {0: "Link down", 1: "Link up"}),

            # Other Indications field
            BitField("GetLinkStatusOtherReserved_1", 0, 27),
            BitEnumField("OEMLinkStatusField", 0, 1, ENABLE_DISABLE),
            BitEnumField("ParallelDetect", 0, 1, ENABLE_DISABLE),
            BitEnumField("LinkTraining", 0, 1, ENABLE_DISABLE),
            BitEnumField("EnergyEfficientEthernet", 0, 1, ENABLE_DISABLE),
            BitEnumField("HostDriverStatusIndication", 0, 1, {0: "Not Operational", 1: "Operational"}),

            # OEM Link Status
            XIntField("OemLinkStatus", 0x00000000),
        ]

        def extract_padding(self, s):
            return ("", s)


    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField(
            "ReasonCode",
            0x0000,
            {
                **STANDARD_REASON_CODE_VALUES,
                0x0A06: "Link Command FailedHardware Access Error",
            },
        ),
        ConditionalField(
            PacketField("LinkStatus", Data(), Data),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 57
class SetVlanFilter_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Set VLAN Filter Request"""

    name = "Set VLAN Filter Request"
    CommandValue = 0x0B

    fields_desc = [
        # Word 1
        XShortField("SetVlanFilterReserved_1", 0x0000),
        BitField("Priority", 0, 3),
        BitField("CFI", 0, 1),
        BitField("VlanId", 0, 12),

        # Word 2
        XShortField("SetVlanFilterReserved_2", 0x0000),
        ByteField("FilterSelector", 0),
        BitField("SetVlanFilterReserved_3", 0, 7),
        BitField("Enable", 0, 1),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 60
class SetVlanFilter_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Set VLAN Filter Response"""

    name = "Set VLAN Filter Response"
    CommandValue = 0x8B

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField(
            "ReasonCode",
            0x0000,
            {
                **STANDARD_REASON_CODE_VALUES,
                0x0B07: "Returned when the VLAN ID is invalid (VLAN ID = 0)",
            },
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 62
class EnableVlan_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable VLAN Request"""

    name = "Enable VLAN Request"
    CommandValue = 0x0C

    fields_desc = [
        X3BytesField("EnableVlanReserved_1", 0x00),
        XByteEnumField(
            "Mode",
            0x00,
            {
                0x00: "Reserved",
                0x01: "VlanOnly",
                0x02: "VlanAndNonVLAN",
                0x03: "AnyVlanAndNonVlan",
            },
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 64
class EnableVlan_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable VLAN Response"""

    name = "Enable VLAN Response"
    CommandValue = 0x8C

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 65
class DisableVlan_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 DisableVLAN Request"""

    name = "Disable VLAN Request"
    CommandValue = 0x0D

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 66
class DisableVlan_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Disable VLAN Response"""

    name = "Disable VLAN Response"
    CommandValue = 0x8D

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 17
class AEN(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Asynchronous Event Notification"""

    name = "Asynchronous Event Notification"
    CommandValue = 0xFF

    fields_desc = [
        X3BytesField("AenReserved_1", 0x000000),
        XShortField("AenType", 0x00),
        XIntField("OptionalAenData", 0x00),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 67
class SetMACAddress_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Set MAC Address Request"""

    name = "Set MAC Address Request"
    CommandValue = 0x0E

    fields_desc = [
        # Word 1
        XByteField("MACAddress_5", 0x00),
        XByteField("MACAddress_4", 0x00),
        XByteField("MACAddress_3", 0x00),
        XByteField("MACAddress_2", 0x00),

        # Word 2
        XByteField("MACAddress_1", 0x00),
        XByteField("MACAddress_0", 0x00),
        XByteField("MACAddressNum", 0x00),
        BitEnumField("AddressType", 0, 3, {0: "Unicast MAC Address", 1: "Multicast MAC address"}),
        BitField("Reserved", 0, 4),
        BitEnumField(
            "Enable",
            0,
            1,
            {0: "Disable this MAC address filter", 1: "Enable this MAC address filter"},
        ),

        # PAD and Checksum and PAD Fields
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 71
class SetMACAddress_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Set MAC Address Response"""

    name = "Set MAC Address Response"
    CommandValue = 0x8E

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField(
            "ReasonCode",
            0x0000,
            {
                **STANDARD_REASON_CODE_VALUES,
                0x0E08: "Returned when the Set MAC Address command is received with the MAC address set to 0",
            },
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 73
class EnableBroadcastFilter_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable Broadcast Filter Request"""

    name = "Enable Broadcast Filter Request"
    CommandValue = 0x10

    fields_desc = [
        # Broadcast Packet Filter Settings
        BitField("Reserved", 0, 28),
        BitEnumField(
            "NetBIOSPackets", 0, 1, FORWARD_FILTER_OUT
        ),  # optional field (0 if unsupported)
        BitEnumField(
            "DHCPServerPackets", 0, 1, FORWARD_FILTER_OUT
        ),  # optional field (0 if unsupported)
        BitEnumField(
            "DHCPClientPackets", 0, 1, FORWARD_FILTER_OUT
        ),  # optional field (0 if unsupported)
        BitEnumField("ARPPackets", 0, 1, FORWARD_FILTER_OUT),  # mandatory field

        # Insert PAD and Checksum Fields
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 75
class EnableBroadcastFilter_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable Broadcast Filter Response"""

    name = "Enable Broadcast Filter Response"
    CommandValue = 0x90

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 87
class GetVersionID_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Version ID Request"""

    name = "Get Version ID Request"
    CommandValue = 0x15

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 88
class GetVersionID_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Version ID Response"""

    name = "Get Version ID Response"
    CommandValue = 0x95

    class Data(Packet):
        name = "Get Version ID Data"

        fields_desc = [
            XByteField("NCSIVersionMajor", 0x00),
            XByteField("NCSIVersionMinor", 0x00),
            XByteField("NCSIVersionUpdate", 0x00),
            XByteField("NCSIVersionAlpha1", 0x00),

            X3BytesField("Reserved", 0x000000),
            XByteField("NCSIVersionAlpha2", 0x00),

            StrLenField("FirmwareNameString11_08", b"", length_from=lambda unused: 4),

            StrLenField("FirmwareNameString07_04", b"", length_from=lambda unused: 4),

            StrLenField("FirmwareNameString03_00", b"", length_from=lambda unused: 4),

            XByteField("FirmwareVersionByte3", 0x00),
            XByteField("FirmwareVersionByte2", 0x00),
            XByteField("FirmwareVersionByte1", 0x00),
            XByteField("FirmwareVersionByte0", 0x00),

            XShortField("PCIDID", 0x0000),
            XShortField("PCIVID", 0x0000),

            XShortField("PCISSID", 0x0000),
            XShortField("PCISVID", 0x0000),

            XIntField("ManufacturerID", 0xFFFFFFFF)     # 0xFFFFFFFF if unused
        ]

        def extract_padding(self, s):
            return ("", s)


    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            PacketField("VersionInfo", Data(), Data),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 89
class GetCapabilities_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Capabilities Request"""

    name = "Get Capabilities Request"
    CommandValue = 0x16

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 90
class GetCapabilities_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Capabilities Response"""

    name = "Get Capabilities Response"
    CommandValue = 0x96

    class Data(Packet):
        """Get Capabilities Response Data"""

        name = "Get Capabilities Response Data"
        fields_desc = [

            # Capabilities Flags
            BitField("Reserved_1", 0, 23),
            BitEnumField("DelayedResponseSupport", 0, 1, SUPPORTED_NOT_SUPPORTED),
            BitEnumField("ThermalShutdownImplementationStatus", 0, 1, SUPPORTED_NOT_SUPPORTED),
            BitEnumField(
                "HardwareArbitrationImplementationStatus",
                0,
                2,
                {
                    0x00: "Unknown",
                    0x01: "Hardware arbitration capability is not implemented for the package on the given system",
                    0x10: "Hardware arbitration capability is implemented for the package on the given system",
                },
            ),
            BitEnumField(
                "AllMulticastAddressesSupport", 0, 1, SUPPORTED_NOT_SUPPORTED
            ),
            BitEnumField(
                "ManagementControllerToNetworkControllerFlowControlSupport",
                0,
                1,
                SUPPORTED_NOT_SUPPORTED,
            ),
            BitEnumField(
                "NetworkControllerToManagementControllerFlowControlSupport",
                0,
                1,
                SUPPORTED_NOT_SUPPORTED,
            ),
            BitEnumField("HostNCDriverStatus", 0, 1, SUPPORTED_NOT_SUPPORTED),
            BitEnumField("HardwareArbitrationCapability", 0, 1, SUPPORTED_NOT_SUPPORTED),

            # Broadcast Packet Filter Capabilities
            BitField("Reserved_2", 0, 28),
            BitEnumField(
                "NetBIOSPackets", 0, 1, FORWARD_FILTER_OUT
            ),  # optional field (0 if unsupported)
            BitEnumField(
                "DHCPServerPackets", 0, 1, FORWARD_FILTER_OUT
            ),  # optional field (0 if unsupported)
            BitEnumField(
                "DHCPClientPackets", 0, 1, FORWARD_FILTER_OUT
            ),  # optional field (0 if unsupported)
            BitEnumField("ARPPackets", 0, 1, FORWARD_FILTER_OUT),  # mandatory field

            # Multicast Packet Filter Capabilities
            BitField("Reserved_3", 0, 26),
            BitEnumField(
                "IPv6NeighborSolicitation", 0, 1, FORWARD_FILTER_OUT
            ),  # optional field
            BitEnumField("IPv6MLD", 0, 1, FORWARD_FILTER_OUT),  # optional field
            BitEnumField(
                "DHCPv6MulticastsFromServerToClientsListeningOnWellknownUDPPorts",
                0,
                1,
                FORWARD_FILTER_OUT,
            ),
            # optional field
            BitEnumField(
                "DHCPv6RelayAndServerMulticast", 0, 1, FORWARD_FILTER_OUT
            ),  # optional field
            BitEnumField(
                "IPv6RouterAdvertisement", 0, 1, FORWARD_FILTER_OUT
            ),  # optional field
            BitEnumField(
                "IPv6NeighborAdvertisement", 0, 1, FORWARD_FILTER_OUT
            ),  # optional field
            XIntField("BufferingCapability", 0x00000000),

            # AEN Control Support
            BitField("OEMSpecificAENControl", 0, 16),
            BitField("Reserved_4", 0, 13),
            BitEnumField("HostNCDriverStatusChangeAENControl", 0, 1, ENABLE_DISABLE),
            BitEnumField("ConfigurationRequiredAENControl", 0, 1, ENABLE_DISABLE),
            BitEnumField("LinkStatusChangeAENControl", 0, 1, ENABLE_DISABLE),

            XByteField("VLANFilterCount", 0x00),
            XByteField("MixedFilterCount", 0x00),
            XByteField("MulticastFilterCount", 0x00),
            XByteField("UnicastFilterCount", 0x00),
            XShortField("Reserved_5", 0x0000),
            BitField("Reserved_6", 0, 5),
            BitField("AnyVLAN_NonVLAN", 0, 1),
            BitField("VLAN_NonVLAN", 0, 1),
            BitField("VLANOnly", 1, 1),
            XByteField("ChannelCount", 0x00)
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            PacketField("Capabilities", Data(), Data),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 93
class GetParameters_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Parameters Request"""

    name = "Get Parameters Request"
    CommandValue = 0x17

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


class VLANTags(Packet):
    """VLAN Tags"""

    name = "VLAN Tags"

    fields_desc = [
        XShortField("VlanTag", 0x0000)
    ]

    def extract_padding(self, s):
        return "", s


# DSP0222 -  Table 94
class GetParameters_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Parameters Response"""

    name = "Get Parameters Response"
    CommandValue = 0x97

    class Data(Packet):
        fields_desc = [
            XByteField("MACAddressCount", 0x00),
            XShortField("Reserved_1", 0x0000),
            BitField("MACAddressFlags", 0, 8),  # Table 91 DSP0222

            XByteField("VLANTagCount", 0x00),
            XByteField("Reserved_2", 0x00),
            BitField("VLANTagFlags", 0, 16),    # Table 92 DSP0222

            # Link Settings

            # Byte 3
            BitField("SetLinkReserved_2", 0, 1),
            BitEnumField("ParallelDetect", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
            BitEnumField("LinkTraining", 0, 1, ENABLE_DISABLE),    # NC-SI 1.2
            BitEnumField("EnergyEfficientEthernet", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
            BitField("FecReserved", 0, 2),    # NC-SI 1.2
            BitField("FecRS_FEC", 0, 1),      # NC-SI 1.2
            BitField("FecBASE_R_FEC", 0, 1),  # NC-SI 1.2

            #Byte 2
            BitField("Enable_PAM_4", 0, 1),  # NC-SI 1.2
            BitField("Enable_NRZ", 0, 1),    # NC-SI 1.2
            BitField("SetLinkReserved_1", 0, 2),
            BitEnumField("Enable800Gbps", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
            BitEnumField("Enable400Gbps", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
            BitEnumField("Enable200Gbps", 0, 1, ENABLE_DISABLE),  # NC-SI 1.2
            BitEnumField("Enable5Gbps", 0, 1, ENABLE_DISABLE),

            # Byte 1
            BitEnumField("Enable2_5Gbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("Enable100Gbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("Enable50Gbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("EnableOEM", 0, 1, ENABLE_DISABLE),
            BitEnumField("EnableAsymmetricPause", 0, 1, ENABLE_DISABLE),
            BitEnumField("PauseCapability", 0, 1, {0: "Enable", 1: "Disable"}),
            BitEnumField("EnableFullDuplex", 0, 1, ENABLE_DISABLE),
            BitEnumField("EnableHalfDuplex", 0, 1, ENABLE_DISABLE),

            #  Byte 0
            BitEnumField("Enable40Gbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("Enable25Gbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("Enable20Gbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("Enable10Gbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("Enable1Gbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("Enable100Mbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("Enable10Mbps", 0, 1, ENABLE_DISABLE),
            BitEnumField("AutoNegotiation", 0, 1, ENABLE_DISABLE),

            XIntField("BroadcastPacketFilterSettings", 0x00000000),

            BitField("Reserved_3", 0, 28),
            BitEnumField("GlobalMulticastPacketFilterStatus", 0, 1, ENABLE_DISABLE),
            BitEnumField("ChannelNetworkTXEnabled", 0, 1, ENABLE_DISABLE),
            BitEnumField("ChannelEnabled", 0, 1, ENABLE_DISABLE),
            BitEnumField("BroadcastPacketFilterStatus", 0, 1, ENABLE_DISABLE),
            XByteEnumField(
                "Mode",
                0x00,
                {
                    0x00: "Reserved",
                    0x01: "VlanOnly",
                    0x02: "VlanAndNonVLAN",
                    0x03: "AnyVlanAndNonVlan",
                },
            ),
            BitEnumField(
                "FlowControlEnable",
                0,
                8,
                {
                    0: "Disables NC-SI flow control",
                    1: "Enables Network Controller to Management Controller flow control frames",
                    2: "Enables Management Controller to Network Controller flow control frames",
                    3: "Enables bi-directional flow control frames",
                },
            ),
            XShortField("Reserved_4", 0x0000),

            # DSP0222_1.2.0 Format AEN control
            # BitField("OEMSpecificAENControl", 0, 16),
            # BitField("Reserved_5", 0, 11),
            # BitEnumField("TransceiverEventAENControl", 0, 1, ENABLE_DISABLE),
            # BitEnumField("DelayedResponseReadyAENControl", 0, 1, ENABLE_DISABLE),
            # BitEnumField("HostNCDriverStatusChangeAENControl", 0, 1, ENABLE_DISABLE),
            # BitEnumField("ConfigurationRequiredAENControl", 0, 1, ENABLE_DISABLE),
            # BitEnumField("LinkStatusChangeAENControl", 0, 1, ENABLE_DISABLE),

            # DSP0222_1.1.0 Format AEN control
            BitField("OEMSpecificAENControl", 0, 16),
            BitField("Reserved_5", 0, 13),
            BitEnumField("HostNCDriverStatusChangeAENControl", 0, 1, ENABLE_DISABLE),
            BitEnumField("ConfigurationRequiredAENControl", 0, 1, ENABLE_DISABLE),
            BitEnumField("LinkStatusChangeAENControl", 0, 1, ENABLE_DISABLE),

            XByteField("MACAddress1_5", 0x00),
            XByteField("MACAddress1_4", 0x00),
            XByteField("MACAddress1_3", 0x00),
            XByteField("MACAddress1_2", 0x00),
            XByteField("MACAddress1_1", 0x00),
            XByteField("MACAddress1_0", 0x00),

            XByteField("MACAddress2_5", 0x00),
            XByteField("MACAddress2_4", 0x00),
            XByteField("MACAddress2_3", 0x00),
            XByteField("MACAddress2_2", 0x00),
            XByteField("MACAddress2_1", 0x00),
            XByteField("MACAddress2_0", 0x00),

            PacketListField(
                "VlanTagsFields",
                VLANTags(),
                VLANTags,
                count_from=lambda pkt: pkt.VLANTagCount,
            )
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            PacketField("Parameters", Data(), Data),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 99
class GetControllerPacketStatistics_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Controller Packet Statistics Request"""

    name = "Get Controller Packet Statistics Request"
    CommandValue = 0x18

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 100
class GetControllerPacketStatistics_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Controller Packet Statistics Response"""

    name = "Get Controller Packet Statistics Response"
    CommandValue = 0x98

    class Data(Packet):
        fields_desc = [
            XLongField("CountersClearedFromLastRead", 0x0000000000000000),
            XLongField("TotalBytesReceived", 0x0000000000000000),
            XLongField("TotalBytesTransmitted", 0x0000000000000000),
            XLongField("TotalUnicastPacketsReceived", 0x0000000000000000),
            XLongField("TotalMulticastPacketsReceived", 0x0000000000000000),
            XLongField("TotalBroadcastPacketsReceived", 0x0000000000000000),
            XLongField("TotalUnicastPacketsTransmitted", 0x0000000000000000),
            XLongField("TotalMulticastPacketsTransmitted", 0x0000000000000000),
            XLongField("TotalBroadcastPacketsTransmitted", 0x0000000000000000),
            XIntField("FCSReceiveErrors", 0x00000000),
            XIntField("AlignmentErrors", 0x00000000),
            XIntField("FalseCarrierDetections", 0x00000000),
            XIntField("RuntPacketsReceived", 0x00000000),
            XIntField("JabberPacketsReceived", 0x00000000),
            XIntField("PauseXONFramesReceived", 0x00000000),
            XIntField("PauseXOFFFramesReceived", 0x00000000),
            XIntField("PauseXONFramesTransmitted", 0x00000000),
            XIntField("PauseXOFFFramesTransmitted", 0x00000000),
            XIntField("SingleCollisionTransmitFrames", 0x00000000),
            XIntField("MultipleCollisionTransmitFrames", 0x00000000),
            XIntField("LateCollisionFrames", 0x00000000),
            XIntField("ExcessiveCollisionFrames", 0x00000000),
            XIntField("ControlFramesReceived", 0x00000000),
            XIntField("_64_ByteFramesReceived", 0x00000000),
            XIntField("_65_127ByteFramesReceived", 0x00000000),
            XIntField("_128_255ByteFramesReceived", 0x00000000),
            XIntField("_256_511ByteFramesReceived", 0x00000000),
            XIntField("_512_1023ByteFramesReceived", 0x00000000),
            XIntField("_1024_1522ByteFramesReceived", 0x00000000),
            XIntField("_1523_9022ByteFramesReceived", 0x00000000),
            XIntField("_64_ByteFramesTransmitted", 0x00000000),
            XIntField("_65_127ByteFramesTransmitted", 0x00000000),
            XIntField("_128_255ByteFramesTransmitted", 0x00000000),
            XIntField("_256_511ByteFramesTransmitted", 0x00000000),
            XIntField("_512_1023ByteFramesTransmitted", 0x00000000),
            XIntField("_1024_1522ByteFramesTransmitted", 0x00000000),
            XIntField("_1523_9022ByteFramesTransmitted", 0x00000000),
            XLongField("ValidBytesReceived", 0x0000000000000000),
            XIntField("ErrorRuntPacketsReceived", 0x00000000),
            XIntField("ErrorJabberPacketsReceived", 0x00000000),
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            PacketField("Statistics", Data(), Data),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 103
class GetNCSIStatistics_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get NC-SI Statistics Request"""

    name = "Get NC-SI Statistics Request"
    CommandValue = 0x19

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 104
class GetNCSIStatistics_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get NC-SI Statistics Response"""

    name = "Get NC-SI Statistics Response"
    CommandValue = 0x99

    class Data(Packet):
        fields_desc = [
            XIntField("NCSICommandsReceived", 0x00000000),
            XIntField("NCSIControlPacketsDropped", 0x00000000),
            XIntField("NCSICommandTypeErrors", 0x00000000),
            XIntField("NCSICommandChecksumErrors", 0x00000000),
            XIntField("NCSIReceivePackets", 0x00000000),
            XIntField("NCSITransmitPackets", 0x00000000),
            XIntField("AENsSent", 0x00000000)
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            PacketField("Statistics", Data(), Data),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 276
class PendingPLDMRequestAEN_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Pending PLDM Request AEN Request"""

    name = "Pending PLDM Request AEN Request"
    CommandValue = 0xFF

    fields_desc = [
        X3BytesField("Reserved", 0x000000),
        XByteField("AENType", 0x71),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 76
class DisableBroadcastFilter_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Disable Broadcast Filter Request"""

    name = "Disable Broadcast Filter Request"
    CommandValue = 0x11

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 77
class DisableBroadcastFilter_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Disable Broadcast Filter Response"""

    name = "Disable Broadcast Filter Response"
    CommandValue = 0x91

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 78
class EnableGlobalMulticastFilter_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable Global Multicast Filter Request"""

    name = "Enable Global Multicast Filter Request"
    CommandValue = 0x12

    fields_desc = [
        BitField("Reserved", 0, 23),
        BitEnumField("mDNSv6", 0, 1, FORWARD_FILTER_OUT),
        BitEnumField("mDNSv4", 0, 1, FORWARD_FILTER_OUT),
        BitEnumField("LLDP", 0, 1, FORWARD_FILTER_OUT),
        BitEnumField("IPv6NeighborSolicitation", 0, 1, FORWARD_FILTER_OUT),
        BitEnumField("IPv6MLD", 0, 1, FORWARD_FILTER_OUT),
        BitEnumField(
            "DHCPv6MulticastsFromServerToClientsListeningOnWellKnownUDPPorts",
            0,
            1,
            FORWARD_FILTER_OUT,
        ),
        BitEnumField("DHCPv6RelayAndServerMulticast", 0, 1, FORWARD_FILTER_OUT),
        BitEnumField("IPv6RouterAdvertisement", 0, 1, FORWARD_FILTER_OUT),
        BitEnumField("IPv6NeighborAdvertisement", 0, 1, FORWARD_FILTER_OUT),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 80
class EnableGlobalMulticastFilter_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Enable Global Multicast Filter Response"""

    name = "Enable Global Multicast Filter Response"
    CommandValue = 0x92

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 81
class DisableGlobalMulticastFilter_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Disable Global Multicast Filter Request"""

    name = "Disable Global Multicast Filter Request"
    CommandValue = 0x13

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 82
class DisableGlobalMulticastFilter_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Disable Global Multicast Filter Response"""

    name = "Disable Global Multicast Filter Response"
    CommandValue = 0x93

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 83
class SetNCSIFlowControl_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Set NC-SI Flow Control Request"""

    name = "Set NC-SI Flow Control Request"
    CommandValue = 0x14

    fields_desc = [
        X3BytesField("Reserved", 0x000000),
        XByteEnumField(
            "FlowControlEnable",
            0x00,
            {
                0x00: "Disables NC-SI flow control",
                0x01: "Enables Network Controller to Management Controller flow control frames",
                0x02: "Enables Management Controller to Network Controller flow control frames",
                0x03: "Enables bi-directional flow control frames",
            },
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 85
class SetNCSIFlowControl_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Set NC-SI Flow Control Response"""

    name = "Set NC-SI Flow Control Response"
    CommandValue = 0x94

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField(
            "ReasonCode",
            0x0000,
            {
                **STANDARD_REASON_CODE_VALUES,
                0x1409: "Independent transmit and receive enable/disable control is not supported",
            },
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 106
class GetNCSIPassthroughStatistics_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get NC-SI Pass-through Statistics Request"""

    name = "Get NC-SI Pass-through Statistics Request"
    CommandValue = 0x1A

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 107
class GetNCSIPassthroughStatistics_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get NC-SI Pass-through Statistics Response"""

    name = "Get NC-SI Pass-through Statistics Response"
    CommandValue = 0x9A

    class NCSIPassthroughStatistics(Packet):
        name = "NS-SI Pass-through Statistics"

        fields_desc = [
                XLongField("TotalPassthroughTXPacketsReceived", 0x0000000000000000),
                XIntField("TotalPassthroughTXPacketsDropped", 0x00000000),
                XIntField("PassthroughTXPacketChannelStateErrors", 0x00000000),
                XIntField("PassthroughTXPacketUndersizedErrors", 0x00000000),
                XIntField("PassthroughTXPacketOversizedErrors", 0x00000000),
                XIntField("TotalPassthroughRXPacketsReceivedOnTheLANInterface", 0x00000000),
                XIntField("TotalPassthroughRXPacketsDropped", 0x00000000),
                XIntField("PassthroughRXPacketChannelStateErrors", 0x00000000),
                XIntField("PassthroughRXPacketUndersizedErrors", 0x00000000),
                XIntField("PassthroughRXPacketOversizedErrors", 0x00000000),

                NcsiReversePadField(XIntField("Checksum", None), 4)
        ]

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            PacketField("Stats", NCSIPassthroughStatistics(), NCSIPassthroughStatistics),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        ConditionalField(
            NcsiReversePadField(XIntField("Checksum", None), 4),
            lambda pkt: pkt.ResponseCode != 0x0000 or pkt.ReasonCode != 0x0000
        )
    ]


# DSP0222 -  Table 108
class GetPackageStatus_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Get Package Status Request"""

    name = "Get Package Status Request"
    CommandValue = 0x1B

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 110
class GetPackageStatus_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Package Status Response"""

    name = "Get Package Status Response"
    CommandValue = 0x9B

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            BitField("Reserved", 0, 30),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            BitEnumField("DelayedResponseStatus", 0, 1, ENABLE_DISABLE),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            BitEnumField("HardwareArbitrationStatus", 0, 1, SUPPORTED_NOT_SUPPORTED),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


class UnsupportedNcsi_Request(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Test Unsupported NCSI Command Request"""

    name = "Test Unsupported NCSI Command Request"
    CommandValue = 0x72

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


class UnsupportedNcsi_Response(NCSI_PAYLOAD):
    """DSP0222 v1.1.0 Test Unsupported NCSI Command Response"""

    name = "Test Unsupported NCSI Command Response"
    CommandValue = 0xf2

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# Register classes for auto lookup
register_ncsi_class(ClearInitialState_Request)
register_ncsi_class(ClearInitialState_Response)
register_ncsi_class(SelectPackage_Request)
register_ncsi_class(SelectPackage_Response)
register_ncsi_class(DeselectPackage_Request)
register_ncsi_class(DeselectPackage_Response)
register_ncsi_class(EnableChannel_Request)
register_ncsi_class(EnableChannel_Response)
register_ncsi_class(DisableChannel_Request)
register_ncsi_class(DisableChannel_Response)
register_ncsi_class(ResetChannel_Request)
register_ncsi_class(ResetChannel_Response)
register_ncsi_class(EnableChannelNetworkTx_Request)
register_ncsi_class(EnableChannelNetworkTx_Response)
register_ncsi_class(DisableChannelNetworkTx_Request)
register_ncsi_class(DisableChannelNetworkTx_Response)
register_ncsi_class(AenEnable_Request)
register_ncsi_class(AenEnable_Response)
register_ncsi_class(SetLink_Request)
register_ncsi_class(SetLink_Response)
register_ncsi_class(GetLinkStatus_Request)
register_ncsi_class(GetLinkStatus_Response)
register_ncsi_class(SetVlanFilter_Request)
register_ncsi_class(SetVlanFilter_Response)
register_ncsi_class(EnableVlan_Request)
register_ncsi_class(EnableVlan_Response)
register_ncsi_class(DisableVlan_Request)
register_ncsi_class(DisableVlan_Response)
register_ncsi_class(SetMACAddress_Request)
register_ncsi_class(SetMACAddress_Response)
register_ncsi_class(EnableBroadcastFilter_Request)
register_ncsi_class(EnableBroadcastFilter_Response)
register_ncsi_class(DisableBroadcastFilter_Request)
register_ncsi_class(DisableBroadcastFilter_Response)
register_ncsi_class(EnableGlobalMulticastFilter_Request)
register_ncsi_class(EnableGlobalMulticastFilter_Response)
register_ncsi_class(DisableGlobalMulticastFilter_Request)
register_ncsi_class(DisableGlobalMulticastFilter_Response)
register_ncsi_class(SetNCSIFlowControl_Request)
register_ncsi_class(SetNCSIFlowControl_Response)
register_ncsi_class(GetVersionID_Request)
register_ncsi_class(GetVersionID_Response)
register_ncsi_class(GetCapabilities_Request)
register_ncsi_class(GetCapabilities_Response)
register_ncsi_class(GetParameters_Request)
register_ncsi_class(GetParameters_Response)
register_ncsi_class(GetControllerPacketStatistics_Request)
register_ncsi_class(GetControllerPacketStatistics_Response)
register_ncsi_class(GetNCSIStatistics_Request)
register_ncsi_class(GetNCSIStatistics_Response)
register_ncsi_class(GetNCSIPassthroughStatistics_Request)
register_ncsi_class(GetNCSIPassthroughStatistics_Response)
register_ncsi_class(GetPackageStatus_Request)
register_ncsi_class(GetPackageStatus_Response)
register_ncsi_class(UnsupportedNcsi_Request)
register_ncsi_class(UnsupportedNcsi_Response)
register_ncsi_class(AEN)

# SCAPY bind layers
bind_layers(NCSI_HEADER, NCSI_PAYLOAD)
