##############################################################################
#  File Abstract:
#  Contains all of the base NC-SI protocol functionality as well as the
#  DMTF defined commands. OEM commands are in separate files.
##############################################################################

import struct
from scapy.all import *     # pylint: disable=unused-import, unused-wildcard-import
from scapy.fields import *  # pylint: disable=unused-import, unused-wildcard-import
from scapy.packet import Packet
from ncsi.dmtf_enums import *  # pylint: disable=unused-import, unused-wildcard-import


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


# DSP0222 - Table 260
class NCSI_UUID(Packet):
    """this is the NC-SI format, per DSP0222"""

    name = "UUID"
    UUID_NODE_LEN = 6

    fields_desc = [
        XLEIntField("TimeLow", 0x00000000),
        XLEShortField("TimeMid", 0x0000),
        XLEShortField("TimeHighAndVersion", 0x0000),
        XLEShortField("ClockSeqAndReserved", 0x0000),
        scapy.layers.l2.DestMACField(
            "Node"
        ),  # it may not be a MAC, but is 6 bytes, so this works well
    ]

    def extract_padding(self, s):
        return (
            "",
            s,
        )  # this has no padding, but may have something following it (like an array of things, so override behavior)


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
    such as Intel OEM commands, in which case the payload.packet_len field
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

        return s + struct.pack("%is" % (self.padlen(len(s),pkt)), self._padwith) + sval
### mrd        return s + struct.pack("%is" % (self.padlen(len(s))), self._padwith) + sval


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

    fields_desc = []  # TODO Can I remove this?

    def getChecksumLen(self):
        """Checksum length is always 4 except for old Intel OEM"""
        return 4


""" ------------------- NC-SI Commands ------------------- """

# DSP0222 - Table 25
class ClearInitialState_Request(NCSI_PAYLOAD):
    name = "Clear Initial State Request"
    CommandValue = 0x00

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)  # Inserts PAD and Checksum Fields
    ]


# DSP0222 - Table 26
class ClearInitialState_Response(NCSI_PAYLOAD):
    name = "Clear Initial State Response"
    CommandValue = 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 27
class SelectPackage_Request(NCSI_PAYLOAD):
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
    name = "Select Package Response"
    CommandValue = 0x81

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 30
class DeselectPackage_Request(NCSI_PAYLOAD):
    name = "Deselect Package Request"
    CommandValue = 0x02

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 31
class DeselectPackage_Response(NCSI_PAYLOAD):
    name = "Deselect Package Response"
    CommandValue = 0x82

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  32
class EnableChannel_Request(NCSI_PAYLOAD):
    name = "Enable Channel Request"
    CommandValue = 0x03

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 33
class EnableChannel_Response(NCSI_PAYLOAD):
    name = "Enable Channel Response"
    CommandValue = 0x83

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 34
class DisableChannel_Request(NCSI_PAYLOAD):
    name = "Disable Channel Request"
    CommandValue = 0x04

    fields_desc = [
        BitField("Reserved", 0, 31),
        BitField("ALD", 0, 1),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 35
class DisableChannel_Response(NCSI_PAYLOAD):
    name = "Disable Channel Response"
    CommandValue = 0x84

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 37
class ResetChannel_Request(NCSI_PAYLOAD):
    name = "Reset Channel Request"
    CommandValue = 0x05

    fields_desc = [
        XIntField("Reserved", 0x00000000),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 37
class ResetChannel_Response(NCSI_PAYLOAD):
    name = "Reset Channel Response"
    CommandValue = 0x85

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 38
class EnableChannelNetworkTx_Request(NCSI_PAYLOAD):
    name = "Enable Channel Network TX Request"
    CommandValue = 0x06

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 39
class EnableChannelNetworkTx_Response(NCSI_PAYLOAD):
    name = "Enable Channel Network TX Response"
    CommandValue = 0x86

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 40
class DisableChannelNetworkTx_Request(NCSI_PAYLOAD):
    name = "Disable Channel Network TX Request"
    CommandValue = 0x07

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 41
class DisableChannelNetworkTx_Response(NCSI_PAYLOAD):
    name = "Disable Channel Network TX Response"
    CommandValue = 0x87

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 42
class AenEnable_Request(NCSI_PAYLOAD):
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
    name = "AEN Enable Response"
    CommandValue = 0x88

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 45
class SetLink_Request(NCSI_PAYLOAD):
    name = "Set Link Request"
    CommandValue = 0x09

    fields_desc = [
        # Link Settings
        # Byte 3
        BitField("SetLinkReserved_2", 0, 1),
        BitEnumField("ParallelDetect", 0, 1, ENABLE_DISABLE),  # optional for NC-SI 1.2
        BitEnumField("LinkTraining", 0, 1, ENABLE_DISABLE),  # optional for NC-SI 1.2
        BitEnumField(
            "EnergyEfficientEthernet", 0, 1, ENABLE_DISABLE
        ),  # optional for NC-SI 1.2

        # Byte 2
        BitField("FecAlgorithm", 0, 4),  # optional for NC-SI 1.2
        BitField("ModulationScheme", 0, 2),  # optional for NC-SI 1.2
        BitField("SetLinkReserved_1", 0, 2),
        BitEnumField("Enable800Gbps", 0, 1, ENABLE_DISABLE),  # optional for NC-SI 1.2
        BitEnumField("Enable400Gbps", 0, 1, ENABLE_DISABLE),  # optional for NC-SI 1.2
        BitEnumField("Enable200Gbps", 0, 1, ENABLE_DISABLE),  # optional for NC-SI 1.2
        BitEnumField("Enable5Gbps", 0, 1, ENABLE_DISABLE),

        # Byte 1
        BitEnumField("Enable2_5Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable100Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("Enable50Gbps", 0, 1, ENABLE_DISABLE),
        BitEnumField("EnableOEM", 0, 1, ENABLE_DISABLE),
        BitEnumField("EnableAsymmetricPause", 0, 1, ENABLE_DISABLE),
        BitEnumField("EnablePause", 0, 1, {0: "Enable", 1: "Disable"}),
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

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 48
class SetLink_Response(NCSI_PAYLOAD):
    name = "Set Link Response"
    CommandValue = 0x89

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField(
            "ReasonCode",
            0x0000,
            {**STANDARD_REASON_CODE_VALUES, **LINK_SETTINGS_REASON_CODES},
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 50
class GetLinkStatus_Request(NCSI_PAYLOAD):
    name = "Get Link Status Request"
    CommandValue = 0x0A

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 51
class GetLinkStatus_Response(NCSI_PAYLOAD):
    name = "Get Link Status Response"
    CommandValue = 0x8A

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

        # Link Status field
        BitField("ExtendedSpeedAndDuplex", 0, 8),
        BitField("ModulationScheme", 0, 2),  # for NC-SI 1.2
        BitField("OemLinkSpeedValid", 0, 1),
        BitField("SerDesLink", 0, 1),
        BitField("LinkPartnerAdvertisedFlowControl", 0, 2),
        BitField("RxFlowControlFlag", 0, 1),
        BitField("TxFlowControlFlag", 0, 1),  # bit 16
        BitField("LinkPartnerAdvertisedSpeedAndDuplex10THD", 0, 1),
        BitField("LinkPartnerAdvertisedSpeedAndDuplex10TFD", 0, 1),
        BitField("LinkPartnerAdvertisedSpeedAndDuplex100TXHD", 0, 1),
        BitField("LinkPartnerAdvertisedSpeedAndDuplex100TXFD", 0, 1),
        BitField("LinkPartnerAdvertisedSpeedAndDuplex100T4", 0, 1),
        BitField("LinkPartnerAdvertisedSpeedAndDuplex1000THD", 0, 1),
        BitField("LinkPartnerAdvertisedSpeedAndDuplex1000TFD", 0, 1),
        BitField("LinkStatusReserved_1", 0, 1),  # bit 8
        BitField("ParallelDetectionFlag", 0, 1),
        BitField("AutoNegotiateComplete", 0, 1),
        BitEnumField("AutoNegotiateFlag", 0, 1, ENABLE_DISABLE),
        BitField("SpeedAndDuplex", 0, 4),
        BitField("LinkFlag", 0, 1),

        # Other Indications field
        BitField("GetLinkStatusOtherReserved_1", 0, 28),
        BitEnumField("ParallelDetect", 0, 1, ENABLE_DISABLE),
        BitEnumField("LinkTraining", 0, 1, ENABLE_DISABLE),
        BitEnumField("EnergyEfficientEthernet", 0, 1, ENABLE_DISABLE),
        BitField("HostDriverStatusIndication", 0, 1),

        # OEM Link Status
        XIntField("OemLinkStatus", 0x00000000),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 57
class SetVlanFilter_Request(NCSI_PAYLOAD):
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
    name = "Enable VLAN Response"
    CommandValue = 0x8C

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
   ]


# DSP0222 -  Table 65
class DisableVlan_Request(NCSI_PAYLOAD):
    name = "Disable Request"
    CommandValue = 0x0D

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 66
class DisableVlan_Response(NCSI_PAYLOAD):
    name = "Disable VLAN Response"
    CommandValue = 0x8D

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 256
class GetMcMacAddress_Request(NCSI_PAYLOAD):
    name = "Get MC MAC Address Request"
    CommandValue = 0x58

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 257
class GetMcMacAddress_Response(NCSI_PAYLOAD):
    name = "Get MC MAC Address Response"
    CommandValue = 0xD8

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        FieldLenField("AddressCount", None, count_of="Addresses", fmt="B"),
        X3BytesField("GetMcMacAddress_1", 0),
        FieldListField(
            "Addresses",
            [],
            MACField("", "ff:ff:ff:ff:ff:ff"),
            count_from=lambda pkt: pkt.AddressCount,
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0261 - Table 12
class MediaDescriptor(Packet):
    """Repeated data within the GetSupportedMedia_Response"""

    name = "Media Descriptor"
    fields_desc = [
        XByteField("EID", 0x00),
        XShortField("BindingID", 0x00),
        XShortField("MediumID", 0x00),

        BitField("Status", 0, 1),
        BitField("MediaDescriptorReserved_1", 0, 6),
        BitField("PassthroughSupported", 0, 1),

        FieldLenField("PhysicalAddressSize", None, "PhysicalAddress", "B"),
        StrLenField(
            "PhysicalAddress", b"", length_from=lambda pkt: pkt.PhysicalAddressSize
        ),
    ]

    def extract_padding(self, s):  # all payloads need to do this
        return "", s


# DSP0261 - Table 10
class GetSupportedMedia_Request(NCSI_PAYLOAD):
    name = "Get Supported Media Request"
    CommandValue = 0x54

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0261 - Table 11
class GetSupportedMedia_Response(NCSI_PAYLOAD):
    name = "Get Supported Media Response"
    CommandValue = 0xD4

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        X3BytesField("GetSupportedMediaReserved_1", 0x000000),
        FieldLenField(
            "NumberOfSupportedMedias", None, count_of="MediaDescriptors", fmt="B"
        ),
        PacketListField(
            "MediaDescriptors",
            None,
            MediaDescriptor,
            count_from=lambda pkt: pkt.NumberOfSupportedMedias,
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 17
class AEN(NCSI_PAYLOAD):
    name = "AEN"
    CommandValue = 0xFF

    fields_desc = [
        X3BytesField("AenReserved_1", 0x000000),
        XShortField("AenType", 0x00),
        XIntField("OptionalAenData", 0x00),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 67
class SetMACAddress_Request(NCSI_PAYLOAD):
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
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 71
class SetMACAddress_Response(NCSI_PAYLOAD):
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

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 73
class EnableBroadcastFilter_Request(NCSI_PAYLOAD):
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
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 75
class EnableBroadcastFilter_Response(NCSI_PAYLOAD):
    name = "Enable Broadcast Filter Response"
    CommandValue = 0x90

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 87
class GetVersionID_Request(NCSI_PAYLOAD):
    name = "Get Version ID Request"
    CommandValue = 0x15

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 88
class GetVersionID_Response(NCSI_PAYLOAD):
    name = "Get Version ID Response"
    CommandValue = 0x95

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        XByteField("NCSIVersionMajor", 0x00),
        XByteField("NCSIVersionMinor", 0x00),
        XByteField("NCSIVersionUpdate", 0x00),
        XByteField("NCSIVersionAlpha1", 0x00),

        X3BytesField("Reserved", 0x000000),
        XByteField("NCSIVersionAlpha2", 0x00),

        StrLenField("FirmwareNameString11_08", b"", length_from=lambda unused: 4),

        StrLenField("FirmwareNameString07_04", b"", length_from=lambda unused: 4),

        StrLenField("FirmwareNameString03_00", b"", length_from=lambda unused: 4),

        XByteField("FirmwareVersionMajor", 0x00),
        XByteField("FirmwareVersionMinor", 0x00),
        XByteField("FirmwareVersionUpdate", 0x00),
        XByteField("FirmwareVersionAlpha", 0x00),

        XShortField("PCIDID", 0x0000),
        XShortField("PCIVID", 0x0000),

        XShortField("PCISSID", 0x0000),
        XShortField("PCISVID", 0x0000),

        XIntField("ManufacturerID", 0x00000000),  # value 0xFFFFFFFF if unused

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 89
class GetCapabilities_Request(NCSI_PAYLOAD):
    name = "Get Capabilities Request"
    CommandValue = 0x16

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 90
class GetCapabilities_Response(NCSI_PAYLOAD):
    name = "Get Capabilities Response"
    CommandValue = 0x96

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

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
        BitField("Reserved_4", 0, 11),
        BitEnumField("TransceiverEventAENControl", 0, 1, ENABLE_DISABLE),
        BitEnumField("DelayedResponseReadyAENControl", 0, 1, ENABLE_DISABLE),
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
        XByteField("ChannelCount", 0x00),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 93
class GetParameters_Request(NCSI_PAYLOAD):
    name = "Get Parameters Request"
    CommandValue = 0x17

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


class VLANTags(Packet):
    name = "VLAN Tags"
    fields_desc = [XLEShortField("VlanTag", 0x0000)]

    def extract_padding(self, s):
        return "", s    # this has no padding, but may have something following it
                        # (like an array of things, so override behavior)

# DSP0222 -  Table 94
class GetParameters_Response(NCSI_PAYLOAD):
    name = "Get Parameters Response"
    CommandValue = 0x97

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        XByteField("MACAddressCount", 0x00),
        XShortField("Reserved_1", 0x0000),
        BitField("MACAddressFlags", 0, 8),  # Table 91 DSP0222

        XByteField("VLANTagCount", 0x00),
        XByteField("Reserved_2", 0x00),
        BitField("VLANTagFlags", 0, 16),    # Table 92 DSP0222

        IntEnumField("LinkSettings", 0x0000, LINK_SETTINGS_REASON_CODES),

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
        ),  # TODO check

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 99
class GetControllerPacketStatistics_Request(NCSI_PAYLOAD):
    name = "Get Controller Packet Statistics Request"
    CommandValue = 0x18

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 100
class GetControllerPacketStatistics_Response(NCSI_PAYLOAD):
    name = "Get Controller Packet Statistics Response"
    CommandValue = 0x98

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

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

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 103
class GetNCSIStatistics_Request(NCSI_PAYLOAD):
    name = "Get NC-SI Statistics Request"
    CommandValue = 0x19

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 104
class GetNCSIStatistics_Response(NCSI_PAYLOAD):
    name = "Get NC-SI Statistics Response"
    CommandValue = 0x99

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        XIntField("NCSICommandsReceived", 0x00000000),
        XIntField("NCSIControlPacketsDropped", 0x00000000),
        XIntField("NCSICommandTypeErrors", 0x00000000),
        XIntField("NCSICommandChecksumErrors", 0x00000000),
        XIntField("NCSIReceivePackets", 0x00000000),
        XIntField("NCSITransmitPackets", 0x00000000),
        XIntField("AENsSent", 0x00000000),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 243
class OEMCommand_Request(NCSI_PAYLOAD):
    name = "OEM Command Request"
    CommandValue = 0x50

    fields_desc = [
        XIntField("ManufacturerID", 0x00000000), # https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
        # Vendor-Data[]
    ]


# DSP0222 -  Table 244
class OEMCommand_Response(NCSI_PAYLOAD):  # TODO to check
    name = "OEM Command Response"
    CommandValue = 0xD0

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        XIntField("ManufacturerID", 0x00000000), # https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
        # Return Data[] (optional)
    ]


# DSP0222 -  Table 250
class SendNCPLDMReply_Request(NCSI_PAYLOAD):  # TODO to check
    name = "Send NC PLDM Reply Request"
    CommandValue = 0x57

    fields_desc = [
        # PLDM Message Common Fields
        X3BytesField("MessageCommonFields", 0x000000),
        XByteField("PLDMCompletionCode", 0x00),

        # PLDM Message payload + Payload Pad
        ### TODO Implement

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 251
class SendNCPLDMReply_Response(NCSI_PAYLOAD):  # TODO to check
    name = "Send NC PLDM Reply Response"
    CommandValue = 0xD7

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        X3BytesField("Reserved", 0x000000),
        BitEnumField(
            "Flags",
            0,
            8,
            {
                0: "No additional pending PLDM command from NC to MC",
                1: "The NC has additional pending PLDM command to the MC",
            },
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 253
class TransportSpecificAENEnable_Request(NCSI_PAYLOAD):
    name = "Transport Specific AEN Enable Request"
    CommandValue = 0x55

    fields_desc = [
        XShortField("Reserved_1", 0x0000),

        BitField("Reserved_2", 0, 13),
        BitEnumField("PendingSPDMRequestAEN", 0, 1, ENABLE_DISABLE),
        BitEnumField("PendingPLDMRequestAEN", 0, 1, ENABLE_DISABLE),
        BitEnumField("MediumChangeAENControl", 0, 1, ENABLE_DISABLE),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 254
class TransportSpecificAENEnable_Response(NCSI_PAYLOAD):
    name = "Transport Specific AEN Enable Response"
    CommandValue = 0xD5

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 276
class PendingPLDMRequestAEN_Request(NCSI_PAYLOAD):
    name = "Pending PLDM Request AEN Request"
    CommandValue = 0xFF

    fields_desc = [
        X3BytesField("Reserved", 0x000000),
        XByteField("AENType", 0x71),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 258
class GetPackageUUID_Request(NCSI_PAYLOAD):  # TODO to check
    name = "Get Package UUID Request"
    CommandValue = 0x52

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 259
class GetPackageUUID_Response(NCSI_PAYLOAD):  # TODO to check
    name = "Get Package UUID Response"
    CommandValue = 0xD2

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        PacketField("UUID", NCSI_UUID(), NCSI_UUID),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 76
class DisableBroadcastFilter_Request(NCSI_PAYLOAD):
    name = "Disable Broadcast Filter Request"
    CommandValue = 0x11

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 77
class DisableBroadcastFilter_Response(NCSI_PAYLOAD):
    name = "Disable Broadcast Filter Response"
    CommandValue = 0x91

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 78
class EnableGlobalMulticastFilter_Request(NCSI_PAYLOAD):
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
    name = "Enable Global Multicast Filter Response"
    CommandValue = 0x92

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 81
class DisableGlobalMulticastFilter_Request(NCSI_PAYLOAD):
    name = "Disable Global Multicast Filter Request"
    CommandValue = 0x13

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 82
class DisableGlobalMulticastFilter_Response(NCSI_PAYLOAD):
    name = "Disable Global Multicast Filter Response"
    CommandValue = 0x93

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 83
class SetNCSIFlowControl_Request(NCSI_PAYLOAD):
    name = "Set NC-SI Flow Control Request"
    CommandValue = 0x14

    fields_desc = [
        X3BytesField("Reserved", 0x000000),
        XByteEnumField(
            "FlowControlEnable",
            0x00,
            {
                0x00: "Disables NC-SI flow control",
                0x01: "Enables Network Controller to Management Controller flow control frames",  # This field is optional
                0x02: "Enables Management Controller to Network Controller flow control frames",  # This field is optional
                0x03: "Enables bi-directional flow control frames",
            },
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 85
class SetNCSIFlowControl_Response(NCSI_PAYLOAD):
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

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 106
class GetNCSIPassthroughStatistics_Request(NCSI_PAYLOAD):
    name = "Get NC-SI Pass-through Statistics Request"
    CommandValue = 0x1A

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 -  Table 107
class GetNCSIPassthroughStatistics_Response(NCSI_PAYLOAD):
    name = "Get NC-SI Pass-through Statistics Response"
    CommandValue = 0x9A

    class NCSIPassthroughStatistics(Packet):
        name = "NS-SI Pass-through Statisitcs"

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

                NcsiReversePadField(XIntField("Checksum", None), 4),

        ]

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            PacketField("Stats",NCSIPassthroughStatistics(),NCSIPassthroughStatistics),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000),
        ConditionalField(
            NcsiReversePadField(XIntField("Checksum", None), 4),
            lambda pkt: pkt.ResponseCode != 0x0000 or pkt.ReasonCode != 0x0000),
    ]


# DSP0222 -  Table 108
class GetPackageStatus_Request(NCSI_PAYLOAD):
    name = "Get Package Status Request"
    CommandValue = 0x1B

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 110
class GetPackageStatus_Response(NCSI_PAYLOAD):
    name = "Get Package Status Response"
    CommandValue = 0x9B

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        BitField("Reserved", 0, 31),
        BitEnumField("HardwareArbitrationStatus", 0, 1, SUPPORTED_NOT_SUPPORTED),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


class UnsupportedNcsi_Request(NCSI_PAYLOAD):
    name = "Test Unsupported NCSI Command Request"
    CommandValue = 0x72

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


class UnsupportedNcsi_Response(NCSI_PAYLOAD):
    name = "Test Unsupported NCSI Command Response"
    CommandValue = 0xf2

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 212
class GetAsicTemperature_Request(NCSI_PAYLOAD):
    """Get ASIC Temperature Request"""

    name = "Get ASIC Temperature Request"
    CommandValue = 0x48

    fields_desc = [
        XIntField("Reserved", 0x00000000),
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 213
class GetAsicTemperature_Response(NCSI_PAYLOAD):
    """Get ASIC Temperature Response"""

    name = "Get ASIC Temperature Response"
    CommandValue = GetAsicTemperature_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        XShortField("MaximumTemperature", 0x00),
        XShortField("CurrentTemperature", 0x00),
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 214
class GetAmbientTemperature_Request(NCSI_PAYLOAD):
    """Get Ambient Temperature Request"""

    name = "Get Ambient Temperature Request"
    CommandValue = 0x49

    fields_desc = [
        XIntField("Reserved", 0x00000000),
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 215
class GetAmbientTemperature_Response(NCSI_PAYLOAD):
    """Get Ambient Temperature Response"""

    name = "Get ASIC Temperature Response"
    CommandValue = GetAmbientTemperature_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        XByteField("TemperatureValue_3", 0x00),
        XByteField("TemperatureValue_2", 0x00),
        XByteField("TemperatureValue_1", 0x00),
        ByteField("NumberOfSensors", 0x00),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 216
class GetTransceiverTemperature_Request(NCSI_PAYLOAD):
    """Get Transceiver Temperature Request"""

    name = "Get Transceiver Temperature Request"
    CommandValue = 0x4A

    fields_desc = [
        XIntField("Reserved", 0x00000000),
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 217
class GetTransceiverTemperature_Response(NCSI_PAYLOAD):
    """Get Transceiver Temperature Response"""

    name = "Get Transceiver Temperature Response"
    CommandValue = GetTransceiverTemperature_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        XShortField("TempHighAlarmThreshold", 0x0000),
        XShortField("TempHighWarningThreshold", 0x0000),
        XShortField("TemperatureValue", 0x0000),
        XShortField("Reserved", 0x0000),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 129
class GetChannelConfiguration_Request(NCSI_PAYLOAD):
    """Get Channel Configuration Request"""

    name = "Get Channel Configuration Request"
    CommandValue = 0x29

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


class GetChannelConfigurationEntry(Packet):
    """Get Channel Configuration Entry"""

    name = "Get Channel Configuration Entry"
    fields_desc = [
        ByteField("Max_TX_BW", 0),
        ByteField("Min_TX_BW", 0)
    ]


# DSP0222 - Table 130
class GetChannelConfiguration_Response(NCSI_PAYLOAD):
    """Get Channel Configuration Response"""

    name = "Get Channel Configuration Response"
    CommandValue = GetChannelConfiguration_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ByteEnumField("FabricType",
                      0,
                      {
                          1 : "Ethernet operation is enabled",
                          2 : "Fibre Channel operation is enabled",
                          3 : "InfiniBand operation is enabled",
                      },
        ),
        BitEnumField("SharedInterface",
                     0,
                     1,
                     {
                         0 : "The media does not have a backplane interface",
                         1 : "The media has a backplane interface",
                     },
        ),
        BitField("Reserved_0", 0, 4),
        BitEnumField("SFF_Cage",
                     0,
                     1,
                     {
                         0 : "The media does not have an SFF-style interface",
                         1 : "The media has an SFF-style interface",
                     },
        ),
        BitEnumField("Base_T",
                     0,
                     1,
                     {
                         0 : "The media does not have an SFF-style interface",
                         1 : "The media has a Base-T (RJ-45 style) interface",
                     },
        ),
        BitEnumField("Backplane",
                     0,
                     1,
                     {
                         0 : "The media does not have a backplane interface",
                         1 : "The media has a backplane interface",
                     },
        ),
        XShortField("MaxMTU", 0x0000),
        X3BytesField("Reserved_1", 0x000000),
        FieldLenField("NumEnabledPartitions", None, count_of="Data", fmt="B"),
        PacketListField(
            "Data",
            None,
            GetChannelConfigurationEntry,
            count_from=lambda pkt: pkt.NumEnabledPartitions
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 187
class GetModuleManagementData_Request(NCSI_PAYLOAD):
    """Get Module Management Data Request"""

    name = "Get Module Management Data Request"
    CommandValue = 0x32

    fields_desc = [
        ByteField("RequestedBank", 0),
        ByteField("RequestedPage", 0),
        ByteField("Reserved_0", 0),

        # Flags Field
        BitField("Reserved_1", 0, 7),
        BitEnumField("PageUpperFlag",
                     0,
                     1,
                     {
                         0 : "Requesting lower page data",
                         1 : "Requesting upper page data",
                     },
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 188
class GetModuleManagementData_Response(NCSI_PAYLOAD):
    """Get Module Management Data Response"""

    name = "Get Module Management Data Response"
    CommandValue = GetModuleManagementData_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ByteField("MaxBank", 0),
        ByteField("MaxPage", 0),
        ByteField("BankNumber", 0),
        ByteField("PageNumber", 0),

        FieldListField(
            "Data",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: 128
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
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
register_ncsi_class(GetSupportedMedia_Request)
register_ncsi_class(GetSupportedMedia_Response)
register_ncsi_class(GetMcMacAddress_Request)
register_ncsi_class(GetMcMacAddress_Response)
register_ncsi_class(SetMACAddress_Request)
register_ncsi_class(SetMACAddress_Response)
register_ncsi_class(EnableBroadcastFilter_Request)
register_ncsi_class(EnableBroadcastFilter_Response)
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
# register_ncsi_class(OEMCommand_Request)
register_ncsi_class(OEMCommand_Response)
register_ncsi_class(SendNCPLDMReply_Request)
register_ncsi_class(SendNCPLDMReply_Response)
# register_ncsi_class(TransportSpecificAENEnable_Request)
# register_ncsi_class(TransportSpecificAENEnable_Response)
# register_ncsi_class(PendingPLDMRequestAEN_Request)
register_ncsi_class(GetPackageUUID_Request)
register_ncsi_class(GetPackageUUID_Response)
register_ncsi_class(DisableBroadcastFilter_Request)
register_ncsi_class(DisableBroadcastFilter_Response)
register_ncsi_class(EnableGlobalMulticastFilter_Request)
register_ncsi_class(EnableGlobalMulticastFilter_Response)
register_ncsi_class(DisableGlobalMulticastFilter_Request)
register_ncsi_class(DisableGlobalMulticastFilter_Response)
register_ncsi_class(SetNCSIFlowControl_Request)
register_ncsi_class(SetNCSIFlowControl_Response)
register_ncsi_class(GetNCSIPassthroughStatistics_Request)
register_ncsi_class(GetNCSIPassthroughStatistics_Response)
register_ncsi_class(GetPackageStatus_Request)
register_ncsi_class(GetPackageStatus_Response)

register_ncsi_class(GetAsicTemperature_Request)
register_ncsi_class(GetAsicTemperature_Response)
register_ncsi_class(GetAmbientTemperature_Request)
register_ncsi_class(GetAmbientTemperature_Response)
register_ncsi_class(GetTransceiverTemperature_Request)
register_ncsi_class(GetTransceiverTemperature_Response)
register_ncsi_class(GetChannelConfiguration_Request)
register_ncsi_class(GetChannelConfiguration_Response)
register_ncsi_class(GetModuleManagementData_Request)
register_ncsi_class(GetModuleManagementData_Response)

register_ncsi_class(UnsupportedNcsi_Request)
register_ncsi_class(UnsupportedNcsi_Response)
register_ncsi_class(AEN)

# SCAPY bind layers
bind_layers(NCSI_HEADER, NCSI_PAYLOAD)
