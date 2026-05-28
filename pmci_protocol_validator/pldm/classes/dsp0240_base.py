# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
PLDM Header and Payload layers

File : dsp0240_base.py

Brief : Scapy classes for PLDM Header and Payload layers
"""

import struct
import scapy

from scapy.fields import *
from scapy.packet import Packet
from pmci_protocol_validator.ncsi.classes.dsp0222 import validateRegisteredClass


DMTF_PLDM_COMMANDS = {}  # Dictionary with keys for PLDM Commands

PLDM_BASE_CODES = {
    0x00: "SUCCESS",
    0x01: "ERROR",
    0x02: "ERROR_INVALID_DATA",
    0x03: "ERROR_INVALID_LENGTH",
    0x04: "ERROR_NOT_READY",
    0x05: "ERROR_UNSUPPORTED_PLDM_CMD",
    0x20: "ERROR_INVALID_PLDM_TYPE",
}

TransferFlags = {0x01: "Start", 0x02: "Middle", 0x04: "End", 0x05: "StartAndEnd"}

TransferFlagsPldm2 = {0x00: "Start", 0x01: "Middle", 0x04: "End", 0x05: "StartAndEnd"}

TransferOperation = {
    0x00: "XFER_FIRST_PART",
    0x01: "XFER_NEXT_PART",
    0x02: "XFER_ABORT",
    0x03: "XFER_COMPLETE",
}

StringTypeValues = {
    0: "Unknown",
    1: "ASCII",
    2: "UTF-8",
    3: "UTF-16",
    4: "UTF-16LE",
    5: "UTF-16BE",
}

COMPONENT_CLASSIFICATION_VALUES = {
    0x0000: "Unknown",
    0x0001: "Other",
    0x0002: "Driver",
    0x0003: "Configuration Software",
    0x0004: "Application Software",
    0x0005: "Instrumentation",
    0x0006: "Firmware/BIOS",
    0x0007: "Diagnostic Software",
    0x0008: "Operating System",
    0x0009: "Middleware",
    0x000A: "Firmware",
    0x000B: "BIOS/FCode",
    0x000C: "Support/Service Pack",
    0x000D: "Software Bundle",
    0xFFFF: "Downstream Device",
}

COMPONENT_IDENTIFIER_VALUES = {}

APPLY_RESULT_VALUES = {
    0x00: "Apply has completed without error",
    0x01: "Apply has completed with success and has modified its activation method",
    0x02: "Apply has completed with a failure due to a memory write issue",
    0x09: "Timeout occurred while performing action",
    0x0A: "Generic Error has occurred",
}

RecordDescriptorTypes = {
    0x0000: "PCIVendorID",              # 2 Bytes
    0x0001: "IANAEnterpriseID",         # 4 Bytes
    0x0002: "UUID",                     # 16 Bytes
    0x0003: "PnPVendorID",              # 3 Bytes
    0x0004: "ACPIVendorID",             # 4 Bytes
    0x0005: "IEEEAssignedCompanyID",    # 3 Bytes
    0x0006: "SCSIVendorID",             # 8 Bytes
    0x0100: "PCIDeviceID",              # 2 Bytes
    0x0101: "PCISubsystemVendorID",     # 2 Bytes
    0x0102: "PCISubsystemID",           # 2 Bytes
    0x0103: "PCIRevisionID",            # 1 Byte
    0x0104: "PnPProductIdentifier",     # 4 Bytes
    0x0105: "ACPIProductIdentifier",    # 4 Bytes
    0x0106: "ASCIIModelNumberLong",	    # 40 bytes
    0x0107: "ASCIIModelNumberShort",    # 10 bytes
    0x0108: "SCSIProductID",		    # 16 bytes
    0x0109: "UBMControllerDeviceCode",  # 4 bytes
    0xFFFF: "VendorDefined"		        # Variable
}

ComponentClassificationValues = {
    0x0000: "Unknown",
    0x0001: "Other",
    0x0002: "Driver",
    0x0003: "Configuration Software",
    0x0004: "Application Software",
    0x0005: "Instrumentation",
    0x0006: "Firmware/BIOS",
    0x0007: "Diagnostic Software",
    0x0008: "Operating System",
    0x0009: "Middleware",
    0x000A: "Firmware",
    0x000B: "BIOS/FCode",
    0x000C: "Support/Service Pack",
    0x000D: "Software Bundle",
    0xFFFF: "Downstream Device",
}

ComponentResponseCodes = {
    0x00: "Component can be updated",
    0x01: "Component comparison stamp is identical to the firmware component comparison stamp...",
    0x02: "Component comparison stamp is lower than the firmware component comparison stamp...",
    0x03: "Invalid component comparison stamp",
    0x04: "Component has conflict with another component provided in a separate PassComponentTable command",
    0x05: "Pre-requisites for this component have not been met",
    0x06: "Component is not supported on FD or Downstream Device",
    0x07: "Security restrictions prevent component from being downgraded",
    0x08: "Incomplete component image set was received",
    0x09: "If this new component image is activated, FD or Downstream device will not be able to subsequently update "
    "to the currently running active component image",
    0x0A: "Component version string is identical to firmware component version string in the FD or DownstreamDevice",
    0x0B: "Component version string is lower to the firmware component version string in the FD or  downstream device",
}

ComponentCompatibilityResponseCodes = {
    0x00: "Component can be updated",
    0x01: "Component comparison stamp is identical to the firmware component comparison stamp...",
    0x02: "Component comparison stamp is lower than the firmware component comparison stamp...",
    0x03: "Invalid component comparison stamp",
    0x04: "Component has conflict with another component provided in a separate PassComponentTable command",
    0x05: "Pre-requisites for this component have not been met",
    0x06: "Component is not supported on FD or Downstream Device",
    0x07: "Security restrictions prevent component from being downgraded",
    0x08: "Incomplete component image set was received",
    0x09: "Component information does not match details presented from PassComponentTable commands",
    0x0A: "Component version string is identical to firmware component version string in the FD or DownstreamDevice, but force update flag is not set",
    0x0B: "Component version string is lower to the firmware component version string in the FD or  downstream device, but force update flag is not set",
}

TransferResults = {
    0x00: "Transfer has completed without error, no additional information on why is provided with this code",
    0x01: "Transfer has completed with error as the image received is corrupt",
    0x02: "Transfer has completed with error as the version of the image received does not match the version expected"
    "from the UpdateComponent command",
    0x03: "Firmware Device has aborted the transfer",
    0x09: "Timeout occurred while performing action",
    0x0A: "Generic Error has occurred",
    0x0B: "The FD/FDP has aborted the transfer as the FD/FDP has to enter a low-power state and cannot continue",
    0x0C: "The FD/FDP has aborted the transfer as it must perform a reset and cannot continue",
    0x0D: "The FD/FDP has aborted the transfer due to an issue with storing the firmware data on the device",
}

VerifyResults = {
    0x00: "Verify has completed without error",
    0x01: "Verify has completed with a verification failure FD will not transition "
    "to APPLY state to apply the component",
    0x02: "Verify has completed with error as the version of the image received does not match the version expected "
    "from the UpdateComponent command FD will not transition to APPLY state to apply the component",
    0x03: "Verify has completed with error as the image failed the FD security checks FD will not transition "
    "to the APPLY state to apply the component",
    0x04: "Verify has completed with error as the image transferred was incomplete FD will not transition "
    "to the APPLY state to apply the component",
    0x09: "Timeout occurred while performing action FD will not transition to APPLY state to apply the component",
    0x0A: "Generic Error has occurred FD will not transition to APPLY state to apply the component",
}

FDStates = {
    0: "IDLE",
    1: "LEARN COMPONENTS",
    2: "READY XFER",
    3: "DOWNLOAD",
    4: "VERIFY",
    5: "APPLY",
    6: "ACTIVATE",
}

AuxStates = {
    0: "Operation in progress",
    1: "Operation successful",
    2: "Operation failed FD/FDP shall provide Error Code in AuxStateStatus field",
    3: "Value used when FD/FDP is in IDLE, Learn Components, or Ready Xfer state",
}

AuxStatus = {
    0x00: "AuxState is In Progress or Success",
    0x09: "Timeout occurred while performing action",
    0x0A: "Generic Error has occurred",
}

AuxReasonCodes = {
    0: "Initialization of firmware device has occurred",
    1: "ActivateFirmware command was received",
    2: "CancelUpdate command was received",
    3: "Timeout occurred when in LEARN COMPONENT state",
    4: "Timeout occurred when in READY XFER state",
    5: "Timeout occurred when in DOWNLOAD state",
    6: "Timeout occurred when in VERIFY state",
    7: "Timeout occurred when in APPLY state",
}

_reserved_dict = {
    key: "Reserved"
    for key in [hex(i) for i in list(range(12, 207)) + list(range(240, 256))]
}
ComponentResponseCodes.update({key: value for (key, value) in _reserved_dict.items()})

_vendorSpecific_dict = {
    key: "Firmware Device or FDP Vendor defined component response code"
    for key in [hex(i) for i in range(208, 223)]
}
ComponentResponseCodes.update(
    {key: value for (key, value) in _vendorSpecific_dict.items()}
)

_reservedTransferResults_dict = {
    key: "Reserved"
    for key in [
        hex(i) for i in list(range(4, 9)) + list(range(14, 112)) + list(range(144, 256))
    ]
}
TransferResults.update(
    {key: value for (key, value) in _reservedTransferResults_dict.items()}
)

_VendorSpecificTransferResults_dict = {
    key: "Firmware Device Vendor defined status code"
    for key in [hex(i) for i in range(12, 207)]
}
TransferResults.update(
    {key: value for (key, value) in _VendorSpecificTransferResults_dict.items()}
)

_reservedVerify_dict = {
    key: "Reserved"
    for key in [
        hex(i) for i in list(range(5, 9)) + list(range(11, 144)) + list(range(176, 256))
    ]
}
VerifyResults.update({key: value for (key, value) in _reservedVerify_dict.items()})

_reservedAux_dict = {
    key: "Reserved"
    for key in [
        hex(i) for i in list(range(1, 9)) + list(range(10, 112)) + list(range(240, 256))
    ]
}
AuxStatus.update({key: value for (key, value) in _reservedAux_dict.items()})

_SpecificAux_dict = {
    key: "Firmware Device Vendor defined status code"
    for key in [hex(i) for i in range(144, 176)]
}
AuxStatus.update({key: value for (key, value) in _SpecificAux_dict.items()})

_SpecificAuxReason_dict = {
    key: "Firmware Device Vendor defined status code"
    for key in [i for i in range(200, 256)]
}
AuxStatus.update({key: value for (key, value) in _SpecificAuxReason_dict.items()})

_reserved_apply_values = {
    key: "Reserved"
    for key in [i for i in range(0x03, 0x08)]
    + [i for i in range(0x03, 0xAF)]
    + [i for i in range(0xD0, 0xFF)]
}
_firmware_device_vendor = {
    key: "Firmware Device Vendor defined status code"
    for key in [i for i in range(0xB0, 0xCF)]
}
APPLY_RESULT_VALUES.update(
    {key: value for (key, value) in _reserved_apply_values.items()}
)
APPLY_RESULT_VALUES.update(
    {key: value for (key, value) in _firmware_device_vendor.items()}
)

_downstream_index_number = {
    key: "Downstream index number to be updated"
    for key in [i for i in range(0x0000, 0x0FFF)]
}
_reserved_identifier = {key: "Reserved" for key in [i for i in range(0x1000, 0xFFFF)]}
COMPONENT_IDENTIFIER_VALUES.update(
    {key: value for (key, value) in _downstream_index_number.items()}
)
COMPONENT_IDENTIFIER_VALUES.update(
    {key: value for (key, value) in _reserved_identifier.items()}
)

_reserved_for_vendor = {
    key: "Reserved for Vendor Defined values"
    for key in [i for i in range(0x8000, 0xFFFE)]
}
COMPONENT_CLASSIFICATION_VALUES.update(
    {key: value for (key, value) in _reserved_for_vendor.items()}
)


def register_pldm_class(cls):
    """
    Helper to register a PLDM_PAYLOAD class. If the name of the
    class has '_Request' in it then it will be registered as a Request
    else as a Response
    """

    CommandVal = cls.CommandValue
    Name = cls.__name__
    PldmPayloadType = cls.PldmPayloadType

    if "_Request" in Name:
        rqBit = 1
    elif "_Response" in Name:
        rqBit = 0
    else:
        assert False, "PLDM classes must be _Request or _Response: {} {}".format(
            hex(CommandVal), Name
        )

    # Unique key is Rq bit, Payload Type and Command combination
    key = ((rqBit << 16) + PldmPayloadType << 8) + CommandVal
    if key in DMTF_PLDM_COMMANDS:
        assert False, "Duplicate PLDM Command: {} from {}".format(hex(CommandVal), Name)

    DMTF_PLDM_COMMANDS[key] = cls

    # Quick check to make sure it is a valid packet
    validateRegisteredClass(cls)


class PLDM_HEADER(Packet):
    """ PLDM Header """

    PayloadType = 0x01  # PLDM over MCTP, used for PLDM over MCTP binding

    name = "PLDM Header"
    fields_desc = [  # 3 bytes
        BitField("Request", 0x0, 1),
        BitField("Datagram", 0x0, 1),
        BitField("PldmHeaderReserved_1", 0x0, 1),
        BitField("InstanceID", 0x0, 5),
        BitField("HeaderVersion", 0x0, 2),
        BitField("PldmType", 0x0, 6),     # This is set by the PayloadType class variable in the payload
        XByteField("CommandCode", None),  # set by CommandValue in payload class
    ]

    def _updateCommandAndRq(self, pkt):
        """
        Some of the fields in the MCTP Control header need to be filled
        out based upon the information that comes from the payload
        such as if it is a request, Payload Type and the command
        """
        if (
            "_Request" in type(self.payload).__name__
        ):  # does class have _Request in name
            rqBit = 1

        else:
            rqBit = 0

        self.Request = rqBit

        (currVal,) = struct.unpack("B", bytes([pkt[0]]))
        rqBit = rqBit << 7
        currVal = currVal & 0x7F  # clear Rq bit
        firstByte = currVal + rqBit  # only twiddle rqbit, if set
        encodedFirstByte = struct.pack("B", firstByte)

        (headerVer,) = struct.unpack("B", bytes([pkt[1]]))
        headerVer = headerVer & 0xC0  # just header ver

        encodedPayloadType = struct.pack("B", self.PldmType + headerVer)

        pkt = encodedFirstByte + encodedPayloadType + pkt[2:]

        self.CommandCode = self.payload.CommandValue
        encodedCommand = struct.pack("B", self.CommandCode)
        pkt = pkt[:2] + encodedCommand  # Command is last byte in header

        return pkt

    def guess_payload_class(self, payload):
        """
        Not 1 key to differentiate payloads, so this routine
        is called to make more complicted determination
        """
        # can make a unique key with request bit, pldm type and command code
        key = (
            (self.Request << 16) + self.PldmType << 8
        ) + self.CommandCode  # have to watch those order of operations.

        # now go look in registered commands
        if key in DMTF_PLDM_COMMANDS:
            return DMTF_PLDM_COMMANDS[key]

        else:
            pass

    def post_build(self, pkt, pay):
        """
        Called by SCAPY framework, this is where I get the command from
        the payload and put into the header
        """
        if self.payload.name != "NoPayload":
            pkt = self._updateCommandAndRq(pkt)

        return pkt + pay

    def do_build(self):
        """
        Overrode this function, because while I set the CommandCode in the
        _updateCommandAndRq() however debugging shows that the 'self' in that
        function is NOT the same as the one here so the changes to
        self.CommandCode are not propagated back to here, so I simply go grab
        it from the raw pkt and and set it.
        """
        p = Packet.do_build(self)
        if None == self.CommandCode and self.payload and len(p) == 3:
            (cmdCode,) = struct.unpack("B", bytes(p[-1:]))
            self.CommandCode = cmdCode

        return p


class PLDM_PAYLOAD(Packet):
    """ Base class for PLDM Payloads """

    name = "PLDM Payload"
    MctpPayloadType = 0x01
    PayloadType = 0x00

    # this has no padding, but may have something following it
    # (like an array of things, so override behavior)
    def extract_padding(self, s):
        return ("", s, )


class PLDM_UUID(Packet):
    """ UUID in the PLDM V1.0 format, per DSP0240 """

    name = "UUID"
    UUID_NODE_LEN = 6

    fields_desc = [
        XLEIntField("TimeLow", 0x00000000),
        XLEShortField("TimeMid", 0x0000),
        XLEShortField("TimeHighAndVersion", 0x0000),
        XByteField("ClockSeqHighAndReserved", 0x00),
        XByteField("ClockSeqLow", 0x00),
        scapy.layers.l2.DestMACField(
            "Node"
        ),  # it may not be a MAC, but is 6 bytes, so this works well
    ]

    # this has no padding, but may have something following it
    # (like an array of things, so override behavior)
    def extract_padding(self, s):
        return ("", s, )


class VAR_STRING(Packet):
    """ Var String class """

    name = "Var String"

    fields_desc = [
        ByteEnumField("stringFormat", 0, StringTypeValues),
        FieldLenField("stringLengthBytes", None, "stringData", "B"),
        StrLenField("stringData", b"", length_from=lambda pkt: pkt.stringLengthBytes),
    ]

    def extract_padding(self, s):
        return ("", s, )


class PLDM_TIMESTAMP104(Packet):
    """ PLDM Timestamp class in the PLDM V1.0 format, per DSP0240 """

    name = "Timestamp104"

    fields_desc = [
        LEShortField("UTC_offset", 0x0000),
        LEThreeBytesField("Microseconds", 0x000000),
        ByteField("Seconds", 0x00),
        ByteField("Minute", 0x00),
        ByteField("Hour", 0x00),
        ByteField("Day", 0x00),
        ByteField("Month", 0x00),
        LEShortField("Year", 0x0000),
        ByteField("Resolution", 0x00),  # change to bitfield
    ]

    def extract_padding(self, s):
        return ("", s,)
