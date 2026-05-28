# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Scapy PDR definition for PLDM Type 2

File : dsp0248_pdrs.py

Brief : Scapy PDR class definitions for PLDM Type 2 (PLDM for Platform Monitoring and Control)
"""

from scapy.fields import *
from scapy.packet import Packet
from .dsp0249 import entity_id_codes

dataSize = {0: "uint8", 1: "sint8", 2: "uint16", 3: "sint16", 4: "uint32", 5: "sint32"}

supported_not_supported = {0: "Not supported", 1: "Supported"}

true_false = {0: "False", 1: "True"}

initialization = {
    1: "State sensor requires initialization",
    0: "State sensor does not require initialization",
}

enableEvent = {
    1: "Enable event message generator for state sensor",
    0: "Disable event message generator for state sensor",
}

occurenceRate = {
    0: "No Occurrence Rate",
    1: "Per Microsecond",
    2: "Per Millisecond",
    3: "Per Second",
    4: "Per Minute",
    5: "Per Hour",
    6: "Per Day",
}

PDRTypes = {
    1: "Terminus Locator",
    2: "Numeric Sensor",
    3: "Numeric Sensor Initialization",
    4: "State Sensor",
    5: "State Sensor Initialization",
    6: "Sensor Auxiliary Names",
    7: "OEM Unit",
    8: "OEM State Set",
    9: "Numeric Effecter",
    10: "Numeric Effecter Initialization",
    11: "State Effecter",
    12: "State Effecter Initialization",
    13: "Effecter Auxiliary Names",
    14: "Effecter OEM Semantic",
    15: "Entity Association",
    16: "Entity Auxiliary Names",
    17: "OEM Entity ID",
    18: "Interrupt Association",
    19: "PLDM Event Log",
    20: "FRU Record Set",
    21: "Compact Numeric Sensor",
    22: "Redfish Resource",
    23: "Redfish Entity Association",
    24: "Redfish Action",
    126: "OEM Device",
    127: "OEM",
}

TerminusLocatorType = {
    0: "UID",
    1: "MCTP_EID",
    2: "SMBusRelative",
    3: "systemSoftware"
}

""" this is the PLDM V1.2 format, per DSP0248"""
SensorUnitsEnumeration = {
    0: "None",
    1: "Unspecified",
    2: "Degrees C",
    3: "Degrees F",
    4: "Kelvins",
    5: "Volts",
    6: "Amps",
    7: "Watts",
    8: "Joules",
    9: "Coulombs",
    10: "VA",
    11: "Nits",
    12: "Lumens",
    13: "Lux",
    14: "Candelas",
    15: "kPa",
    16: "PSI",
    17: "Newtons",
    18: "CFM",
    19: "RPM",
    20: "Hertz",
    21: "Seconds",
    22: "Minutes",
    23: "Hours",
    24: "Days",
    25: "Weeks",
    26: "Mils",
    27: "Inches",
    28: "Feet",
    29: "Cubic Inches",
    30: "Cubic Feet",
    31: "Meters",
    32: "Cubic Centimeters ",
    33: "Cubic Meters",
    34: "Liters",
    35: "Fluid Ounces",
    36: "Radians",
    37: "Steradians",
    38: "Revolutions",
    39: "Cycles",
    40: "Gravities",
    41: "Ounces",
    42: "Pounds",
    43: "Foot-Pounds",
    44: "Ounce-Inches",
    45: "Gauss",
    46: "Gilberts",
    47: "Henries",
    48: "Farads",
    49: "Ohms",
    50: "Siemens",
    51: "Moles",
    52: "Becquerels",
    53: "PPM (parts/million)",
    54: "Decibels",
    55: "DbA",
    56: "DbC",
    57: "Grays",
    58: "Sieverts",
    59: "Color Temperature Degrees K",
    60: "Bits",
    61: "Bytes",
    62: "Words (data)",
    63: "DoubleWords",
    64: "QuadWords",
    65: "Percentage",
    66: "Pascals",
    67: "Counts",
    68: "Grams",
    69: "Newton-meters",
    70: "Hits",
    71: "Misses",
    72: "Retries",
    73: "Overruns/Overflows",
    74: "Underruns",
    75: "Collisions",
    76: "Packets",
    77: "Messages",
    78: "Characters",
    79: "Errors",
    80: "Corrected Errors",
    81: "Uncorrectable Errors",
    82: "Square Mils",
    83: "Square Inches",
    84: "Square Feet",
    85: "Square Centimeters",
    86: "Square Meters",
    # All others reserved
    255: "OEMUnit",
}

RateUnit = {
    0: "None",
    1: "Per MicroSecond",
    2: "Per MilliSecond",
    3: "Per Second",
    4: "Per Minute",
    5: "Per Hour",
    6: "Per Day",
    7: "Per Week",
    8: "Per Month",
    9: "Per Year",
}


class LEIeeeFloatField(Field[int, int]):
    """ Define a Little Endian IEEE Single Float for DMTF real32 type """

    def __init__(self, name, default):
        Field.__init__(self, name, default, "<f")
        return


class TerminusLocatorPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Terminus Locator"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x00000000),
        ByteEnumField("Validity", 0, {0: "notValid", 1: "valid"}),
        XByteField("TID", 0x00),
        XLEShortField("ContainerID", 0x0000),
        ByteEnumField("TerminusLocatorType", 0, TerminusLocatorType),
        ByteField("TerminusLocatorValueSize", 0x00),
        FieldListField(
            "RecordData",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.TerminusLocatorValueSize,
        ),
    ]

    # This packet has no padding, but may have something following it
    # like an array, so override this behavior.
    def extract_padding(self, s):
        return ("", s)


class NumericSensorPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Numeric Sensor"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x00000000),
        XLEShortField("SensorID", 0x0000),
        LEShortEnumField("EntityType", 0x0000, entity_id_codes),
        LEShortField("EntityInstanceNumber", 0x0000),
        XLEShortField("ContainerID", 0x0000),
        ByteEnumField(
            "SensorInit",
            0,
            {
                0: "noInit",
                1: "useInitPDR",
                2: "enableSensor",
                3: "disableSensor",
            },
        ),
        ByteEnumField("SensorAuxiliaryNamesPDR", 0, true_false),
        ByteEnumField("BaseUnit", 0, SensorUnitsEnumeration),
        ByteField("UnitModifier", 0x00),
        ByteEnumField("RateUnit", 0, RateUnit),
        XByteField("BaseOEMUnitHandle", 0x00),
        ByteEnumField("AuxUnit", 0, SensorUnitsEnumeration),
        ByteField("AuxUnitModifier", 0x00),
        ByteEnumField("AuxRateUnit", 0, RateUnit),
        ByteEnumField("Relationship", 0, {0: "dividedBy", 1: "multipliedBy"}),
        XByteField("AuxOEMUnitHandle", 0x00),
        ByteEnumField("IsLinear", 0, true_false),  # bool8
        ByteEnumField("SensorDataSize", 0, {**dataSize, 6: "real32"}),
        LEIeeeFloatField("Resolution", 0x00000000),  # real32
        LEIeeeFloatField("Offset", 0x00000000),  # real32
        LEShortField("Accuracy", 0x0000),
        ByteField("PlusTolerance", 0x00),
        ByteField("MinusTolerance", 0x00),
        MultipleTypeField(
            [
                (
                    ByteField("HysteresisValue", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    LEShortField("HysteresisValue", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    LEIntField("HysteresisValue", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
                (
                    LEIeeeFloatField("HysteresisValue", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [6],
                ),
            ],
            XByteField("HysteresisValue", 0x00),  # Default field
        ),
        BitField("Reserved_1", 0, 2),
        BitEnumField("lowerThresholdFatal", 0, 1, supported_not_supported),
        BitEnumField("lowerThresholdCritical", 0, 1, supported_not_supported),
        BitEnumField("lowerThresholdWarning", 0, 1, supported_not_supported),
        BitEnumField("upperThresholdFatal", 0, 1, supported_not_supported),
        BitEnumField("upperThresholdCritical", 0, 1, supported_not_supported),
        BitEnumField("upperThresholdWarning", 0, 1, supported_not_supported),
        BitField("Reserved_2", 0, 3),
        BitEnumField("PLDMTerminusReturnsToOnlineCondition", 0, 1, true_false),
        BitEnumField("SystemWarmResets", 0, 1, true_false),
        BitEnumField("SystemHardResets", 0, 1, true_false),
        BitEnumField("PLDMSubsystemPowerUp", 0, 1, true_false),
        BitEnumField("InitializationAgentControllerRestartUpdate", 0, 1, true_false),
        LEIeeeFloatField("StateTransitionInterval", 0x00000000),  # real32
        LEIeeeFloatField("UpdateInterval", 0x00000000),  # real32
        MultipleTypeField(
            [
                (
                    ByteField("MaxReadable", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    LEShortField("MaxReadable", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    LEIntField("MaxReadable", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
                (
                    LEIeeeFloatField("MaxReadable", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [6],
                ),
            ],
            XByteField("MaxReadable", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("MinReadable", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    LEShortField("MinReadable", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    LEIntField("MinReadable", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
                (
                    LEIeeeFloatField("MinReadable", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [6],
                ),
            ],
            XByteField("MinReadable", 0x00),  # Default field
        ),
        ByteEnumField("RangeFieldFormat", 0, {**dataSize, 6: "real32"}),
        BitField("Reserved_3", 0, 1),
        BitEnumField("FatalLowSupported", 0, 1, supported_not_supported),
        BitEnumField("FatalHighSupported", 0, 1, supported_not_supported),
        BitEnumField("CriticalLowSupported", 0, 1, supported_not_supported),
        BitEnumField("CriticalHighSupported", 0, 1, supported_not_supported),
        BitEnumField("NormalMinSupported", 0, 1, supported_not_supported),
        BitEnumField("NormalMaxSupported", 0, 1, supported_not_supported),
        BitEnumField("NominalValueSupported", 0, 1, supported_not_supported),
        MultipleTypeField(
            [
                (
                    ByteField("NominalValue", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("NominalValue", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("NominalValue", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5, 6],
                ),
                (
                    LEIeeeFloatField("NominalValue", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),  # real32
            ],
            XByteField("NominalValue", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("NormalMax", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("NormalMax", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("NormalMax", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("NormalMax", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),  # real32
            ],
            XByteField("NormalMax", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("NormalMin", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("NormalMin", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("NormalMin", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("NormalMin", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),  # real32
            ],
            XByteField("NormalMin", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("WarningHigh", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("WarningHigh", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("WarningHigh", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("WarningHigh", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),  # real32
            ],
            XByteField("WarningHigh", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("WarningLow", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("WarningLow", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("WarningLow", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("WarningLow", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),  # real32
            ],
            XByteField("WarningLow", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("CriticalHigh", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("CriticalHigh", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("CriticalHigh", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("CriticalHigh", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),  # real32
            ],
            XByteField("CriticalHigh", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("CriticalLow", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("CriticalLow", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("CriticalLow", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("CriticalLow", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),  # real32
            ],
            XByteField("CriticalLow", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("FatalHigh", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("FatalHigh", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("FatalHigh", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("FatalHigh", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),  # real32
            ],
            XByteField("FatalHigh", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("FatalLow", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("FatalLow", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("FatalLow", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("FatalLow", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),  # real32
            ],
            XByteField("FatalLow", 0x00),  # Default field
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class NumericSensorInitializationPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Numeric Sensor Initialization"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x00000000),
        XLEShortField("SensorID", 0x0000),
        BitField("Reserved_1", 0, 3),
        BitEnumField("PLDMTerminusReturnsToOnlineCondition", 0, 1, true_false),
        BitEnumField("SystemWarmResets", 0, 1, true_false),
        BitEnumField("SystemHardResets", 0, 1, true_false),
        BitEnumField("PLDMSubsystemPowerUp", 0, 1, true_false),
        BitEnumField("InitializationAgentControllerRestartUpdate", 0, 1, true_false),
        XByteField("SensorEnable", 0x00),
        BitField("Reserved_2", 0, 2),
        BitEnumField("lowerThresholdFatal", 0, 1, true_false),
        BitEnumField("lowerThresholdCritical", 0, 1, true_false),
        BitEnumField("lowerThresholdWarning", 0, 1, true_false),
        BitEnumField("upperThresholdFatal", 0, 1, true_false),
        BitEnumField("upperThresholdCritical", 0, 1, true_false),
        BitEnumField("upperThresholdWarning", 0, 1, true_false),
        ByteEnumField("SensorDataSize", 0, dataSize),
        MultipleTypeField(
            [
                (
                    XByteField("UpperThresholdWarning", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("UpperThresholdWarning", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("UpperThresholdWarning", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("UpperThresholdWarning", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("UpperThresholdCritical", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("UpperThresholdCritical", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("UpperThresholdCritical", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("UpperThresholdCritical", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("UpperThresholdFatal", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("UpperThresholdFatal", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("UpperThresholdFatal", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("UpperThresholdFatal", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("LowerThresholdWarning", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("LowerThresholdWarning", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("LowerThresholdWarning", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("LowerThresholdWarning", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("LowerThresholdCritical", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("LowerThresholdCritical", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("LowerThresholdCritical", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("LowerThresholdCritical", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("LowerThresholdFatal", 0x00),
                    lambda pkt: pkt.SensorDataSize in [0, 1],
                ),
                (
                    XLEShortField("LowerThresholdFatal", 0x0000),
                    lambda pkt: pkt.SensorDataSize in [2, 3],
                ),
                (
                    XLEIntField("LowerThresholdFatal", 0x00000000),
                    lambda pkt: pkt.SensorDataSize in [4, 5],
                ),
            ],
            XByteField("LowerThresholdFatal", 0x00),  # Default field
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class StateSensorBitFields(Packet):
    name = "State Sensor Possible States BitFields"

    fields_desc = [
        BitEnumField("StateSetSupported_7", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_6", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_5", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_4", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_3", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_2", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_1", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_0", 0, 1, supported_not_supported),
    ]

    def extract_padding(self, s):
        return ("", s)


class StateSensorFields(Packet):
    name = "State Sensor Possible States"

    fields_desc = [
        LEShortField("StateSetID", 0x0000),
        ByteField("PossibleStateSize", 0x00),
        PacketListField(
            "PossibleStates",
            StateSensorBitFields(),
            StateSensorBitFields,
            count_from=lambda pkt: pkt.PossibleStateSize,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class StateSensorPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "State Sensor"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XLEShortField("SensorID", 0x0000),
        LEShortEnumField("EntityType", 0x0000, entity_id_codes),
        LEShortField("EntityInstanceNumber", 0x0000),
        XLEShortField("ContainerID", 0x0000),
        ByteEnumField(
            "SensorInit",
            0,
            {
                0: "noInit",
                1: "useInitPDR",
                2: "enableSensor",
                3: "disableSensor",
            },
        ),
        ByteEnumField("SensorAuxiliaryNamesPDR", 0, true_false),
        ByteField("CompositeSensorCount", 0x00),  # Values from 0x01 to 0x08
        PacketListField(
            "PossibleStatesFields",
            StateSensorFields(),
            StateSensorFields,
            count_from=lambda pkt: pkt.CompositeSensorCount,
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class StateSensorInitializationPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "State Sensor Initialization"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x00000000),
        XLEShortField("SensorID", 0x0000),
        BitField("Reserved_1", 0, 3),
        BitEnumField("PLDMTerminusReturnsToOnlineCondition", 0, 1, true_false),
        BitEnumField("SystemWarmResets", 0, 1, true_false),
        BitEnumField("SystemHardResets", 0, 1, true_false),
        BitEnumField("PLDMSubsystemPowerUp", 0, 1, true_false),
        BitEnumField("InitializationAgentControllerRestartUpdate", 0, 1, true_false),
        XByteField("SensorEnable", 0x00),
        BitEnumField("SensorInitMask_7", 0, 1, initialization),
        BitEnumField("SensorInitMask_6", 0, 1, initialization),
        BitEnumField("SensorInitMask_5", 0, 1, initialization),
        BitEnumField("SensorInitMask_4", 0, 1, initialization),
        BitEnumField("SensorInitMask_3", 0, 1, initialization),
        BitEnumField("SensorInitMask_2", 0, 1, initialization),
        BitEnumField("SensorInitMask_1", 0, 1, initialization),
        BitEnumField("SensorInitMask_0", 0, 1, initialization),
        BitEnumField("sensorStateEventEnableMask_7", 0, 1, enableEvent),
        BitEnumField("sensorStateEventEnableMask_6", 0, 1, enableEvent),
        BitEnumField("sensorStateEventEnableMask_5", 0, 1, enableEvent),
        BitEnumField("sensorStateEventEnableMask_4", 0, 1, enableEvent),
        BitEnumField("sensorStateEventEnableMask_3", 0, 1, enableEvent),
        BitEnumField("sensorStateEventEnableMask_2", 0, 1, enableEvent),
        BitEnumField("sensorStateEventEnableMask_1", 0, 1, enableEvent),
        BitEnumField("sensorStateEventEnableMask_0", 0, 1, enableEvent),
        BitEnumField("SensorEventRearm_7", 0, 1, true_false),
        BitEnumField("SensorEventRearm_6", 0, 1, true_false),
        BitEnumField("SensorEventRearm_5", 0, 1, true_false),
        BitEnumField("SensorEventRearm_4", 0, 1, true_false),
        BitEnumField("SensorEventRearm_3", 0, 1, true_false),
        BitEnumField("SensorEventRearm_2", 0, 1, true_false),
        BitEnumField("SensorEventRearm_1", 0, 1, true_false),
        BitEnumField("SensorEventRearm_0", 0, 1, true_false),
        XByteField("StateValue_0", 0x00),
        XByteField("StateValue_1", 0x00),
        XByteField("StateValue_2", 0x00),
        XByteField("StateValue_3", 0x00),
        XByteField("StateValue_4", 0x00),
        XByteField("StateValue_5", 0x00),
        XByteField("StateValue_6", 0x00),
        XByteField("StateValue_7", 0x00),
    ]

    def extract_padding(self, s):
        return ("", s)


class NamesFieldsSensorAuxiliaryNames(Packet):
    name = "Sensor Auxiliary Names Fields"

    fields_desc = [
        StrField("NameLanguageTag", None, fmt="B"),
        StrField("SensorName", None, fmt="B"),
    ]

    def extract_padding(self, s):
        return ("", s)


class SensorAuxiliaryNamesFields(Packet):
    name = "Sensor Auxiliary Names Sensor Fields"

    fields_desc = [
        ByteField("NameStringCount", 0x00),
        PacketListField(
            "NameStrings",
            NamesFieldsSensorAuxiliaryNames(),
            NamesFieldsSensorAuxiliaryNames,
            count_from=lambda pkt: pkt.NameStringCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class SensorAuxiliaryNamesPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Sensor Auxiliary Names"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x00000000),
        XLEShortField("SensorID", 0x0000),
        ByteField("SensorCount", 0x00),
        PacketListField(
            "Sensors",
            SensorAuxiliaryNamesFields(),
            SensorAuxiliaryNamesFields,
            count_from=lambda pkt: pkt.SensorCount,
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class OEMUnitStrings(Packet):
    name = "OEM Unit Strings"

    fields_desc = [
        StrField("UnitLanguageTag", None, fmt="B"),
        StrField("UnitName", None, fmt="B"),
    ]

    def extract_padding(self, s):
        return ("", s)


class OEMUnitPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "OEM Unit"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x00000000),
        XByteField("OEMUnitHandle", 0x0000),
        XLEIntField("VendorIANA", 0x00000000),
        XByteField("OEMUnitID", 0x00),
        ByteField("StringCount", 0x00),
        PacketListField(
            "UnitNames",
            OEMUnitStrings(),
            OEMUnitStrings,
            count_from=lambda pkt: pkt.StringCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class OEMStateStrings(Packet):
    name = "OEM State Strings"

    fields_desc = [
        StrField("StateLanguageTag", None, fmt="B"),
        StrField("StateName", None, fmt="B"),
    ]

    def extract_padding(self, s):
        return("", s)   # this has no padding, but may have something following
                        # it (like an array of things, so override behavior)


class OEMStateValueRecordFields(Packet):
    name = "OEM State Value Records"

    fields_desc = [
        XByteField("MinStateValue", 0x00),
        XByteField("MaxStateValue", 0x00),
        XByteField("StringCount", 0x00),
        PacketListField(
            "StateNames",
            OEMStateStrings(),
            OEMStateStrings,
            count_from=lambda pkt: pkt.StringCount,
        )
    ]


class OEMStatePDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "OEM State Set"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x00000000),
        XLEShortField("OEMStateSetIDHandle", 0x0000),
        XLEIntField("VendorIANA", 0x00000000),
        XLEShortField("OEMStateSetID", 0x00),
        ByteEnumField(
            "UnspecifiedValueHint",
            0,
            {
                0: "treatAsUnspecified",
                1: "treatAsError"
            }
        ),
        ByteField("StateCount", 0x00),
        PacketListField(
            "OEMStateValueRecords",
            OEMStateValueRecordFields(),
            OEMStateValueRecordFields,
            count_from=lambda pkt: pkt.StateCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class NumericEffecterPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Numeric Effecter"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XLEShortField("EffecterID", 0x0000),
        LEShortEnumField("EntityType", 0x0000, entity_id_codes),
        LEShortField("EntityInstanceNumber", 0x0000),
        XLEShortField("ContainerID", 0x0000),
        XLEShortField("EffecterSemanticID", 0x0000),
        ByteEnumField(
            "EffecterInit",
            0,
            {
                0: "noInit",
                1: "useInitPDR",
                2: "enableEffecter",
                3: "disableEffecter",
            },
        ),
        ByteEnumField("EffecterAuxiliaryNamesPDR", 0x00, true_false),
        ByteEnumField("BaseUnit", 0, SensorUnitsEnumeration),
        ByteField("UnitModifier", 0x00),
        ByteEnumField("RateUnit", 0, RateUnit),
        XByteField("BaseOEMUnitHandle", 0x00),
        ByteEnumField("AuxUnit", 0, SensorUnitsEnumeration),
        ByteField("AuxUnitModifier", 0x00),
        ByteEnumField("AuxRateUnit", 0, RateUnit),
        XByteField("AuxOEMUnitHandle", 0x00),
        ByteEnumField("IsLinear", 0, true_false),  # bool8
        ByteEnumField("EffecterDataSize", 0, dataSize),
        LEIeeeFloatField("Resolution", 0x00000000),
        LEIeeeFloatField("Offset", 0x00000000),
        LEShortField("Accuracy", 0x0000),
        ByteField("PlusTolerance", 0x00),
        ByteField("MinusTolerance", 0x00),
        LEIeeeFloatField("StateTransitionInterval", 0x00000000),
        MultipleTypeField(
            [
                (
                    XByteField("MaxSettable", 0x00),
                    lambda pkt: pkt.EffecterDataSize in [0, 1],
                ),
                (
                    XLEShortField("MaxSettable", 0x0000),
                    lambda pkt: pkt.EffecterDataSize in [2, 3],
                ),
                (
                    XLEIntField("MaxSettable", 0x00000000),
                    lambda pkt: pkt.EffecterDataSize in [4, 5],
                ),
            ],
            XByteField("MaxSettable", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    XByteField("MinSettable", 0x00),
                    lambda pkt: pkt.EffecterDataSize in [0, 1],
                ),
                (
                    XLEShortField("MinSettable", 0x0000),
                    lambda pkt: pkt.EffecterDataSize in [2, 3],
                ),
                (
                    XLEIntField("MinSettable", 0x00000000),
                    lambda pkt: pkt.EffecterDataSize in [4, 5],
                ),
            ],
            XByteField("MinSettable", 0x00),  # Default field
        ),

        ByteEnumField("RangeFieldFormat", 0, {**dataSize, 6: "real32"}),
        BitField("Reserved_1", 0, 3),
        BitEnumField("RatedMinSupported", 0, 1, supported_not_supported),
        BitEnumField("RatedMaxSupported", 0, 1, supported_not_supported),
        BitEnumField("NormalMinSupported", 0, 1, supported_not_supported),
        BitEnumField("NormalMaxSupported", 0, 1, supported_not_supported),
        BitEnumField("NominalValueSupported", 0, 1, supported_not_supported),
        MultipleTypeField(
            [
                (
                    ByteField("NominalValue", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("NominalValue", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("NominalValue", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("NominalValue", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),
            ],
            XByteField("NominalValue", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("NormalMax", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("NormalMax", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("NormalMax", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("NormalMax", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),
            ],
            XByteField("NormalMax", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("NormalMin", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("NormalMin", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("NormalMin", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("NormalMin", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),
            ],
            XByteField("NormalMin", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("RatedMax", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("RatedMax", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("RatedMax", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("RatedMax", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),
            ],
            XByteField("RatedMax", 0x00),  # Default field
        ),
        MultipleTypeField(
            [
                (
                    ByteField("RatedMin", 0x00),
                    lambda pkt: pkt.RangeFieldFormat in [0, 1],
                ),
                (
                    LEShortField("RatedMin", 0x0000),
                    lambda pkt: pkt.RangeFieldFormat in [2, 3],
                ),
                (
                    LEIntField("RatedMin", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [4, 5],
                ),
                (
                    LEIeeeFloatField("RatedMin", 0x00000000),
                    lambda pkt: pkt.RangeFieldFormat in [6],
                ),
            ],
            XByteField("RatedMin", 0x00),  # Default field
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class NumericEffecterInitializationPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Numeric Effecter Initialization"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XLEShortField("EffecterID", 0x0000),
        XByteField("EffecterEnable", 0x00),
        BitField("Reserved_1", 0, 3),
        BitEnumField("PLDMTerminusReturnsToOnlineCondition", 0, 1, true_false),
        BitEnumField("SystemWarmResets", 0, 1, true_false),
        BitEnumField("SystemHardResets", 0, 1, true_false),
        BitEnumField("PLDMSubsystemPowerUp", 0, 1, true_false),
        BitEnumField("InitializationAgentControllerRestartUpdate", 0, 1, true_false),
        ByteEnumField("EffecterDataSize", 0, dataSize),
        MultipleTypeField(
            [
                (
                    ByteField("EffecterData", 0x00),
                    lambda pkt: pkt.EffecterDataSize in [0, 1],
                ),
                (
                    LEShortField("EffecterData", 0x0000),
                    lambda pkt: pkt.EffecterDataSize in [2, 3],
                ),
                (
                    LEIntField("EffecterData", 0x00000000),
                    lambda pkt: pkt.EffecterDataSize in [4, 5],
                ),
                (
                    LEIeeeFloatField("EffecterData", 0x00000000),
                    lambda pkt: pkt.EffecterDataSize in [6],
                ),
            ],
            XByteField("EffecterData", 0x00)  # Default field
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class StateEffecterBitFields(Packet):
    name = "State Effecter Possible States BitFields"

    fields_desc = [
        BitEnumField("StateSetSupported_7", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_6", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_5", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_4", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_3", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_2", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_1", 0, 1, supported_not_supported),
        BitEnumField("StateSetSupported_0", 0, 1, supported_not_supported),
    ]

    def extract_padding(self, s):
        return("", s)


class StateEffecterFields(Packet):
    name = "State Effecter Possible States"

    fields_desc = [
        LEShortField("StateSetID", 0x0000),
        ByteField("PossibleStateSize", 0x00),
        PacketListField(
            "PossibleStates",
            StateEffecterBitFields(),
            StateEffecterBitFields,
            count_from=lambda pkt: pkt.PossibleStateSize,
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class StateEffecterPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "State Effecter"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XLEShortField("EffecterID", 0x0000),
        LEShortEnumField("EntityType", 0x0000, entity_id_codes),
        LEShortField("EntityInstanceNumber", 0x0000),
        XLEShortField("ContainerID", 0x0000),
        XLEShortField("EffecterSemanticID", 0x0000),
        ByteEnumField(
            "EffecterInit",
            0,
            {
                0: "noInit",
                1: "useInitPDR",
                2: "enableEffecter",
                3: "disableEffecter",
            },
        ),
        ByteEnumField("EffecterDescriptionPDR", 0x00, true_false),
        ByteField("CompositeEffecterCount", 0x00),
        PacketListField(
            "PossibleStatesFields",
            StateEffecterFields(),
            StateEffecterFields,
            count_from=lambda pkt: pkt.CompositeEffecterCount,
        )
    ]

    def extract_padding(self, s):
        return("", s)


class StateEffecterInitializationPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "State Effecter Initialization"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XLEShortField("EffecterID", 0x0000),
        LEShortEnumField("EntityType", 0x0000, entity_id_codes),
        LEShortField("EntityInstanceNumber", 0x0000),
        XLEShortField("ContainerID", 0x0000),
        BitField("Reserved_1", 0, 3),
        BitEnumField("PLDMTerminusReturnsToOnlineCondition", 0, 1, true_false),
        BitEnumField("SystemWarmResets", 0, 1, true_false),
        BitEnumField("SystemHardResets", 0, 1, true_false),
        BitEnumField("PLDMSubsystemPowerUp", 0, 1, true_false),
        BitEnumField("InitializationAgentControllerRestartUpdate", 0, 1, true_false),
        XByteField("EffecterEnable", 0x00),
        BitEnumField("EffecterInitMask_7", 0, 1, initialization),
        BitEnumField("EffecterInitMask_6", 0, 1, initialization),
        BitEnumField("EffecterInitMask_5", 0, 1, initialization),
        BitEnumField("EffecterInitMask_4", 0, 1, initialization),
        BitEnumField("EffecterInitMask_3", 0, 1, initialization),
        BitEnumField("EffecterInitMask_2", 0, 1, initialization),
        BitEnumField("EffecterInitMask_1", 0, 1, initialization),
        BitEnumField("EffecterInitMask_0", 0, 1, initialization),
        BitEnumField("EffecterOpStateEventEnableMask_7", 0, 1, enableEvent),
        BitEnumField("EffecterOpStateEventEnableMask_6", 0, 1, enableEvent),
        BitEnumField("EffecterOpStateEventEnableMask_5", 0, 1, enableEvent),
        BitEnumField("EffecterOpStateEventEnableMask_4", 0, 1, enableEvent),
        BitEnumField("EffecterOpStateEventEnableMask_3", 0, 1, enableEvent),
        BitEnumField("EffecterOpStateEventEnableMask_2", 0, 1, enableEvent),
        BitEnumField("EffecterOpStateEventEnableMask_1", 0, 1, enableEvent),
        BitEnumField("EffecterOpStateEventEnableMask_0", 0, 1, enableEvent),
        XByteField("StateValue_0", 0x00),
        XByteField("StateValue_1", 0x00),
        XByteField("StateValue_2", 0x00),
        XByteField("StateValue_3", 0x00),
        XByteField("StateValue_4", 0x00),
        XByteField("StateValue_5", 0x00),
        XByteField("StateValue_6", 0x00),
        XByteField("StateValue_7", 0x00),
    ]

    def extract_padding(self, s):
        return ("", s)


class EffecterAuxiliaryNamesStrings(Packet):
    name = "Effecter Auxiliary Names Strings"

    fields_desc = [
        StrField("NameLanguageTag", None, fmt="B"),
        StrField("EffecterName", None, fmt="B"),
    ]

    def extract_padding(self, s):
        return ("", s)


class EffecterAuxiliaryNamesFields(Packet):
    name = "Effecter Auxiliary Names Records"

    fields_desc = [
        ByteField("NameStringCount", 0x00),
        PacketListField(
            "EffecterNames",
            EffecterAuxiliaryNamesStrings(),
            EffecterAuxiliaryNamesStrings,
            count_from=lambda pkt: pkt.NameStringCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class EffecterAuxiliaryNamesPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Effecter Auxiliary Names"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XLEShortField("EffecterID", 0x0000),
        ByteField("EffecterCount", 0x00),
        PacketListField(
            "EffecterNames",
            EffecterAuxiliaryNamesFields(),
            EffecterAuxiliaryNamesFields,
            count_from=lambda pkt: pkt.EffecterCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class OEMEffecterSemanticStrings(Packet):
    name = "OEM Effecter Semantic Strings"

    fields_desc = [
        StrField("LanguageTag", None, fmt="B"),
        StrField("Name", None, fmt="B"),
    ]

    def extract_padding(self, s):
        return ("", s)


class OEMEffecterSemanticPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "OEM Effecter Semantics"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XByteField("OEMEffecterSemanticHandle", 0x00),
        XLEIntField("VendorIANA", 0x0000000000),
        XByteField("OEMEffecterSemanticID", 0x00),
        ByteField("StringCount", 0x00),
        PacketListField(
            "Names",
            OEMEffecterSemanticStrings(),
            OEMEffecterSemanticStrings,
            count_from=lambda pkt: pkt.StringCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class EntityAssociationContained(Packet):
    name = "Contained Entity"

    fields_desc = [
        LEShortEnumField("ContainedEntityType", 0x0000, entity_id_codes),
        LEShortField("ContainedEntityInstanceNumber", 0x0000),
        XLEShortField("ContainedEntityContainerID", 0x0000),
    ]

    def extract_padding(self, s):
        return ("", s)


class EntityAssociationPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Entity Association"

    fields_desc = [
        XLEShortField("ContainerID", 0x0000),
        ByteEnumField(
            "AssociationType",
            0,
            {0: "physicalToPhysicalContainment", 1: "logicalContainment"},
        ),
        LEShortEnumField("ContainerEntityType", 0x0000, entity_id_codes),
        LEShortField("ContainerEntityInstanceNumber", 0x0000),
        XLEShortField("ContainerEntityContainerID", 0x0000),
        ByteField("ContainedEntityCount", 0x00),
        PacketListField(
            "ContainedEntities",
            EntityAssociationContained(),
            EntityAssociationContained,
            count_from=lambda pkt: pkt.ContainedEntityCount,
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class EntityAuxiliaryNamesStrings(Packet):
    name = "Entity Auxiliary Names Strings"

    fields_desc = [
        StrField("NameLanguageTag", None, fmt="B"),
        StrField("EntityAuxName", None, fmt="B"),
    ]

    def extract_padding(self, s):
        return ("", s)


class EntityAuxiliaryNamesPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Entity Auxiliary Names"

    fields_desc = [
        LEShortEnumField("EntityType", 0x0000, entity_id_codes),
        LEShortField("EntityInstanceNumber", 0x0000),
        XLEShortField("EntityContainerID", 0x0000),
        LEShortField("SharedNameCount", 0x0000),
        ByteField("NameStringCount", 0x00),
        PacketListField(
            "EntityAuxiliaryNames",
            EntityAuxiliaryNamesStrings(),
            EntityAuxiliaryNamesStrings,
            count_from=lambda pkt: pkt.NameStringCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class OEMEntityIDStrings(Packet):
    name = "OEM Entity ID Strings"

    fields_desc = [
        StrField("EntityIDLanguageTag", None, fmt="B"),
        StrField("EntityIDName", None, fmt="B"),
    ]

    def extract_padding(self, s):
        return ("", s)


class OEMEntityIDPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "OEM EntityID"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XLEShortField("OEMEntityIDHandleValue", 0x0000),  # MSB is reserved
        XLEIntField("VendorIANA", 0x00000000),
        XLEShortField("VendorEntityID", 0x0000),  # MSB is reserved
        ByteField("StringCount", 0x00),
        PacketListField(
            "EntityIDStrings",
            OEMEntityIDStrings(),
            OEMEntityIDStrings,
            count_from=lambda pkt: pkt.StringCount,
        ),
    ]

    def extract_padding(self, s):
         return ("", s)


class InterruptAssociationFields(Packet):
    name = "Interrupt Association Fields"

    fields_desc = [
        XLEIntField("InterruptSourcePLDMTerminusHandle", 0x00000000),
        XLEShortField("InterruptSourceEntityType", 0x0000),
        LEShortField("InterruptSourceEntityInstanceNumber", 0x0000),
        XLEShortField("InterruptSourceEntityContainerID", 0x0000),
        XLEShortField("InterruptSourceSensorID", 0x0000),
    ]

    def extract_padding(self, s):
        return ("", s)


class InterruptAssociationPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Interrupt Association"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XLEShortField("SensorID", 0x0000),
        ByteEnumField(
            "SourceOrTargetSensor", 0, {0: "targetSensor", 1: "sourceSensor"}
        ),
        XLEShortField("InterruptTargetEntityType", 0x0000),
        LEShortField("InterruptTargetEntityInstanceNumber", 0x0000),
        XLEShortField("InterruptTargetEntityContainerID", 0x0000),
        ByteField("InterruptSourceEntityCount", 0x0000),
        PacketListField(
            "SourceEntityIdentificationInformation",
            InterruptAssociationFields(),
            InterruptAssociationFields,
            count_from=lambda pkt: pkt.InterruptSourceEntityCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class EventLogPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Event Log"

    fields_desc = [
        LEIntField("LogSize", 0x00000000),
        BitField("Reserved", 0, 5),
        BitEnumField("clearOnAge", 0, 1, supported_not_supported),
        BitEnumField("FIFO", 0, 1, supported_not_supported),
        BitEnumField("fillAndStop", 0, 1, supported_not_supported),
        ByteField("EntryIDTimeout", 0x00),
        ByteField("PerEntryOverhead", 0x00),
        ByteField("AllocationGranularity", 0x00),
        ByteField("PercentUsedResolution", 0x00),
    ]

    def extract_padding(self, s):
        return ("", s)


class FRURecordSetPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "FRU Record Set"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        XLEShortField("FRURecordSetIdentifier", 0x0000),
        LEShortEnumField("EntityType", 0x0000, entity_id_codes),
        LEShortField("EntityInstanceNumber", 0x0000),
        XLEShortField("ContainerID", 0x0000),
    ]

    def extract_padding(self, s):
        return ("", s)


class OEMDevicePDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "OEM Device"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x0000),
        ByteEnumField("CopyPDR",
            0,
            {
                0: "doNotCopy",
                1: "copyToPrimaryRepository"
            }
        ),
        XLEIntField("VendorIANA", 0x00000000),
        XLEShortField("OEMRecordID", 0x0000),
        LEShortField("DataLength", 0x0000),
        FieldListField(
            "VendorSpecificData",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.DataLength,
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class OEMPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "OEM PDR"

    fields_desc = [
        XLEIntField("VendorIANA", 0x00000000),
        XLEShortField("OEMRecordID", 0x0000),
        LEShortField("DataLength", 0x0000),
        FieldListField(
            "VendorSpecificData",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.DataLength,
        ),
    ]

    def extract_padding(self, s):
        return ("", s)


class CompactNumericSensorPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Compact Numeric Sensor"

    fields_desc = [
        XLEShortField("PLDMTerminusHandle", 0x00000000),
        XLEShortField("SensorID", 0x0000),
        LEShortEnumField("EntityType", 0x0000, entity_id_codes),
        LEShortField("EntityInstanceNumber", 0x0000),
        XLEShortField("ContainerID", 0x0000),
        ByteField("SensorNameStringByteLength", 0x00),
        ByteEnumField("BaseUnit", 0, SensorUnitsEnumeration),
        ByteField("UnitModifier", 0x00),
        ByteEnumField("OccurenceRate", 0, occurenceRate),
        BitField("Reserved_1", 0, 2),
        BitEnumField("FatalLowSupported", 0, 1, supported_not_supported),
        BitEnumField("FatalHighSupported", 0, 1, supported_not_supported),
        BitEnumField("CriticalLowSupported", 0, 1, supported_not_supported),
        BitEnumField("CriticalHighSupported", 0, 1, supported_not_supported),
        BitEnumField("WarningLowSupported", 0, 1, supported_not_supported),
        BitEnumField("WarningHighSupported", 0, 1, supported_not_supported),
        LEIntField("WarningHigh", 0x00000000),
        LEIntField("WarningLow", 0x00000000),
        LEIntField("CriticalHigh", 0x00000000),
        LEIntField("CriticalLow", 0x00000000),
        LEIntField("FatalHigh", 0x00000000),
        LEIntField("FatalLow", 0x00000000),
        StrLenField(
            "sensorNameString",
            b"",
            length_from=lambda pkt: pkt.SensorNameStringByteLength,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishResourceAdditionalResources(Packet):
    name = "Additional Resources"

    fields_desc = [
        XLEIntField("AdditionalResourceID", 0x00000000),
        XLEShortField("AdditionalResourceSubURILengthBytes", 0x0000),
        StrLenField(
            "AdditionalResourceSubURI",
            b"",
            length_from=lambda pkt: pkt.AdditionalResourceSubURILengthBytes,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishResourceAdditionalResources1(Packet):
    name = "Additional Resources"

    fields_desc = [
        XLEIntField("AdditionalResourceID", 0x00000000),
        XLEShortField("AdditionalResourceSubURILengthBytes", 0x0000),
        XByteField("AdditionalResourceSubURI", 0x00),
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishResourceOEMNames(Packet):
    name = "OEM Names"

    fields_desc = [
        FieldLenField("OEMNameLengthBytes", None, fmt="H", length_of="OEMName"),
        StrLenField("OEMName", b"", length_from=lambda pkt: pkt.OEMNameLengthBytes),
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishResourcePDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Redfish Resource"

    fields_desc = [
        XLEIntField("ResourceID", 0x00000000),
        BitField("Reserved_1", 0, 5),
        BitEnumField("IsCollection", 0, 1, true_false),
        BitEnumField("IsContainedInCollection", 0, 1, true_false),
        BitEnumField("IsDeviceRoot", 0, 1, true_false),
        XLEIntField("ContainingResourceID", 0x00000000),
        LEShortField("ProposedContainingResourceLengthBytes", 0x0000),
        StrLenField(
            "ProposedContainingResourceName",
            b"",
            length_from=lambda pkt: pkt.ProposedContainingResourceLengthBytes,
        ),
        LEShortField("SubURILengthBytes", 0x0000),
        MultipleTypeField(
            [
                (
                    XByteField("SubURI", 0x00),
                    lambda pkt: pkt.ContainingResourceID == 0x00000000,
                ),
                (
                    StrLenField(
                        "SubURI", b"", length_from=lambda pkt: pkt.SubURILengthBytes
                    ),
                    lambda pkt: pkt.ContainingResourceID != 0x00000000,
                ),
            ],
            XByteField("SubURI", 0x00),  # Default field
        ),
        LEShortField("AdditionalResourceIDCount", 0x0000),
        MultipleTypeField(
            [
                (
                    PacketListField(
                        "AdditionalResources",
                        RedfishResourceAdditionalResources(),
                        RedfishResourceAdditionalResources,
                        count_from=lambda pkt: pkt.AdditionalResourceIDCount,
                    ),
                    lambda pkt: pkt.ContainingResourceID != 0x00000000,
                ),
                (
                    PacketListField(
                        "AdditionalResources",
                        RedfishResourceAdditionalResources(),
                        RedfishResourceAdditionalResources,
                        count_from=lambda pkt: pkt.AdditionalResourceIDCount,
                    ),
                    lambda pkt: pkt.ContainingResourceID == 0x00000000,
                ),
            ],
            PacketListField(
                "AdditionalResources",
                RedfishResourceAdditionalResources(),
                RedfishResourceAdditionalResources,
            ),
        ),
        XLEIntField("MajorSchemaVersion", 0x00000000),
        LEShortField("MajorSchemaDictionaryLengthBytes", 0x0000),
        XLEIntField("MajorSchemaDictionarySignature", 0x00000000),
        ByteField("MajorSchemaNameLength", 0x00),
        StrLenField(
            "MajorSchemaName", b"", length_from=lambda pkt: pkt.MajorSchemaNameLength
        ),
        LEShortField("OEMCount", 0x0000),
        PacketListField(
            "OEMNames",
            RedfishResourceOEMNames(),
            RedfishResourceOEMNames,
            count_from=lambda pkt: pkt.OEMCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishEntityAssociationPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Redfish Entity Association"

    fields_desc = [
        XLEIntField("ContainingResourceID", 0x00000000),
        LEShortField("ProposedContainingResourceLengthBytes", 0x0000),
        StrLenField(
            "ProposedContainingResourceName",
            b"",
            length_from=lambda pkt: pkt.ProposedContainingResourceLengthBytes,
        ),
        ByteField("ContainedEntityCount", 0x0000),
        FieldListField(
            "ContainedEntity",
            [],
            XIntField("", 0x00000000),
            count_from=lambda pkt: pkt.ContainedEntityCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishActionRelatedResources(Packet):
    name = "Related Resources"

    fields_desc = [XLEIntField("RelatedResourceID", 0x00000000)]

    def extract_padding(self, s):
        return ("", s)


class RedfishActionNames(Packet):
    name = "Action Names"

    fields_desc = [
        FieldLenField("ActionNameLengthBytes", None, fmt="B", length_of="ActionName"),
        StrLenField(
            "ActionName", b"", length_from=lambda pkt: pkt.ActionNameLengthBytes
        ),
        FieldLenField("ActionPathLengthBytes", None, fmt="B", length_of="ActionPath"),
        StrLenField(
            "ActionPath", b"", length_from=lambda pkt: pkt.ActionPathLengthBytes
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class RedfishActionPDR(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "Redfish Action"

    fields_desc = [
        ByteField("ActionPDRIndex", 0x00),
        LEShortField("RelatedResourceCount", 0x0000),
        PacketListField(
            "RelatedResources",
            RedfishActionRelatedResources(),
            RedfishActionRelatedResources,
            count_from=lambda pkt: pkt.RelatedResourceCount,
        ),
        ByteField("ActionCount", 0x00),
        PacketListField(
            "ActionNames",
            RedfishActionNames(),
            RedfishActionNames,
            count_from=lambda pkt: pkt.ActionCount,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class PDR_HEADER(Packet):
    """this is the PLDM V1.2 format, per DSP0248"""

    name = "PDR Header"

    fields_desc = [
        XLEIntField("RecordHandle", 0x00000000),
        ByteField("PDRHeaderVersion", 0x00),
        ByteEnumField("PDRType", 0x00, PDRTypes),
        LEShortField("RecordChangeNumber", 0x0000),
        LEShortField("DataLength", 0),

        ConditionalField(
            PacketField("Terminus", TerminusLocatorPDR(), TerminusLocatorPDR),
            lambda pkt: pkt.PDRType == 1,
        ),
        ConditionalField(
            PacketField("NumericSensor", NumericSensorPDR(), NumericSensorPDR),
            lambda pkt: pkt.PDRType == 2,
        ),
        ConditionalField(
            PacketField(
                "NumericSensorInitialization",
                NumericSensorInitializationPDR(),
                NumericSensorInitializationPDR,
            ),
            lambda pkt: pkt.PDRType == 3,
        ),
        ConditionalField(
            PacketField("StateSensor", StateSensorPDR(), StateSensorPDR),
            lambda pkt: pkt.PDRType == 4,
        ),
        ConditionalField(
            PacketField(
                "StateSensorInitialization",
                StateSensorInitializationPDR(),
                StateSensorInitializationPDR,
            ),
            lambda pkt: pkt.PDRType == 5,
        ),
        ConditionalField(
            PacketField(
                "SensorAuxiliaryNames",
                SensorAuxiliaryNamesPDR(),
                SensorAuxiliaryNamesPDR,
            ),
            lambda pkt: pkt.PDRType == 6,
        ),
        ConditionalField(
            PacketField("OEMUnit", OEMUnitPDR(), OEMUnitPDR), lambda pkt: pkt.PDRType == 7
        ),
        ConditionalField(
            PacketField("OEMStateSet", OEMStatePDR(), OEMStatePDR),
            lambda pkt: pkt.PDRType == 8,
        ),
        ConditionalField(
            PacketField("NumericEffecter", NumericEffecterPDR(), NumericEffecterPDR),
            lambda pkt: pkt.PDRType == 9,
        ),
        ConditionalField(
            PacketField(
                "NumericEffecterInitialization",
                NumericEffecterInitializationPDR(),
                NumericEffecterInitializationPDR,
            ),
            lambda pkt: pkt.PDRType == 10,
        ),
        ConditionalField(
            PacketField("StateEffecter", StateEffecterPDR(), StateEffecterPDR),
            lambda pkt: pkt.PDRType == 11,
        ),
        ConditionalField(
            PacketField(
                "StateEffecterInitialization",
                StateEffecterInitializationPDR(),
                StateEffecterInitializationPDR,
            ),
            lambda pkt: pkt.PDRType == 12,
        ),
        ConditionalField(
            PacketField(
                "EffecterAuxiliaryNames",
                EffecterAuxiliaryNamesPDR(),
                EffecterAuxiliaryNamesPDR,
            ),
            lambda pkt: pkt.PDRType == 13,
        ),
        ConditionalField(
            PacketField(
                "OEMEffecterSemantic", OEMEffecterSemanticPDR(), OEMEffecterSemanticPDR
            ),
            lambda pkt: pkt.PDRType == 14,
        ),
        ConditionalField(
            PacketField(
                "EntityAssociation", EntityAssociationPDR(), EntityAssociationPDR
            ),
            lambda pkt: pkt.PDRType == 15,
        ),
        ConditionalField(
            PacketField(
                "EntityAuxiliaryNames",
                EntityAuxiliaryNamesPDR(),
                EntityAuxiliaryNamesPDR,
            ),
            lambda pkt: pkt.PDRType == 16,
        ),
        ConditionalField(
            PacketField("OEMEntityID", OEMEntityIDPDR(), OEMEntityIDPDR),
            lambda pkt: pkt.PDRType == 17,
        ),
        ConditionalField(
            PacketField(
                "InterruptAssociation",
                InterruptAssociationPDR(),
                InterruptAssociationPDR,
            ),
            lambda pkt: pkt.PDRType == 18,
        ),
        ConditionalField(
            PacketField("EventLog", EventLogPDR(), EventLogPDR),
            lambda pkt: pkt.PDRType == 19,
        ),
        ConditionalField(
            PacketField("FRURecordSet", FRURecordSetPDR(), FRURecordSetPDR),
            lambda pkt: pkt.PDRType == 20,
        ),
        ConditionalField(
            PacketField(
                "CompactNumericSensor",
                CompactNumericSensorPDR(),
                CompactNumericSensorPDR,
            ),
            lambda pkt: pkt.PDRType == 21,
        ),
        ConditionalField(
            PacketField("RedfishResource", RedfishResourcePDR(), RedfishResourcePDR),
            lambda pkt: pkt.PDRType == 22,
        ),
        ConditionalField(
            PacketField(
                "RedfishEntityAssociation",
                RedfishEntityAssociationPDR(),
                RedfishEntityAssociationPDR,
            ),
            lambda pkt: pkt.PDRType == 23,
        ),
        ConditionalField(
            PacketField("RedfishAction", RedfishActionPDR(), RedfishActionPDR),
            lambda pkt: pkt.PDRType == 24,
        ),
        ConditionalField(
            PacketField("OEMDevice", OEMDevicePDR(), OEMDevicePDR),
            lambda pkt: pkt.PDRType == 126,
        ),
        ConditionalField(
            PacketField("OEM", OEMPDR(), OEMPDR), lambda pkt: pkt.PDRType == 127
        ),
        ConditionalField(
            FieldListField(
                "RecordData",
                [],
                XByteField("", 0x00),
                count_from=lambda pkt: pkt.DataLength,
            ),
            lambda pkt: pkt.PDRType
            not in [
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
                21,
                22,
                23,
                24,
                126,
                127,
            ],
        )
    ]

    def extract_padding(self, s):
        return ("", s)
