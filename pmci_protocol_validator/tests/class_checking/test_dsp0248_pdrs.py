# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Verify PLDM Platform Descriptor Records (PDRs) Scapy classes

File : test_dsp0248_pdrs.py

Brief : Verify PLDM Platform Descriptor Records (PDRs) Scapy classes
"""

import pytest
from pmci_protocol_validator.pldm.classes.dsp0248_pdrs import *


@pytest.mark.parametrize("class_type", PDR_HEADER())
def test_PDR_HEADER(class_type):
    """Verify PDR_HEADER class"""

    assert (len(class_type.fields_desc) >= 6), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XLEIntField))     # RecordHandle
    assert (isinstance(class_type.fields_desc[1], ByteField))       # PDRHeaderVersion
    assert (isinstance(class_type.fields_desc[2], ByteEnumField))   # PDRType
    assert (isinstance(class_type.fields_desc[3], LEShortField))    # RecordChangeNumber
    assert (isinstance(class_type.fields_desc[4], LEShortField))    # DataLength

    assert (class_type.RecordHandle == 0)
    assert (class_type.PDRHeaderVersion == 0)
    assert (class_type.PDRType == 0)
    assert (class_type.RecordChangeNumber == 0)
    assert (class_type.DataLength == 0)
    return


@pytest.mark.parametrize("class_type", TerminusLocatorPDR())
def test_TerminusLocatorPDR(class_type):
    """Verify TerminusLocatorPDR class"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # Validity
    assert (isinstance(class_type.fields_desc[2], XByteField))      # TID
    assert (isinstance(class_type.fields_desc[3], XLEShortField))   # ContainerID
    assert (isinstance(class_type.fields_desc[4], ByteEnumField))   # TerminusLocatorType
    assert (isinstance(class_type.fields_desc[5], ByteField))       # TerminusLocatorValueSize
    assert (isinstance(class_type.fields_desc[6], FieldListField))  # RecordData

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.Validity == 0)
    assert (class_type.TID == 0)
    assert (class_type.ContainerID == 0)
    assert (class_type.TerminusLocatorType == 0)
    assert (class_type.TerminusLocatorValueSize == 0)
    assert (len(class_type.RecordData) == 0)
    return

@pytest.mark.parametrize("class_type", NumericSensorPDR())
def test_NumericSensorPDR(class_type):
    """Verify NumericSensorPDR initialization"""

    assert (len(class_type.fields_desc) == 59), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # SensorID
    assert (isinstance(class_type.fields_desc[2], LEShortEnumField))   # EntityType
    assert (isinstance(class_type.fields_desc[3], LEShortField))   # EntityInstanceNumber
    assert (isinstance(class_type.fields_desc[4], XLEShortField))   # ContainerID
    assert (isinstance(class_type.fields_desc[5], ByteEnumField))   # SensorInit
    assert (isinstance(class_type.fields_desc[6], ByteEnumField))   # SensorAuxiliaryNamesPDR

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)
    assert (class_type.SensorInit == 0)
    assert (class_type.SensorAuxiliaryNamesPDR == 0)

    assert (isinstance(class_type.fields_desc[7], ByteEnumField))   # BaseUnit
    assert (isinstance(class_type.fields_desc[8], ByteField))       # UnitModifier
    assert (isinstance(class_type.fields_desc[9], ByteEnumField))   # RateUnit
    assert (isinstance(class_type.fields_desc[10], XByteField))     # BaseOEMUnitHandle
    assert (isinstance(class_type.fields_desc[11], ByteEnumField))  # AuxUnit
    assert (isinstance(class_type.fields_desc[12], ByteField))      # AuxUnitModifier
    assert (isinstance(class_type.fields_desc[13], ByteEnumField))  # AuxRateUnit

    assert (class_type.BaseUnit == 0)
    assert (class_type.UnitModifier == 0)
    assert (class_type.RateUnit == 0)
    assert (class_type.BaseOEMUnitHandle == 0)
    assert (class_type.AuxUnit == 0)
    assert (class_type.AuxUnitModifier == 0)
    assert (class_type.AuxRateUnit == 0)

    assert (isinstance(class_type.fields_desc[14], ByteEnumField))  # Relationship
    assert (isinstance(class_type.fields_desc[15], XByteField))     # AuxOEMUnitHandle
    assert (isinstance(class_type.fields_desc[16], ByteEnumField))  # IsLinear
    assert (isinstance(class_type.fields_desc[17], ByteEnumField))  # SensorDataSize

    assert (class_type.Relationship == 0)
    assert (class_type.AuxOEMUnitHandle == 0)
    assert (class_type.IsLinear == 0)
    assert (class_type.SensorDataSize == 0)

    assert (isinstance(class_type.fields_desc[18], LEIeeeFloatField))   # Resolution
    assert (isinstance(class_type.fields_desc[19], LEIeeeFloatField))   # Offset
    assert (isinstance(class_type.fields_desc[20], LEShortField))       # Accuracy
    assert (isinstance(class_type.fields_desc[21], ByteField))          # PlusTolerance
    assert (isinstance(class_type.fields_desc[22], ByteField))          # MinusTolerance
    assert (isinstance(class_type.fields_desc[23], MultipleTypeField))  # HysteresisValue

    assert (class_type.Resolution == 0)
    assert (class_type.Offset == 0)
    assert (class_type.Accuracy == 0)
    assert (class_type.PlusTolerance == 0)
    assert (class_type.MinusTolerance == 0)
    assert (class_type.HysteresisValue == 0)

    assert (isinstance(class_type.fields_desc[24], BitField))       # Reserved_1
    assert (isinstance(class_type.fields_desc[25], BitEnumField))   # lowerThresholdFatal
    assert (isinstance(class_type.fields_desc[26], BitEnumField))   # lowerThresholdCritical
    assert (isinstance(class_type.fields_desc[27], BitEnumField))   # lowerThresholdWarning
    assert (isinstance(class_type.fields_desc[28], BitEnumField))   # upperThresholdFatal
    assert (isinstance(class_type.fields_desc[29], BitEnumField))   # upperThresholdCritical
    assert (isinstance(class_type.fields_desc[30], BitEnumField))   # upperThresholdWarning

    assert (class_type.Reserved_1 == 0)
    assert (class_type.lowerThresholdFatal == 0)
    assert (class_type.lowerThresholdCritical == 0)
    assert (class_type.lowerThresholdWarning == 0)
    assert (class_type.upperThresholdFatal == 0)
    assert (class_type.upperThresholdCritical == 0)
    assert (class_type.upperThresholdWarning == 0)

    assert (isinstance(class_type.fields_desc[31], BitField))       # Reserved_2
    assert (isinstance(class_type.fields_desc[32], BitEnumField))   # PLDMTerminusReturnsToOnlineCondition
    assert (isinstance(class_type.fields_desc[33], BitEnumField))   # SystemWarmResets
    assert (isinstance(class_type.fields_desc[34], BitEnumField))   # SystemHardResets
    assert (isinstance(class_type.fields_desc[35], BitEnumField))   # PLDMSubsystemPowerUp
    assert (isinstance(class_type.fields_desc[36], BitEnumField))   # InitializationAgentControllerRestartUpdate

    assert (class_type.Reserved_2 == 0)
    assert (class_type.PLDMTerminusReturnsToOnlineCondition == 0)
    assert (class_type.SystemWarmResets == 0)
    assert (class_type.SystemHardResets == 0)
    assert (class_type.PLDMSubsystemPowerUp == 0)
    assert (class_type.InitializationAgentControllerRestartUpdate == 0)

    assert (isinstance(class_type.fields_desc[37], LEIeeeFloatField))   # StateTransitionInterval
    assert (isinstance(class_type.fields_desc[38], LEIeeeFloatField))   # UpdateInterval
    assert (isinstance(class_type.fields_desc[39], MultipleTypeField))  # MaxReadable
    assert (isinstance(class_type.fields_desc[40], MultipleTypeField))  # MinReadable
    assert (isinstance(class_type.fields_desc[41], ByteEnumField))      # RangeFieldFormat

    assert (class_type.StateTransitionInterval == 0)
    assert (class_type.UpdateInterval == 0)
    assert (class_type.MaxReadable == 0)
    assert (class_type.MinReadable == 0)
    assert (class_type.RangeFieldFormat == 0)

    assert (isinstance(class_type.fields_desc[42], BitField))       # Reserved_3
    assert (isinstance(class_type.fields_desc[43], BitEnumField))   # FatalLowSupported
    assert (isinstance(class_type.fields_desc[44], BitEnumField))   # FatalHighSupported
    assert (isinstance(class_type.fields_desc[45], BitEnumField))   # CriticalLowSupported
    assert (isinstance(class_type.fields_desc[46], BitEnumField))   # CriticalHighSupported
    assert (isinstance(class_type.fields_desc[47], BitEnumField))   # NormalMinSupported
    assert (isinstance(class_type.fields_desc[48], BitEnumField))   # NormalMaxSupported
    assert (isinstance(class_type.fields_desc[49], BitEnumField))   # NominalValueSupported

    assert (class_type.Reserved_3 == 0)
    assert (class_type.FatalLowSupported == 0)
    assert (class_type.FatalHighSupported == 0)
    assert (class_type.CriticalLowSupported == 0)
    assert (class_type.CriticalHighSupported == 0)
    assert (class_type.NormalMinSupported == 0)
    assert (class_type.NormalMaxSupported == 0)
    assert (class_type.NominalValueSupported == 0)

    assert (isinstance(class_type.fields_desc[50], MultipleTypeField))  # NominalValue
    assert (isinstance(class_type.fields_desc[51], MultipleTypeField))  # NormalMax
    assert (isinstance(class_type.fields_desc[52], MultipleTypeField))  # NormalMIN
    assert (isinstance(class_type.fields_desc[53], MultipleTypeField))  # WarningHigh
    assert (isinstance(class_type.fields_desc[54], MultipleTypeField))  # WarningLow
    assert (isinstance(class_type.fields_desc[55], MultipleTypeField))  # CriticalHigh
    assert (isinstance(class_type.fields_desc[56], MultipleTypeField))  # CriticalLow
    assert (isinstance(class_type.fields_desc[57], MultipleTypeField))  # FatalHigh
    assert (isinstance(class_type.fields_desc[58], MultipleTypeField))  # FatalLow

    assert (class_type.NominalValue == 0)
    assert (class_type.NormalMax == 0)
    assert (class_type.NormalMin == 0)
    assert (class_type.WarningHigh == 0)
    assert (class_type.WarningLow == 0)
    assert (class_type.CriticalHigh == 0)
    assert (class_type.CriticalLow == 0)
    assert (class_type.FatalHigh == 0)
    assert (class_type.FatalLow == 0)
    return


@pytest.mark.parametrize("class_type", NumericSensorInitializationPDR())
def test_NumericSensorInitializationPDR(class_type):
    """Verify NumericSensorInitializationPDR class"""

    assert (len(class_type.fields_desc) == 23), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # SensorID
    assert (isinstance(class_type.fields_desc[2], BitField))        # Reserved_1
    assert (isinstance(class_type.fields_desc[3], BitEnumField))    # PLDMTerminusReturnsToOnlineCondition
    assert (isinstance(class_type.fields_desc[4], BitEnumField))    # SystemWarmResets
    assert (isinstance(class_type.fields_desc[5], BitEnumField))    # SystemHardResets
    assert (isinstance(class_type.fields_desc[6], BitEnumField))    # PLDMSubsystemPowerUp
    assert (isinstance(class_type.fields_desc[7], BitEnumField))    # InitializationAgentControllerRestartUpdate
    assert (isinstance(class_type.fields_desc[8], XByteField))      # SensorEnable

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.PLDMTerminusReturnsToOnlineCondition == 0)
    assert (class_type.SystemWarmResets == 0)
    assert (class_type.SystemHardResets == 0)
    assert (class_type.PLDMSubsystemPowerUp == 0)
    assert (class_type.InitializationAgentControllerRestartUpdate == 0)
    assert (class_type.SensorEnable == 0)

    assert (isinstance(class_type.fields_desc[9], BitField))        # Reserved_2
    assert (isinstance(class_type.fields_desc[10], BitEnumField))   # lowerThresholdFatal
    assert (isinstance(class_type.fields_desc[11], BitEnumField))   # lowerThresholdCritical
    assert (isinstance(class_type.fields_desc[12], BitEnumField))   # lowerThresholdWarning
    assert (isinstance(class_type.fields_desc[13], BitEnumField))   # upperThresholdFatal
    assert (isinstance(class_type.fields_desc[14], BitEnumField))   # upperThresholdCritical
    assert (isinstance(class_type.fields_desc[15], BitEnumField))   # upperThresholdWarning

    assert (class_type.Reserved_2 == 0)
    assert (class_type.lowerThresholdFatal == 0)
    assert (class_type.lowerThresholdCritical == 0)
    assert (class_type.lowerThresholdWarning == 0)
    assert (class_type.upperThresholdFatal == 0)
    assert (class_type.upperThresholdCritical == 0)
    assert (class_type.upperThresholdWarning == 0)

    assert (isinstance(class_type.fields_desc[16], ByteEnumField))   # SensorDataSize
    assert (class_type.SensorDataSize == 0)

    assert (isinstance(class_type.fields_desc[17], MultipleTypeField))  # UpperThresholdWarning
    assert (isinstance(class_type.fields_desc[18], MultipleTypeField))  # UpperThresholdCritical
    assert (isinstance(class_type.fields_desc[19], MultipleTypeField))  # UpperThresholdFatal
    assert (isinstance(class_type.fields_desc[20], MultipleTypeField))  # LowerThresholdWarning
    assert (isinstance(class_type.fields_desc[21], MultipleTypeField))  # LowerThresholdCritical
    assert (isinstance(class_type.fields_desc[22], MultipleTypeField))  # LowerThresholdFatal

    assert (class_type.UpperThresholdWarning == 0)
    assert (class_type.UpperThresholdCritical == 0)
    assert (class_type.UpperThresholdFatal == 0)
    assert (class_type.LowerThresholdWarning == 0)
    assert (class_type.LowerThresholdCritical == 0)
    assert (class_type.LowerThresholdFatal == 0)
    return


@pytest.mark.parametrize("class_type", StateSensorBitFields())
def test_StateSensorBitFields(class_type):
    """Verify StateSensorBitFields class"""

    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], BitEnumField))   # StateSetSupported_7
    assert (isinstance(class_type.fields_desc[1], BitEnumField))   # StateSetSupported_6
    assert (isinstance(class_type.fields_desc[2], BitEnumField))   # StateSetSupported_5
    assert (isinstance(class_type.fields_desc[3], BitEnumField))   # StateSetSupported_4
    assert (isinstance(class_type.fields_desc[4], BitEnumField))   # StateSetSupported_3
    assert (isinstance(class_type.fields_desc[5], BitEnumField))   # StateSetSupported_2
    assert (isinstance(class_type.fields_desc[6], BitEnumField))   # StateSetSupported_1
    assert (isinstance(class_type.fields_desc[7], BitEnumField))   # StateSetSupported_0

    assert (class_type.StateSetSupported_7 == 0)
    assert (class_type.StateSetSupported_6 == 0)
    assert (class_type.StateSetSupported_5 == 0)
    assert (class_type.StateSetSupported_4 == 0)
    assert (class_type.StateSetSupported_3 == 0)
    assert (class_type.StateSetSupported_2 == 0)
    assert (class_type.StateSetSupported_1 == 0)
    assert (class_type.StateSetSupported_0 == 0)
    return


@pytest.mark.parametrize("class_type", StateSensorFields())
def test_StateSensorFields(class_type):
    """Verify StateSensorFields class"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], LEShortField))    # StateSetID
    assert (isinstance(class_type.fields_desc[1], ByteField))       # PossibleStateSize
    assert (isinstance(class_type.fields_desc[2], PacketListField)) # PossibleStates

    assert (class_type.StateSetID == 0)
    assert (class_type.PossibleStateSize == 0)
    assert (class_type.PossibleStates is not None)
    return


@pytest.mark.parametrize("class_type", StateSensorPDR())
def test_StateSensorPDR(class_type):
    """Verify StateSensorPDR class"""

    assert (len(class_type.fields_desc) == 9), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))       # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))       # SensorID
    assert (isinstance(class_type.fields_desc[2], LEShortEnumField))    # EntityType
    assert (isinstance(class_type.fields_desc[3], LEShortField))        # EntityInstanceNumber
    assert (isinstance(class_type.fields_desc[4], XLEShortField))       # ContainerID
    assert (isinstance(class_type.fields_desc[5], ByteEnumField))       # SensorInit
    assert (isinstance(class_type.fields_desc[6], ByteEnumField))       # SensorAuxiliaryNamesPDR
    assert (isinstance(class_type.fields_desc[7], ByteField))           # CompositeSensorCount
    assert (isinstance(class_type.fields_desc[8], PacketListField))     # PossibleStatesFields

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)
    assert (class_type.SensorInit == 0)
    assert (class_type.SensorAuxiliaryNamesPDR == 0)
    assert (class_type.CompositeSensorCount == 0)
    assert (class_type.PossibleStatesFields is not None)
    return


@pytest.mark.parametrize("class_type", StateSensorInitializationPDR())
def test_StateSensorInitializationPDR(class_type):
    """Verify StateSensorInitializationPDR class"""

    assert (len(class_type.fields_desc) == 41), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # SensorID
    assert (isinstance(class_type.fields_desc[2], BitField))        # Reserved_1
    assert (isinstance(class_type.fields_desc[3], BitEnumField))    # PLDMTerminusReturnsToOnlineCondition
    assert (isinstance(class_type.fields_desc[4], BitEnumField))    # SystemWarmResets
    assert (isinstance(class_type.fields_desc[5], BitEnumField))    # SystemHardResets
    assert (isinstance(class_type.fields_desc[6], BitEnumField))    # PLDMSubsystemPowerUp
    assert (isinstance(class_type.fields_desc[7], BitEnumField))    # InitializationAgentControllerRestartUpdate
    assert (isinstance(class_type.fields_desc[8], XByteField))      # SensorEnable

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.PLDMTerminusReturnsToOnlineCondition == 0)
    assert (class_type.SystemWarmResets == 0)
    assert (class_type.SystemHardResets == 0)
    assert (class_type.PLDMSubsystemPowerUp == 0)
    assert (class_type.InitializationAgentControllerRestartUpdate == 0)
    assert (class_type.SensorEnable == 0)

    assert (isinstance(class_type.fields_desc[9], BitEnumField))    # SensorInitMask_7
    assert (isinstance(class_type.fields_desc[10], BitEnumField))   # SensorInitMask_6
    assert (isinstance(class_type.fields_desc[11], BitEnumField))   # SensorInitMask_5
    assert (isinstance(class_type.fields_desc[12], BitEnumField))   # SensorInitMask_4
    assert (isinstance(class_type.fields_desc[13], BitEnumField))   # SensorInitMask_3
    assert (isinstance(class_type.fields_desc[14], BitEnumField))   # SensorInitMask_2
    assert (isinstance(class_type.fields_desc[15], BitEnumField))   # SensorInitMask_1
    assert (isinstance(class_type.fields_desc[16], BitEnumField))   # SensorInitMask_0

    assert (class_type.SensorInitMask_7 == 0)
    assert (class_type.SensorInitMask_6 == 0)
    assert (class_type.SensorInitMask_5 == 0)
    assert (class_type.SensorInitMask_4 == 0)
    assert (class_type.SensorInitMask_3 == 0)
    assert (class_type.SensorInitMask_2 == 0)
    assert (class_type.SensorInitMask_1 == 0)
    assert (class_type.SensorInitMask_0 == 0)

    assert (isinstance(class_type.fields_desc[17], BitEnumField))   # sensorStateEventEnableMask_7
    assert (isinstance(class_type.fields_desc[18], BitEnumField))   # sensorStateEventEnableMask_6
    assert (isinstance(class_type.fields_desc[19], BitEnumField))   # sensorStateEventEnableMask_5
    assert (isinstance(class_type.fields_desc[20], BitEnumField))   # sensorStateEventEnableMask_4
    assert (isinstance(class_type.fields_desc[21], BitEnumField))   # sensorStateEventEnableMask_3
    assert (isinstance(class_type.fields_desc[22], BitEnumField))   # sensorStateEventEnableMask_2
    assert (isinstance(class_type.fields_desc[23], BitEnumField))   # sensorStateEventEnableMask_1
    assert (isinstance(class_type.fields_desc[24], BitEnumField))   # sensorStateEventEnableMask_0

    assert (class_type.sensorStateEventEnableMask_7 == 0)
    assert (class_type.sensorStateEventEnableMask_6 == 0)
    assert (class_type.sensorStateEventEnableMask_5 == 0)
    assert (class_type.sensorStateEventEnableMask_4 == 0)
    assert (class_type.sensorStateEventEnableMask_3 == 0)
    assert (class_type.sensorStateEventEnableMask_2 == 0)
    assert (class_type.sensorStateEventEnableMask_1 == 0)
    assert (class_type.sensorStateEventEnableMask_0 == 0)

    assert (isinstance(class_type.fields_desc[25], BitEnumField))   # SensorEventRearm_7
    assert (isinstance(class_type.fields_desc[26], BitEnumField))   # SensorEventRearm_6
    assert (isinstance(class_type.fields_desc[27], BitEnumField))   # SensorEventRearm_5
    assert (isinstance(class_type.fields_desc[28], BitEnumField))   # SensorEventRearm_4
    assert (isinstance(class_type.fields_desc[29], BitEnumField))   # SensorEventRearm_3
    assert (isinstance(class_type.fields_desc[30], BitEnumField))   # SensorEventRearm_2
    assert (isinstance(class_type.fields_desc[31], BitEnumField))   # SensorEventRearm_1
    assert (isinstance(class_type.fields_desc[32], BitEnumField))   # SensorEventRearm_0

    assert (class_type.SensorEventRearm_7 == 0)
    assert (class_type.SensorEventRearm_6 == 0)
    assert (class_type.SensorEventRearm_5 == 0)
    assert (class_type.SensorEventRearm_4 == 0)
    assert (class_type.SensorEventRearm_3 == 0)
    assert (class_type.SensorEventRearm_2 == 0)
    assert (class_type.SensorEventRearm_1 == 0)
    assert (class_type.SensorEventRearm_0 == 0)

    assert (isinstance(class_type.fields_desc[33], XByteField))  # StateValue_7
    assert (isinstance(class_type.fields_desc[34], XByteField))  # StateValue_6
    assert (isinstance(class_type.fields_desc[35], XByteField))  # StateValue_5
    assert (isinstance(class_type.fields_desc[36], XByteField))  # StateValue_4
    assert (isinstance(class_type.fields_desc[37], XByteField))  # StateValue_3
    assert (isinstance(class_type.fields_desc[38], XByteField))  # StateValue_2
    assert (isinstance(class_type.fields_desc[39], XByteField))  # StateValue_1
    assert (isinstance(class_type.fields_desc[40], XByteField))  # StateValue_0

    assert (class_type.StateValue_7 == 0)
    assert (class_type.StateValue_6 == 0)
    assert (class_type.StateValue_5 == 0)
    assert (class_type.StateValue_4 == 0)
    assert (class_type.StateValue_3 == 0)
    assert (class_type.StateValue_2 == 0)
    assert (class_type.StateValue_1 == 0)
    assert (class_type.StateValue_0 == 0)
    return


@pytest.mark.parametrize("class_type", NamesFieldsSensorAuxiliaryNames())
def test_NamesFieldsSensorAuxiliaryNames(class_type):
    """Verify NamesFieldsSensorAuxiliaryNames class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], StrField))   # NameLanguageTag
    assert (isinstance(class_type.fields_desc[1], StrField))   # SensorName

    assert (class_type.NameLanguageTag is None)
    assert (class_type.SensorName is None)
    return


@pytest.mark.parametrize("class_type", SensorAuxiliaryNamesFields())
def test_SensorAuxiliaryNamesFields(class_type):
    """Verify SensorAuxiliaryNamesFields class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], ByteField))       # NameStringCount
    assert (isinstance(class_type.fields_desc[1], PacketListField)) # NameStrings

    assert (class_type.NameStringCount == 0)
    assert (class_type.NameStrings is not None)
    return


@pytest.mark.parametrize("class_type", SensorAuxiliaryNamesPDR())
def test_SensorAuxiliaryNamesPDR(class_type):
    """Verify SensorAuxiliaryNamesPDR class"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # SensorID
    assert (isinstance(class_type.fields_desc[2], ByteField))       # SensorCount
    assert (isinstance(class_type.fields_desc[3], PacketListField)) # Sensors

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.SensorCount == 0)
    assert (class_type.Sensors is not None)
    return


@pytest.mark.parametrize("class_type", OEMUnitStrings())
def test_OEMUnitStrings(class_type):
    """Verify OEMUnitStrings class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], StrField))   # UnitLanguageTag
    assert (isinstance(class_type.fields_desc[1], StrField))   # UnitName

    assert (class_type.UnitLanguageTag is None)
    assert (class_type.UnitName is None)
    return


@pytest.mark.parametrize("class_type", OEMUnitPDR())
def test_OEMUnitPDR(class_type):
    """Verify OEMUnitPDR class"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XByteField))      # OEMUnitHandle
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # VendorIANA
    assert (isinstance(class_type.fields_desc[3], XByteField))      # OEMUnitID
    assert (isinstance(class_type.fields_desc[4], ByteField))       # StringCount
    assert (isinstance(class_type.fields_desc[5], PacketListField)) # UnitNames

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.OEMUnitHandle == 0)
    assert (class_type.VendorIANA == 0)
    assert (class_type.OEMUnitID == 0)
    assert (class_type.StringCount == 0)
    assert (class_type.UnitNames is not None)
    return


@pytest.mark.parametrize("class_type", OEMStateStrings())
def test_OEMStateStrings(class_type):
    """Verify OEMStateStrings class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], StrField))   # StateLanguageTag
    assert (isinstance(class_type.fields_desc[1], StrField))   # StateName

    assert (class_type.StateLanguageTag is None)
    assert (class_type.StateName is None)
    return


@pytest.mark.parametrize("class_type", OEMStateValueRecordFields())
def test_OEMStateValueRecordFields(class_type):
    """Verify OEMStateValueRecordFields class"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XByteField))      # MinStateValue
    assert (isinstance(class_type.fields_desc[1], XByteField))      # MaxStateValue
    assert (isinstance(class_type.fields_desc[2], XByteField))      # StringCount
    assert (isinstance(class_type.fields_desc[3], PacketListField)) # StateNames

    assert (class_type.MinStateValue == 0)
    assert (class_type.MaxStateValue == 0)
    assert (class_type.StringCount == 0)
    assert (class_type.StateNames is not None)
    return


@pytest.mark.parametrize("class_type", OEMStatePDR())
def test_OEMStatePDR(class_type):
    """Verify OEMStatePDR class"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.PLDMTerminusHandle == 0)
    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # OEMStateSetIDHandle
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # VendorIANA
    assert (isinstance(class_type.fields_desc[3], XLEShortField))   # OEMStateSetID
    assert (isinstance(class_type.fields_desc[4], ByteEnumField))   # UnspecifiedValueHint
    assert (isinstance(class_type.fields_desc[5], ByteField))       # StateCount
    assert (isinstance(class_type.fields_desc[6], PacketListField)) # OEMStateValueRecords

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.OEMStateSetIDHandle == 0)
    assert (class_type.VendorIANA == 0)
    assert (class_type.OEMStateSetID == 0)
    assert (class_type.UnspecifiedValueHint == 0)
    assert (class_type.StateCount == 0)
    assert (class_type.OEMStateValueRecords is not None)
    return


@pytest.mark.parametrize("class_type", NumericEffecterPDR())
def test_NumericEffecterPDR(class_type):
    """Verify NumericEffecterPDR initialization"""

    assert (len(class_type.fields_desc) == 38), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))     # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))     # EffecterID
    assert (isinstance(class_type.fields_desc[2], LEShortEnumField))  # EntityType
    assert (isinstance(class_type.fields_desc[3], LEShortField))      # EntityInstanceNumber
    assert (isinstance(class_type.fields_desc[4], XLEShortField))     # ContainerID
    assert (isinstance(class_type.fields_desc[5], XLEShortField))     # EffecterSemanticID
    assert (isinstance(class_type.fields_desc[6], ByteEnumField))     # EffecterInit
    assert (isinstance(class_type.fields_desc[7], ByteEnumField))     # EffecterAuxiliaryNamesPDR

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.EffecterID == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)
    assert (class_type.EffecterSemanticID == 0)
    assert (class_type.EffecterInit == 0)
    assert (class_type.EffecterAuxiliaryNamesPDR == 0)

    assert (isinstance(class_type.fields_desc[8], ByteEnumField))   # BaseUnit
    assert (isinstance(class_type.fields_desc[9], ByteField))       # UnitModifier
    assert (isinstance(class_type.fields_desc[10], ByteEnumField))  # RateUnit
    assert (isinstance(class_type.fields_desc[11], XByteField))     # BaseOEMUnitHandle
    assert (isinstance(class_type.fields_desc[12], ByteEnumField))  # AuxUnit
    assert (isinstance(class_type.fields_desc[13], ByteField))      # AuxUnitModifier
    assert (isinstance(class_type.fields_desc[14], ByteEnumField))  # AuxRateUnit
    assert (isinstance(class_type.fields_desc[15], XByteField))     # AuxOEMUnitHandle

    assert (class_type.BaseUnit == 0)
    assert (class_type.UnitModifier == 0)
    assert (class_type.RateUnit == 0)
    assert (class_type.BaseOEMUnitHandle == 0)
    assert (class_type.AuxUnit == 0)
    assert (class_type.AuxUnitModifier == 0)
    assert (class_type.AuxRateUnit == 0)
    assert (class_type.AuxOEMUnitHandle == 0)

    assert (isinstance(class_type.fields_desc[16], ByteEnumField))     # IsLinear
    assert (isinstance(class_type.fields_desc[17], ByteEnumField))     # EffecterDataSize
    assert (isinstance(class_type.fields_desc[18], LEIeeeFloatField))  # Resolution
    assert (isinstance(class_type.fields_desc[19], LEIeeeFloatField))  # Offset
    assert (isinstance(class_type.fields_desc[20], LEShortField))      # Accuracy
    assert (isinstance(class_type.fields_desc[21], ByteField))         # PlusTolerance
    assert (isinstance(class_type.fields_desc[22], ByteField))         # MinusTolerance

    assert (class_type.IsLinear == 0)
    assert (class_type.EffecterDataSize == 0)
    assert (class_type.Resolution == 0)
    assert (class_type.Offset == 0)
    assert (class_type.Accuracy == 0)
    assert (class_type.PlusTolerance == 0)
    assert (class_type.MinusTolerance == 0)

    assert (isinstance(class_type.fields_desc[23], LEIeeeFloatField))   # StateTransitionInterval
    assert (isinstance(class_type.fields_desc[24], MultipleTypeField))   # MaxSettable
    assert (isinstance(class_type.fields_desc[25], MultipleTypeField))   # MinSettable

    assert (class_type.StateTransitionInterval == 0)
    assert (class_type.MaxSettable == 0)
    assert (class_type.MinSettable == 0)


    assert (isinstance(class_type.fields_desc[26], ByteEnumField))  # RangeFieldFormat
    assert (isinstance(class_type.fields_desc[27], BitField))       # Reserved_1
    assert (isinstance(class_type.fields_desc[28], BitEnumField))   # RatedMinSupported
    assert (isinstance(class_type.fields_desc[29], BitEnumField))   # RatedMaxSupported
    assert (isinstance(class_type.fields_desc[30], BitEnumField))   # NormalMinSupported
    assert (isinstance(class_type.fields_desc[31], BitEnumField))   # NormalMaxSupported
    assert (isinstance(class_type.fields_desc[32], BitEnumField))   # NominalValueSupported

    assert (class_type.RangeFieldFormat == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.RatedMinSupported == 0)
    assert (class_type.RatedMaxSupported == 0)
    assert (class_type.NormalMinSupported == 0)
    assert (class_type.NormalMaxSupported == 0)
    assert (class_type.NominalValueSupported == 0)

    assert (isinstance(class_type.fields_desc[33], MultipleTypeField))   # NominalValue
    assert (isinstance(class_type.fields_desc[34], MultipleTypeField))   # NormalMax
    assert (isinstance(class_type.fields_desc[35], MultipleTypeField))   # NormalMin
    assert (isinstance(class_type.fields_desc[36], MultipleTypeField))   # RatedMax
    assert (isinstance(class_type.fields_desc[37], MultipleTypeField))   # RatedMin

    assert (class_type.NominalValue == 0)
    assert (class_type.NormalMax == 0)
    assert (class_type.NormalMin == 0)
    assert (class_type.RatedMax == 0)
    assert (class_type.RatedMin == 0)
    return


@pytest.mark.parametrize("class_type", NumericEffecterInitializationPDR())
def test_NumericEffecterInitializationPDR(class_type):
    """Verify NumericEffecterInitializationPDR class"""

    assert (len(class_type.fields_desc) == 11), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))       # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))       # EffecterID
    assert (isinstance(class_type.fields_desc[2], XByteField))          # EffecterEnable
    assert (isinstance(class_type.fields_desc[3], BitField))            # Reserved_1
    assert (isinstance(class_type.fields_desc[4], BitEnumField))        # PLDMTerminusReturnsToOnlineCondition
    assert (isinstance(class_type.fields_desc[5], BitEnumField))        # SystemWarmResets
    assert (isinstance(class_type.fields_desc[6], BitEnumField))        # SystemHardResets
    assert (isinstance(class_type.fields_desc[7], BitEnumField))        # PLDMSubsystemPowerUp
    assert (isinstance(class_type.fields_desc[8], BitEnumField))        # InitializationAgentControllerRestartUpdate
    assert (isinstance(class_type.fields_desc[9], ByteEnumField))       # EffecterDataSize
    assert (isinstance(class_type.fields_desc[10], MultipleTypeField))  # EffecterData

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.EffecterID == 0)
    assert (class_type.EffecterEnable == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.PLDMTerminusReturnsToOnlineCondition == 0)
    assert (class_type.SystemWarmResets == 0)
    assert (class_type.SystemHardResets == 0)
    assert (class_type.PLDMSubsystemPowerUp == 0)
    assert (class_type.InitializationAgentControllerRestartUpdate == 0)
    assert (class_type.EffecterDataSize == 0)
    assert (class_type.EffecterData == 0)
    return


@pytest.mark.parametrize("class_type", StateEffecterFields())
def test_StateEffecterFields(class_type):
    """Verify StateEffecterFields class"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], LEShortField))    # StateSetID
    assert (isinstance(class_type.fields_desc[1], ByteField))       # PossibleStateSize
    assert (isinstance(class_type.fields_desc[2], PacketListField)) # PossibleStates

    assert (class_type.StateSetID == 0)
    assert (class_type.PossibleStateSize == 0)
    assert (class_type.PossibleStates is not None)
    return


@pytest.mark.parametrize("class_type", StateEffecterBitFields())
def test_StateEffecterPDR(class_type):
    """Verify StateEffecterBitFields class"""

    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], BitEnumField))   # StateSetSupported_7
    assert (isinstance(class_type.fields_desc[1], BitEnumField))   # StateSetSupported_6
    assert (isinstance(class_type.fields_desc[2], BitEnumField))   # StateSetSupported_5
    assert (isinstance(class_type.fields_desc[3], BitEnumField))   # StateSetSupported_4
    assert (isinstance(class_type.fields_desc[4], BitEnumField))   # StateSetSupported_3
    assert (isinstance(class_type.fields_desc[5], BitEnumField))   # StateSetSupported_2
    assert (isinstance(class_type.fields_desc[6], BitEnumField))   # StateSetSupported_1
    assert (isinstance(class_type.fields_desc[7], BitEnumField))   # StateSetSupported_0

    assert (class_type.StateSetSupported_7 == 0)
    assert (class_type.StateSetSupported_6 == 0)
    assert (class_type.StateSetSupported_5 == 0)
    assert (class_type.StateSetSupported_4 == 0)
    assert (class_type.StateSetSupported_3 == 0)
    assert (class_type.StateSetSupported_2 == 0)
    assert (class_type.StateSetSupported_1 == 0)
    assert (class_type.StateSetSupported_0 == 0)
    return


@pytest.mark.parametrize("class_type", StateEffecterPDR())
def test_StateEffecterPDR(class_type):
    """Verify StateEffecterPDR class"""

    assert (len(class_type.fields_desc) == 10), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))       # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))       # EffecterID
    assert (isinstance(class_type.fields_desc[2], LEShortEnumField))    # EntityType
    assert (isinstance(class_type.fields_desc[3], LEShortField))        # EntityInstanceNumber
    assert (isinstance(class_type.fields_desc[4], XLEShortField))       # ContainerID
    assert (isinstance(class_type.fields_desc[5], XLEShortField))       # EffecterSemanticID
    assert (isinstance(class_type.fields_desc[6], ByteEnumField))       # EffecterInit
    assert (isinstance(class_type.fields_desc[7], ByteEnumField))       # EffecterDescriptionPDR
    assert (isinstance(class_type.fields_desc[8], ByteField))           # CompositeEffecterCount
    assert (isinstance(class_type.fields_desc[9], PacketListField))     # PossibleStatesFields

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.EffecterID == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)
    assert (class_type.EffecterSemanticID == 0)
    assert (class_type.EffecterInit == 0)
    assert (class_type.EffecterDescriptionPDR == 0)
    assert (class_type.CompositeEffecterCount == 0)
    assert (class_type.PossibleStatesFields is not None)
    return


@pytest.mark.parametrize("class_type", StateEffecterInitializationPDR())
def test_StateEffecterInitializationPDR(class_type):
    """Verify StateEffecterInitializationPDR class"""

    assert (len(class_type.fields_desc) == 36), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))     # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))     # EffecterID
    assert (isinstance(class_type.fields_desc[2], LEShortEnumField))  # EntityType
    assert (isinstance(class_type.fields_desc[3], LEShortField))      # EntityInstanceNumber
    assert (isinstance(class_type.fields_desc[4], XLEShortField))     # ContainerID
    assert (isinstance(class_type.fields_desc[5], BitField))          # Reserved_1
    assert (isinstance(class_type.fields_desc[6], BitEnumField))      # PLDMTerminusReturnsToOnlineCondition
    assert (isinstance(class_type.fields_desc[7], BitEnumField))      # SystemWarmResets
    assert (isinstance(class_type.fields_desc[8], BitEnumField))      # SystemHardResets
    assert (isinstance(class_type.fields_desc[9], BitEnumField))      # PLDMSubsystemPowerUp
    assert (isinstance(class_type.fields_desc[10], BitEnumField))     # InitializationAgentControllerRestartUpdate
    assert (isinstance(class_type.fields_desc[11], XByteField))       # EffecterEnable

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.EffecterID == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.PLDMTerminusReturnsToOnlineCondition == 0)
    assert (class_type.SystemWarmResets == 0)
    assert (class_type.SystemHardResets == 0)
    assert (class_type.PLDMSubsystemPowerUp == 0)
    assert (class_type.InitializationAgentControllerRestartUpdate == 0)
    assert (class_type.EffecterEnable == 0)

    assert (isinstance(class_type.fields_desc[12], BitEnumField))   # EffecterInitMask_7
    assert (isinstance(class_type.fields_desc[13], BitEnumField))   # EffecterInitMask_6
    assert (isinstance(class_type.fields_desc[14], BitEnumField))   # EffecterInitMask_5
    assert (isinstance(class_type.fields_desc[15], BitEnumField))   # EffecterInitMask_4
    assert (isinstance(class_type.fields_desc[16], BitEnumField))   # EffecterInitMask_3
    assert (isinstance(class_type.fields_desc[17], BitEnumField))   # EffecterInitMask_2
    assert (isinstance(class_type.fields_desc[18], BitEnumField))   # EffecterInitMask_1
    assert (isinstance(class_type.fields_desc[19], BitEnumField))   # EffecterInitMask_0

    assert (class_type.EffecterInitMask_7 == 0)
    assert (class_type.EffecterInitMask_6 == 0)
    assert (class_type.EffecterInitMask_5 == 0)
    assert (class_type.EffecterInitMask_4 == 0)
    assert (class_type.EffecterInitMask_3 == 0)
    assert (class_type.EffecterInitMask_2 == 0)
    assert (class_type.EffecterInitMask_1 == 0)
    assert (class_type.EffecterInitMask_0 == 0)

    assert (isinstance(class_type.fields_desc[20], BitEnumField))   # EffecterOpStateEventEnableMask_7
    assert (isinstance(class_type.fields_desc[21], BitEnumField))   # EffecterOpStateEventEnableMask_6
    assert (isinstance(class_type.fields_desc[22], BitEnumField))   # EffecterOpStateEventEnableMask_5
    assert (isinstance(class_type.fields_desc[23], BitEnumField))   # EffecterOpStateEventEnableMask_4
    assert (isinstance(class_type.fields_desc[24], BitEnumField))   # EffecterOpStateEventEnableMask_3
    assert (isinstance(class_type.fields_desc[25], BitEnumField))   # EffecterOpStateEventEnableMask_2
    assert (isinstance(class_type.fields_desc[26], BitEnumField))   # EffecterOpStateEventEnableMask_1
    assert (isinstance(class_type.fields_desc[27], BitEnumField))   # EffecterOpStateEventEnableMask_0

    assert (class_type.EffecterOpStateEventEnableMask_7 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_6 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_5 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_4 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_3 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_2 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_1 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_0 == 0)

    assert (isinstance(class_type.fields_desc[28], XByteField))     # StateValue_0
    assert (isinstance(class_type.fields_desc[29], XByteField))     # StateValue_1
    assert (isinstance(class_type.fields_desc[30], XByteField))     # StateValue_2
    assert (isinstance(class_type.fields_desc[31], XByteField))     # StateValue_3
    assert (isinstance(class_type.fields_desc[32], XByteField))     # StateValue_4
    assert (isinstance(class_type.fields_desc[33], XByteField))     # StateValue_5
    assert (isinstance(class_type.fields_desc[34], XByteField))     # StateValue_6
    assert (isinstance(class_type.fields_desc[35], XByteField))     # StateValue_7

    assert (class_type.StateValue_0 == 0)
    assert (class_type.StateValue_1 == 0)
    assert (class_type.StateValue_2 == 0)
    assert (class_type.StateValue_3 == 0)
    assert (class_type.StateValue_4 == 0)
    assert (class_type.StateValue_5 == 0)
    assert (class_type.StateValue_6 == 0)
    assert (class_type.StateValue_7 == 0)
    return


@pytest.mark.parametrize("class_type", EffecterAuxiliaryNamesStrings())
def test_EffecterAuxiliaryNamesStrings(class_type):
    """Verify EffecterAuxiliaryNamesStrings class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], StrField))    # NameLanguageTag
    assert (isinstance(class_type.fields_desc[1], StrField))    # EffecterName

    assert (class_type.NameLanguageTag is None)
    assert (class_type.EffecterName is None)
    return


@pytest.mark.parametrize("class_type", EffecterAuxiliaryNamesFields())
def test_EffecterAuxiliaryNamesFields(class_type):
    """Verify EffecterAuxiliaryNamesFields class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], ByteField))       # NameStringCount
    assert (isinstance(class_type.fields_desc[1], PacketListField)) # EffecterNames

    assert (class_type.NameStringCount == 0)
    assert (class_type.EffecterNames is not None)
    return


@pytest.mark.parametrize("class_type", EffecterAuxiliaryNamesPDR())
def test_EffecterAuxiliaryNamesPDR(class_type):
    """Verify EffecterAuxiliaryNamesPDR class"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # EffecterID
    assert (isinstance(class_type.fields_desc[2], ByteField))       # EffecterCount
    assert (isinstance(class_type.fields_desc[3], PacketListField)) # EffecterNames

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.EffecterID == 0)
    assert (class_type.EffecterCount == 0)
    assert (class_type.EffecterNames is not None)
    return


@pytest.mark.parametrize("class_type", OEMEffecterSemanticStrings())
def test_OEMEffecterSemanticStrings(class_type):
    """Verify OEMEffecterSemanticStrings class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], StrField))   # LanguageTag
    assert (isinstance(class_type.fields_desc[1], StrField))   # Name

    assert (class_type.LanguageTag is None)
    assert (class_type.Name is None)
    return


@pytest.mark.parametrize("class_type", OEMEffecterSemanticPDR())
def test_OEMEffecterSemanticPDR(class_type):
    """Verify OEMEffecterSemanticPDR class"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XByteField))      # OEMEffecterSemanticHandle
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # OEMEffecterSemanticID
    assert (isinstance(class_type.fields_desc[3], XByteField))      # VendorIANA
    assert (isinstance(class_type.fields_desc[4], ByteField))       # StringCount
    assert (isinstance(class_type.fields_desc[5], PacketListField)) # Names

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.OEMEffecterSemanticHandle == 0)
    assert (class_type.OEMEffecterSemanticID == 0)
    assert (class_type.VendorIANA == 0)
    assert (class_type.StringCount == 0)
    assert (class_type.Names is not None)
    return


@pytest.mark.parametrize("class_type", EntityAssociationContained())
def test_EntityAssociationContained(class_type):
    """Verify EntityAssociationContained class"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], LEShortEnumField))  # ContainedEntityType
    assert (isinstance(class_type.fields_desc[1], LEShortField))      # ContainedEntityInstanceNumber
    assert (isinstance(class_type.fields_desc[2], XLEShortField))     # ContainedEntityContainerID

    assert (class_type.ContainedEntityType == 0)
    assert (class_type.ContainedEntityInstanceNumber == 0)
    assert (class_type.ContainedEntityContainerID == 0)
    return


@pytest.mark.parametrize("class_type", EntityAssociationPDR())
def test_EntityAssociationPDR(class_type):
    """Verify EntityAssociationPDR class"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))     # ContainerID
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))     # AssociationType
    assert (isinstance(class_type.fields_desc[2], LEShortEnumField))  # ContainerEntityType
    assert (isinstance(class_type.fields_desc[3], LEShortField))      # ContainerEntityInstanceNumber
    assert (isinstance(class_type.fields_desc[4], XLEShortField))     # ContainerEntityContainerID
    assert (isinstance(class_type.fields_desc[5], ByteField))         # ContainedEntityCount
    assert (isinstance(class_type.fields_desc[6], PacketListField))   # ContainedEntities

    assert (class_type.ContainerID == 0)
    assert (class_type.AssociationType == 0)
    assert (class_type.ContainerEntityType == 0)
    assert (class_type.ContainerEntityInstanceNumber == 0)
    assert (class_type.ContainerEntityContainerID == 0)
    assert (class_type.ContainedEntityCount == 0)
    assert (class_type.ContainedEntities is not None)
    return


@pytest.mark.parametrize("class_type", EntityAuxiliaryNamesStrings())
def test_EntityAuxiliaryNamesStrings(class_type):
    """Verify EntityAuxiliaryNamesStrings class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], StrField))    # NameLanguageTag
    assert (isinstance(class_type.fields_desc[1], StrField))    # EntityAuxName

    assert (class_type.NameLanguageTag is None)
    assert (class_type.EntityAuxName is None)
    return


@pytest.mark.parametrize("class_type", EntityAuxiliaryNamesPDR())
def test_EntityAuxiliaryNamesPDR(class_type):
    """Verify EntityAuxiliaryNamesPDR class"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.EntityType == 0)
    assert (isinstance(class_type.fields_desc[0], LEShortEnumField))    # EntityType
    assert (isinstance(class_type.fields_desc[1], LEShortField))        # EntityInstanceNumber
    assert (isinstance(class_type.fields_desc[2], XLEShortField))       # EntityContainerID
    assert (isinstance(class_type.fields_desc[3], LEShortField))        # SharedNameCount
    assert (isinstance(class_type.fields_desc[4], ByteField))           # NameStringCount
    assert (isinstance(class_type.fields_desc[5], PacketListField))     # EntityAuxiliaryNames

    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.EntityContainerID == 0)
    assert (class_type.SharedNameCount == 0)
    assert (class_type.NameStringCount == 0)
    assert (class_type.EntityAuxiliaryNames is not None)
    return


@pytest.mark.parametrize("class_type", OEMEntityIDStrings())
def test_OEMEntityIDStrings(class_type):
    """Verify OEMEntityIDStrings class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], StrField))    # EntityIDLanguageTag
    assert (isinstance(class_type.fields_desc[1], StrField))    # EntityIDName

    assert (class_type.EntityIDLanguageTag is None)
    assert (class_type.EntityIDName is None)
    return


@pytest.mark.parametrize("class_type", OEMEntityIDPDR())
def test_OEMEntityIDPDR(class_type):
    """Verify OEMEntityIDPDR class"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))    # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))    # OEMEntityIDHandleValue
    assert (isinstance(class_type.fields_desc[2], XLEIntField))      # VendorIANA
    assert (isinstance(class_type.fields_desc[3], XLEShortField))    # VendorEntityID
    assert (isinstance(class_type.fields_desc[4], ByteField))        # StringCount
    assert (isinstance(class_type.fields_desc[5], PacketListField))  # EntityIDStrings

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.OEMEntityIDHandleValue == 0)
    assert (class_type.VendorIANA == 0)
    assert (class_type.VendorEntityID == 0)
    assert (class_type.StringCount == 0)
    assert (class_type.EntityIDStrings is not None)
    return


@pytest.mark.parametrize("class_type", InterruptAssociationFields())
def test_InterruptAssociationFields(class_type):
    """Verify InterruptAssociationFields class"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEIntField))     # InterruptSourcePLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # InterruptSourceEntityType
    assert (isinstance(class_type.fields_desc[2], LEShortField))    # InterruptSourceEntityInstanceNumber
    assert (isinstance(class_type.fields_desc[3], XLEShortField))   # InterruptSourceEntityContainerID
    assert (isinstance(class_type.fields_desc[4], XLEShortField))   # InterruptSourceSensorID

    assert (class_type.InterruptSourcePLDMTerminusHandle == 0)
    assert (class_type.InterruptSourceEntityType == 0)
    assert (class_type.InterruptSourceEntityInstanceNumber == 0)
    assert (class_type.InterruptSourceEntityContainerID == 0)
    assert (class_type.InterruptSourceSensorID == 0)
    return


@pytest.mark.parametrize("class_type", InterruptAssociationPDR())
def test_InterruptAssociationPDR(class_type):
    """Verify InterruptAssociationPDR class"""

    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))    # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))    # SensorID
    assert (isinstance(class_type.fields_desc[2], ByteEnumField))    # SourceOrTargetSensor
    assert (isinstance(class_type.fields_desc[3], XLEShortField))    # InterruptTargetEntityType
    assert (isinstance(class_type.fields_desc[4], LEShortField))     # InterruptTargetEntityInstanceNumber
    assert (isinstance(class_type.fields_desc[5], XLEShortField))    # InterruptTargetEntityContainerID
    assert (isinstance(class_type.fields_desc[6], ByteField))        # InterruptSourceEntityCount
    assert (isinstance(class_type.fields_desc[7], PacketListField))  # SourceEntityIdentificationInformation

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.SourceOrTargetSensor == 0)
    assert (class_type.InterruptTargetEntityType == 0)
    assert (class_type.InterruptTargetEntityInstanceNumber == 0)
    assert (class_type.InterruptTargetEntityContainerID == 0)
    assert (class_type.InterruptSourceEntityCount == 0)
    assert (class_type.SourceEntityIdentificationInformation is not None)
    return


@pytest.mark.parametrize("class_type", EventLogPDR())
def test_EventLogPDR(class_type):
    """Verify EventLogPDR class"""

    assert (len(class_type.fields_desc) == 9), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], LEIntField))      # LogSize
    assert (isinstance(class_type.fields_desc[1], BitField))        # Reserved
    assert (isinstance(class_type.fields_desc[2], BitEnumField))    # clearOnAge
    assert (isinstance(class_type.fields_desc[3], BitEnumField))    # FIFO
    assert (isinstance(class_type.fields_desc[4], BitEnumField))    # fillAndStop
    assert (isinstance(class_type.fields_desc[5], ByteField))       # EntryIDTimeout
    assert (isinstance(class_type.fields_desc[6], ByteField))       # PerEntryOverhead
    assert (isinstance(class_type.fields_desc[7], ByteField))       # AllocationGranularity
    assert (isinstance(class_type.fields_desc[8], ByteField))       # PercentUsedResolution

    assert (class_type.LogSize == 0)
    assert (class_type.Reserved == 0)
    assert (class_type.clearOnAge == 0)
    assert (class_type.FIFO == 0)
    assert (class_type.fillAndStop == 0)
    assert (class_type.EntryIDTimeout == 0)
    assert (class_type.PerEntryOverhead == 0)
    assert (class_type.AllocationGranularity == 0)
    assert (class_type.PercentUsedResolution == 0)
    return


@pytest.mark.parametrize("class_type", FRURecordSetPDR())
def test_FRURecordSetPDR(class_type):
    """Verify FRURecordSetPDR class"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))       # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))       # FRURecordSetIdentifier
    assert (isinstance(class_type.fields_desc[2], LEShortEnumField))    # EntityType
    assert (isinstance(class_type.fields_desc[3], LEShortField))        # EntityInstanceNumber
    assert (isinstance(class_type.fields_desc[4], XLEShortField))       # ContainerID

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.FRURecordSetIdentifier == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)
    return


@pytest.mark.parametrize("class_type", OEMDevicePDR())
def test_OEMDevicePDR(class_type):
    """Verify OEMDevicePDR class"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))   # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # CopyPDR
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # VendorIANA
    assert (isinstance(class_type.fields_desc[3], XLEShortField))   # OEMRecordID
    assert (isinstance(class_type.fields_desc[4], LEShortField))    # DataLength
    assert (isinstance(class_type.fields_desc[5], FieldListField))  # VendorSpecificData

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.CopyPDR == 0)
    assert (class_type.VendorIANA == 0)
    assert (class_type.OEMRecordID == 0)
    assert (class_type.DataLength == 0)
    assert (class_type.VendorSpecificData == [])
    return


@pytest.mark.parametrize("class_type", OEMPDR())
def test_OEMPDR(class_type):
    """Verify OEMPDR class"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEIntField))     # VendorIANA
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # OEMRecordID
    assert (isinstance(class_type.fields_desc[2], LEShortField))    # DataLength
    assert (isinstance(class_type.fields_desc[3], FieldListField))  # VendorSpecificData

    assert (class_type.VendorIANA == 0)
    assert (class_type.OEMRecordID == 0)
    assert (class_type.DataLength == 0)
    assert (class_type.VendorSpecificData is not None)
    return


@pytest.mark.parametrize("class_type", RedfishResourceAdditionalResources())
def test_RedfishResourceAdditionalResources(class_type):
    """Verify RedfishResourceAdditionalResources class"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEIntField))     # AdditionalResourceID
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # AdditionalResourceSubURILengthBytes
    assert (isinstance(class_type.fields_desc[2], StrLenField))     # AdditionalResourceSubURI

    assert (class_type.AdditionalResourceID == 0)
    assert (class_type.AdditionalResourceSubURILengthBytes == 0)
    assert (class_type.AdditionalResourceSubURI == b'')
    return


@pytest.mark.parametrize("class_type", RedfishResourceAdditionalResources1())
def test_RedfishResourceAdditionalResources1(class_type):
    """Verify RedfishResourceAdditionalResources1 class"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEIntField))     # AdditionalResourceID
    assert (isinstance(class_type.fields_desc[1], XLEShortField))   # AdditionalResourceSubURILengthBytes
    assert (isinstance(class_type.fields_desc[2], XByteField))      # AdditionalResourceSubURI

    assert (class_type.AdditionalResourceID == 0)
    assert (class_type.AdditionalResourceSubURILengthBytes == 0)
    assert (class_type.AdditionalResourceSubURI == 0)
    return


@pytest.mark.parametrize("class_type", RedfishResourceOEMNames())
def test_RedfishResourceOEMNames(class_type):
    """Verify RedfishResourceOEMNames class"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], FieldLenField))   # OEMNameLengthBytes
    assert (isinstance(class_type.fields_desc[1], StrLenField))     # OEMName

    assert (class_type.OEMNameLengthBytes is None)
    assert (class_type.OEMName == b'')
    return


@pytest.mark.parametrize("class_type", CompactNumericSensorPDR())
def test_CompactNumericSensorPDR(class_type):
    """Verify CompactNumericSensorPDR initialization"""

    assert (len(class_type.fields_desc) == 23), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEShortField))     # PLDMTerminusHandle
    assert (isinstance(class_type.fields_desc[1], XLEShortField))     # SensorID
    assert (isinstance(class_type.fields_desc[2], LEShortEnumField))  # EntityType
    assert (isinstance(class_type.fields_desc[3], LEShortField))      # EntityInstanceNumber
    assert (isinstance(class_type.fields_desc[4], XLEShortField))     # ContainerID

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)

    assert (isinstance(class_type.fields_desc[5], ByteField))       # SensorNameStringByteLength
    assert (isinstance(class_type.fields_desc[6], ByteEnumField))   # BaseUnit
    assert (isinstance(class_type.fields_desc[7], ByteField))       # UnitModifier
    assert (isinstance(class_type.fields_desc[8], ByteEnumField))   # OccurenceRate

    assert (class_type.SensorNameStringByteLength == 0)
    assert (class_type.BaseUnit == 0)
    assert (class_type.UnitModifier == 0)
    assert (class_type.OccurenceRate == 0)

    assert (isinstance(class_type.fields_desc[9], BitField))        # Reserved_1
    assert (isinstance(class_type.fields_desc[10], BitEnumField))   # FatalLowSupported
    assert (isinstance(class_type.fields_desc[11], BitEnumField))   # FatalHighSupported
    assert (isinstance(class_type.fields_desc[12], BitEnumField))   # CriticalLowSupported
    assert (isinstance(class_type.fields_desc[13], BitEnumField))   # CriticalHighSupported
    assert (isinstance(class_type.fields_desc[14], BitEnumField))   # WarningLowSupported
    assert (isinstance(class_type.fields_desc[15], BitEnumField))   # WarningHighSupported

    assert (class_type.Reserved_1 == 0)
    assert (class_type.FatalLowSupported == 0)
    assert (class_type.FatalHighSupported == 0)
    assert (class_type.CriticalLowSupported == 0)
    assert (class_type.CriticalHighSupported == 0)
    assert (class_type.WarningLowSupported == 0)
    assert (class_type.WarningHighSupported == 0)

    assert (isinstance(class_type.fields_desc[16], LEIntField))   # WarningHigh
    assert (isinstance(class_type.fields_desc[17], LEIntField))   # WarningLow
    assert (isinstance(class_type.fields_desc[18], LEIntField))   # CriticalHigh
    assert (isinstance(class_type.fields_desc[19], LEIntField))   # CriticalLow
    assert (isinstance(class_type.fields_desc[20], LEIntField))   # FatalHigh
    assert (isinstance(class_type.fields_desc[21], LEIntField))   # FatalLow

    assert (class_type.WarningHigh == 0)
    assert (class_type.WarningLow == 0)
    assert (class_type.CriticalHigh == 0)
    assert (class_type.CriticalLow == 0)
    assert (class_type.FatalHigh == 0)
    assert (class_type.FatalLow == 0)

    assert (isinstance(class_type.fields_desc[22], StrLenField))  # sensorNameString
    assert (class_type.sensorNameString == b"")
    return


@pytest.mark.parametrize("class_type", RedfishResourcePDR())
def test_RedfishResourcePDR(class_type):
    """Verify RedfishResourcePDR class"""

    assert (len(class_type.fields_desc) == 19), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEIntField))     # ResourceID
    assert (isinstance(class_type.fields_desc[1], BitField))        # Reserved_1
    assert (isinstance(class_type.fields_desc[2], BitEnumField))    # IsCollection
    assert (isinstance(class_type.fields_desc[3], BitEnumField))    # IsContainedInCollection
    assert (isinstance(class_type.fields_desc[4], BitEnumField))    # IsDeviceRoot
    assert (isinstance(class_type.fields_desc[5], XLEIntField))     # ContainingResourceID
    assert (isinstance(class_type.fields_desc[6], LEShortField))    # ProposedContainingResourceLengthBytes
    assert (isinstance(class_type.fields_desc[7], StrLenField))     # ProposedContainingResourceName

    assert (class_type.ResourceID == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.IsCollection == 0)
    assert (class_type.IsContainedInCollection == 0)
    assert (class_type.IsDeviceRoot == 0)
    assert (class_type.ContainingResourceID == 0)
    assert (class_type.ProposedContainingResourceLengthBytes == 0)
    assert (class_type.ProposedContainingResourceName == b'')

    assert (isinstance(class_type.fields_desc[8], LEShortField))        # SubURILengthBytes
    assert (isinstance(class_type.fields_desc[9], MultipleTypeField))   # SubURI
    assert (isinstance(class_type.fields_desc[10], LEShortField))       # AdditionalResourceIDCount
    assert (isinstance(class_type.fields_desc[11], MultipleTypeField))  # AdditionalResources
    assert (isinstance(class_type.fields_desc[12], XLEIntField))        # MajorSchemaVersion
    assert (isinstance(class_type.fields_desc[13], LEShortField))       # MajorSchemaDictionaryLengthBytes
    assert (isinstance(class_type.fields_desc[14], XLEIntField))        # MajorSchemaDictionarySignature
    assert (isinstance(class_type.fields_desc[15], ByteField))          # MajorSchemaNameLength
    assert (isinstance(class_type.fields_desc[16], StrLenField))        # MajorSchemaName
    assert (isinstance(class_type.fields_desc[17], LEShortField))       # OEMCount
    assert (isinstance(class_type.fields_desc[18], PacketListField))    # OEMNames

    assert (class_type.SubURILengthBytes == 0)
    assert (class_type.SubURI == 0)
    assert (class_type.AdditionalResourceIDCount == 0)
    assert (class_type.AdditionalResources is not None)
    assert (class_type.MajorSchemaVersion == 0)
    assert (class_type.MajorSchemaDictionaryLengthBytes == 0)
    assert (class_type.MajorSchemaDictionarySignature == 0)
    assert (class_type.MajorSchemaNameLength == 0)
    assert (class_type.MajorSchemaName == b'')
    assert (class_type.OEMCount == 0)
    assert (class_type.OEMNames is not None)
    return


@pytest.mark.parametrize("class_type", RedfishEntityAssociationPDR())
def test_RedfishEntityAssociationPDR(class_type):
    """Verify RedfishEntityAssociationPDR class"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XLEIntField))     # ContainingResourceID
    assert (isinstance(class_type.fields_desc[1], LEShortField))    # ProposedContainingResourceLengthBytes
    assert (isinstance(class_type.fields_desc[2], StrLenField))     # ProposedContainingResourceName
    assert (isinstance(class_type.fields_desc[3], ByteField))       # ContainedEntityCount
    assert (isinstance(class_type.fields_desc[4], FieldListField))  # ContainedEntity

    assert (class_type.ContainingResourceID == 0)
    assert (class_type.ProposedContainingResourceLengthBytes == 0)
    assert (class_type.ProposedContainingResourceName == b"")
    assert (class_type.ContainedEntityCount == 0)
    assert (class_type.ContainedEntity == [])
    return


@pytest.mark.parametrize("class_type", RedfishActionRelatedResources())
def test_RedfishActionRelatedResources(class_type):
    """Verify RedfishActionRelatedResources class"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XLEIntField))   # RelatedResourceID
    assert (class_type.RelatedResourceID == 0)
    return


@pytest.mark.parametrize("class_type", RedfishActionNames())
def test_RedfishActionNames(class_type):
    """Verify RedfishActionNames class"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], FieldLenField))   # ActionNameLengthBytes
    assert (isinstance(class_type.fields_desc[1], StrLenField))     # ActionName
    assert (isinstance(class_type.fields_desc[2], FieldLenField))   # ActionPathLengthBytes
    assert (isinstance(class_type.fields_desc[3], StrLenField))     # ActionPath

    assert (class_type.ActionNameLengthBytes is None)
    assert (class_type.ActionName == b'')
    assert (class_type.ActionPathLengthBytes is None)
    assert (class_type.ActionPath == b'')
    return


@pytest.mark.parametrize("class_type", RedfishActionPDR())
def test_RedfishActionPDR(class_type):
    """Verify RedfishActionPDR class"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], ByteField))        # ActionPDRIndex
    assert (isinstance(class_type.fields_desc[1], LEShortField))     # RelatedResourceCount
    assert (isinstance(class_type.fields_desc[2], PacketListField))  # RelatedResources
    assert (isinstance(class_type.fields_desc[3], ByteField))        # ActionCount
    assert (isinstance(class_type.fields_desc[4], PacketListField))  # ActionNames

    assert (class_type.ActionPDRIndex == 0)
    assert (class_type.RelatedResourceCount == 0)
    assert (class_type.RelatedResources is not None)
    assert (class_type.ActionCount == 0)
    assert (class_type.ActionNames is not None)
    return


@pytest.mark.parametrize("class_type", PDR_HEADER())
def test_PDR_HEADER(class_type):
    """Verify PDR_HEADER class"""

    assert (len(class_type.fields_desc) == 32), "Incorrect number of fields"
    assert (class_type.RecordHandle == 0)
    assert (class_type.PDRHeaderVersion == 0)
    assert (class_type.PDRType == 0)
    assert (class_type.RecordChangeNumber == 0)
    assert (class_type.DataLength == 0)

    assert (class_type.Terminus is None)
    assert (class_type.NumericSensor is None)
    assert (class_type.NumericSensorInitialization is None)
    assert (class_type.StateSensor is None)
    assert (class_type.StateSensorInitialization is None)
    assert (class_type.SensorAuxiliaryNames is None)
    assert (class_type.OEMUnit is None)
    assert (class_type.OEMStateSet is None)
    assert (class_type.NumericEffecter is None)
    assert (class_type.NumericEffecterInitialization is None)
    assert (class_type.StateEffecter is None)
    assert (class_type.StateEffecterInitialization is None)

    assert (class_type.EffecterAuxiliaryNames is None)
    assert (class_type.OEMEffecterSemantic is None)
    assert (class_type.EntityAssociation is None)
    assert (class_type.EntityAuxiliaryNames is None)
    assert (class_type.OEMEntityID is None)
    assert (class_type.InterruptAssociation is None)
    assert (class_type.EventLog is None)
    assert (class_type.FRURecordSet is None)
    assert (class_type.CompactNumericSensor is None)

    assert (class_type.RedfishResource is None)
    assert (class_type.RedfishAction is None)
    assert (class_type.OEMDevice is None)
    assert (class_type.OEM is None)
    assert (class_type.RecordData == [])
    return
