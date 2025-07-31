# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Verifies structure of PLDM Platform Descriptor Records (PDRs)
##############################################################################

import pytest
from pmci_protocol_validator.pldm.classes.dsp0248_pdrs import *


@pytest.mark.parametrize("class_type", PDR_HEADER())
def test_PDR_HEADER(class_type):
    """Verify PDR_HEADER initialization"""

    assert (len(class_type.fields_desc) >= 6), "Incorrect number of fields"

    assert (class_type.RecordHandle == 0)
    assert (class_type.PDRHeaderVersion == 0)
    assert (class_type.PDRType == 0)
    assert (class_type.RecordChangeNumber == 0)
    assert (class_type.DataLength == 0)
    return


@pytest.mark.parametrize("class_type", TerminusLocatorPDR())
def test_TerminusLocatorPDR(class_type):
    """Verify TerminusLocatorPDR initialization"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

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

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)
    assert (class_type.SensorInit == 0)
    assert (class_type.SensorAuxiliaryNamesPDR == 0)
    assert (class_type.BaseUnit == 0)
    assert (class_type.UnitModifier == 0)
    assert (class_type.RateUnit == 0)

    assert (class_type.BaseOEMUnitHandle == 0)
    assert (class_type.AuxUnit == 0)
    assert (class_type.AuxUnitModifier == 0)
    assert (class_type.AuxRateUnit == 0)
    assert (class_type.Relationship == 0)
    assert (class_type.AuxOEMUnitHandle == 0)
    assert (class_type.IsLinear == 0)
    assert (class_type.SensorDataSize == 0)
    assert (class_type.Resolution == 0)
    assert (class_type.Offset == 0)

    assert (class_type.Accuracy == 0)
    assert (class_type.PlusTolerance == 0)
    assert (class_type.MinusTolerance == 0)
    assert (class_type.HysteresisValue == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.lowerThresholdFatal == 0)
    assert (class_type.lowerThresholdCritical == 0)
    assert (class_type.lowerThresholdWarning == 0)
    assert (class_type.upperThresholdFatal == 0)
    assert (class_type.upperThresholdCritical == 0)

    assert (class_type.upperThresholdWarning == 0)
    assert (class_type.Reserved_2 == 0)
    assert (class_type.PLDMTerminusReturnsToOnlineCondition == 0)
    assert (class_type.SystemWarmResets == 0)
    assert (class_type.SystemHardResets == 0)
    assert (class_type.PLDMSubsystemPowerUp == 0)
    assert (class_type.InitializationAgentControllerRestartUpdate == 0)
    assert (class_type.StateTransitionInterval == 0)
    assert (class_type.UpdateInterval == 0)
    assert (class_type.MaxReadable == 0)

    assert (class_type.MinReadable == 0)
    assert (class_type.RangeFieldFormat == 0)
    assert (class_type.Reserved_3 == 0)
    assert (class_type.FatalLowSupported == 0)
    assert (class_type.FatalHighSupported == 0)
    assert (class_type.CriticalLowSupported == 0)
    assert (class_type.CriticalHighSupported == 0)
    assert (class_type.NormalMinSupported == 0)
    assert (class_type.NormalMaxSupported == 0)
    assert (class_type.NominalValueSupported == 0)

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
    """Verify NumericSensorInitializationPDR initialization"""

    assert (len(class_type.fields_desc) == 23), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.PLDMTerminusReturnsToOnlineCondition == 0)
    assert (class_type.SystemWarmResets == 0)
    assert (class_type.SystemHardResets == 0)
    assert (class_type.PLDMSubsystemPowerUp == 0)
    assert (class_type.InitializationAgentControllerRestartUpdate == 0)
    assert (class_type.SensorEnable == 0)
    assert (class_type.Reserved_2 == 0)
    assert (class_type.lowerThresholdFatal == 0)
    assert (class_type.lowerThresholdCritical == 0)
    assert (class_type.lowerThresholdWarning == 0)
    assert (class_type.upperThresholdFatal == 0)
    assert (class_type.upperThresholdCritical == 0)
    assert (class_type.upperThresholdWarning == 0)
    assert (class_type.SensorDataSize == 0)
    assert (class_type.UpperThresholdWarning == 0)
    assert (class_type.UpperThresholdCritical == 0)
    assert (class_type.UpperThresholdFatal == 0)
    assert (class_type.LowerThresholdWarning == 0)
    assert (class_type.LowerThresholdCritical == 0)
    assert (class_type.LowerThresholdFatal == 0)
    return

@pytest.mark.parametrize("class_type", StateSensorBitFields())
def test_StateSensorBitFields(class_type):
    """Verify StateSensorBitFields initialization"""

    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"

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
    """Verify StateSensorFields initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.StateSetID == 0)
    assert (class_type.PossibleStateSize == 0)
    assert (class_type.PossibleStates is not None)
    return


@pytest.mark.parametrize("class_type", StateSensorPDR())
def test_StateSensorPDR(class_type):
    """Verify StateSensorPDR initialization"""

    assert (len(class_type.fields_desc) == 9), "Incorrect number of fields"
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
    """Verify StateSensorInitializationPDR initialization"""

    assert (len(class_type.fields_desc) == 41), "Incorrect number of fields"

    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.PLDMTerminusReturnsToOnlineCondition == 0)
    assert (class_type.SystemWarmResets == 0)
    assert (class_type.SystemHardResets == 0)
    assert (class_type.PLDMSubsystemPowerUp == 0)
    assert (class_type.InitializationAgentControllerRestartUpdate == 0)
    assert (class_type.SensorEnable == 0)

    assert (class_type.SensorInitMask_7 == 0)
    assert (class_type.SensorInitMask_6 == 0)
    assert (class_type.SensorInitMask_5 == 0)
    assert (class_type.SensorInitMask_4 == 0)
    assert (class_type.SensorInitMask_3 == 0)
    assert (class_type.SensorInitMask_2 == 0)
    assert (class_type.SensorInitMask_1 == 0)
    assert (class_type.SensorInitMask_0 == 0)

    assert (class_type.sensorStateEventEnableMask_7 == 0)
    assert (class_type.sensorStateEventEnableMask_6 == 0)
    assert (class_type.sensorStateEventEnableMask_5 == 0)
    assert (class_type.sensorStateEventEnableMask_4 == 0)
    assert (class_type.sensorStateEventEnableMask_3 == 0)
    assert (class_type.sensorStateEventEnableMask_2 == 0)
    assert (class_type.sensorStateEventEnableMask_1 == 0)
    assert (class_type.sensorStateEventEnableMask_0 == 0)

    assert (class_type.SensorEventRearm_7 == 0)
    assert (class_type.SensorEventRearm_6 == 0)
    assert (class_type.SensorEventRearm_5 == 0)
    assert (class_type.SensorEventRearm_4 == 0)
    assert (class_type.SensorEventRearm_3 == 0)
    assert (class_type.SensorEventRearm_2 == 0)
    assert (class_type.SensorEventRearm_1 == 0)
    assert (class_type.SensorEventRearm_0 == 0)

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
    """Verify NamesFieldsSensorAuxiliaryNames initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.NameLanguageTag is None)
    assert (class_type.SensorName is None)
    return

@pytest.mark.parametrize("class_type", SensorAuxiliaryNamesFields())
def test_SensorAuxiliaryNamesFields(class_type):
    """Verify SensorAuxiliaryNamesFields initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.NameStringCount == 0)
    assert (class_type.NameStrings is not None)
    return


@pytest.mark.parametrize("class_type", SensorAuxiliaryNamesPDR())
def test_SensorAuxiliaryNamesPDR(class_type):
    """Verify SensorAuxiliaryNamesPDR initialization"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.SensorCount == 0)
    assert (class_type.Sensors is not None)
    return


@pytest.mark.parametrize("class_type", OEMUnitStrings())
def test_OEMUnitStrings(class_type):
    """Verify OEMUnitStrings initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.UnitLanguageTag is None)
    assert (class_type.UnitName is None)
    return

@pytest.mark.parametrize("class_type", OEMUnitPDR())
def test_OEMUnitPDR(class_type):
    """Verify OEMUnitPDR initialization"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.OEMUnitHandle == 0)
    assert (class_type.VendorIANA == 0)
    assert (class_type.OEMUnitID == 0)
    assert (class_type.StringCount == 0)
    assert (class_type.UnitNames is not None)
    return

@pytest.mark.parametrize("class_type", OEMStateStrings())
def test_OEMStateStrings(class_type):
    """Verify OEMStateStrings initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.StateLanguageTag is None)
    assert (class_type.StateName is None)
    return


@pytest.mark.parametrize("class_type", OEMStateValueRecordFields())
def test_OEMStateValueRecordFields(class_type):
    """Verify OEMStateValueRecordFields initialization"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.MinStateValue == 0)
    assert (class_type.MaxStateValue == 0)
    assert (class_type.StringCount == 0)
    assert (class_type.StateNames is not None)
    return


@pytest.mark.parametrize("class_type", OEMStatePDR())
def test_OEMStatePDR(class_type):
    """Verify OEMStatePDR initialization"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"
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
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.EffecterID == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)
    assert (class_type.EffecterSemanticID == 0)
    assert (class_type.EffecterInit == 0)
    assert (class_type.EffecterAuxiliaryNamesPDR == 0)
    assert (class_type.BaseUnit == 0)
    assert (class_type.UnitModifier == 0)

    assert (class_type.RateUnit == 0)
    assert (class_type.BaseOEMUnitHandle == 0)
    assert (class_type.AuxUnit == 0)
    assert (class_type.AuxUnitModifier == 0)
    assert (class_type.AuxRateUnit == 0)
    assert (class_type.AuxOEMUnitHandle == 0)
    assert (class_type.IsLinear == 0)
    assert (class_type.EffecterDataSize == 0)
    assert (class_type.Resolution == 0)
    assert (class_type.Offset == 0)

    assert (class_type.Accuracy == 0)
    assert (class_type.PlusTolerance == 0)
    assert (class_type.MinusTolerance == 0)
    assert (class_type.StateTransitionInterval == 0)
    assert (class_type.MaxSettable == 0)
    assert (class_type.MinSettable == 0)
    assert (class_type.RangeFieldFormat == 0)
    assert (class_type.RatedMinSupported == 0)
    assert (class_type.RatedMaxSupported == 0)
    assert (class_type.NormalMinSupported == 0)

    assert (class_type.NormalMaxSupported == 0)
    assert (class_type.NominalValueSupported == 0)
    assert (class_type.NominalValue == 0)
    assert (class_type.NormalMax == 0)
    assert (class_type.NormalMin == 0)
    assert (class_type.RatedMax == 0)
    assert (class_type.RatedMin == 0)
    return


@pytest.mark.parametrize("class_type", NumericEffecterInitializationPDR())
def test_NumericEffecterInitializationPDR(class_type):
    """Verify NumericEffecterInitializationPDR initialization"""

    assert (len(class_type.fields_desc) == 11), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.EffecterID == 0)
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
    """Verify StateEffecterFields initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.StateSetID == 0)
    assert (class_type.PossibleStateSize == 0)
    assert (class_type.PossibleStates is not None)
    return


@pytest.mark.parametrize("class_type", StateEffecterPDR())
def test_StateEffecterPDR(class_type):
    """Verify StateEffecterPDR initialization"""

    assert (len(class_type.fields_desc) == 10), "Incorrect number of fields"
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
    """Verify StateEffecterInitializationPDR initialization"""

    assert (len(class_type.fields_desc) == 36), "Incorrect number of fields"

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

    assert (class_type.EffecterInitMask_7 == 0)
    assert (class_type.EffecterInitMask_6 == 0)
    assert (class_type.EffecterInitMask_5 == 0)
    assert (class_type.EffecterInitMask_4 == 0)
    assert (class_type.EffecterInitMask_3 == 0)
    assert (class_type.EffecterInitMask_2 == 0)
    assert (class_type.EffecterInitMask_1 == 0)
    assert (class_type.EffecterInitMask_0 == 0)

    assert (class_type.EffecterOpStateEventEnableMask_7 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_6 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_5 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_4 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_3 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_2 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_1 == 0)
    assert (class_type.EffecterOpStateEventEnableMask_0 == 0)

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
    """Verify EffecterAuxiliaryNamesStrings initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.NameLanguageTag is None)
    assert (class_type.EffecterName is None)
    return


@pytest.mark.parametrize("class_type", EffecterAuxiliaryNamesFields())
def test_EffecterAuxiliaryNamesFields(class_type):
    """Verify EffecterAuxiliaryNamesFields initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.NameStringCount == 0)
    assert (class_type.EffecterNames is not None)
    return


@pytest.mark.parametrize("class_type", EffecterAuxiliaryNamesPDR())
def test_EffecterAuxiliaryNamesPDR(class_type):
    """Verify EffecterAuxiliaryNamesPDR initialization"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.EffecterID == 0)
    assert (class_type.EffecterCount == 0)
    assert (class_type.EffecterNames is not None)
    return


@pytest.mark.parametrize("class_type", OEMEffecterSemanticStrings())
def test_OEMEffecterSemanticStrings(class_type):
    """Verify OEMEffecterSemanticStrings initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.LanguageTag is None)
    assert (class_type.Name is None)
    return


@pytest.mark.parametrize("class_type", OEMEffecterSemanticPDR())
def test_OEMEffecterSemanticPDR(class_type):
    """Verify OEMEffecterSemanticPDR initialization"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.OEMEffecterSemanticHandle == 0)
    assert (class_type.OEMEffecterSemanticID == 0)
    assert (class_type.VendorIANA == 0)
    assert (class_type.StringCount == 0)
    assert (class_type.Names is not None)
    return


@pytest.mark.parametrize("class_type", EntityAssociationContained())
def test_EntityAssociationContained(class_type):
    """Verify EntityAssociationContained initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.ContainedEntityType == 0)
    assert (class_type.ContainedEntityInstanceNumber == 0)
    assert (class_type.ContainedEntityContainerID == 0)
    return


@pytest.mark.parametrize("class_type", EntityAssociationPDR())
def test_EntityAssociationPDR(class_type):
    """Verify EntityAssociationPDR initialization"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"
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
    """Verify EntityAuxiliaryNamesStrings initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.NameLanguageTag is None)
    assert (class_type.EntityAuxName is None)
    return


@pytest.mark.parametrize("class_type", EntityAuxiliaryNamesPDR())
def test_EntityAuxiliaryNamesPDR(class_type):
    """Verify EntityAuxiliaryNamesPDR initialization"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.EntityContainerID == 0)
    assert (class_type.SharedNameCount == 0)
    assert (class_type.NameStringCount == 0)
    assert (class_type.EntityAuxiliaryNames is not None)
    return


@pytest.mark.parametrize("class_type", OEMEntityIDStrings())
def test_OEMEntityIDStrings(class_type):
    """Verify OEMEntityIDStrings initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.EntityIDLanguageTag is None)
    assert (class_type.EntityIDName is None)
    return


@pytest.mark.parametrize("class_type", OEMEntityIDPDR())
def test_OEMEntityIDPDR(class_type):
    """Verify OEMEntityIDPDR initialization"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.OEMEntityIDHandleValue == 0)
    assert (class_type.VendorIANA == 0)
    assert (class_type.VendorEntityID == 0)
    assert (class_type.StringCount == 0)
    assert (class_type.EntityIDStrings is not None)
    return


@pytest.mark.parametrize("class_type", InterruptAssociationFields())
def test_InterruptAssociationFields(class_type):
    """Verify InterruptAssociationFields initialization"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.InterruptSourcePLDMTerminusHandle == 0)
    assert (class_type.InterruptSourceEntityType == 0)
    assert (class_type.InterruptSourceEntityInstanceNumber == 0)
    assert (class_type.InterruptSourceEntityContainerID == 0)
    assert (class_type.InterruptSourceSensorID == 0)
    return


@pytest.mark.parametrize("class_type", InterruptAssociationPDR())
def test_InterruptAssociationPDR(class_type):
    """Verify InterruptAssociationPDR initialization"""

    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"
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
    """Verify EventLogPDR initialization"""

    assert (len(class_type.fields_desc) == 9), "Incorrect number of fields"
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
    """Verify FRURecordSetPDR initialization"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.FRURecordSetIdentifier == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)
    return


@pytest.mark.parametrize("class_type", OEMDevicePDR())
def test_OEMDevicePDR(class_type):
    """Verify OEMDevicePDR initialization"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.CopyPDR == 0)
    assert (class_type.VendorIANA == 0)
    assert (class_type.OEMRecordID == 0)
    assert (class_type.DataLength == 0)
    assert (class_type.VendorSpecificData == [])
    return


@pytest.mark.parametrize("class_type", OEMPDR())
def test_OEMPDR(class_type):
    """Verify OEMPDR initialization"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.VendorIANA == 0)
    assert (class_type.OEMRecordID == 0)
    assert (class_type.DataLength == 0)
    assert (class_type.VendorSpecificData is not None)
    return


@pytest.mark.parametrize("class_type", RedfishResourceAdditionalResources())
def test_RedfishResourceAdditionalResources(class_type):
    """Verify RedfishResourceAdditionalResources initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.AdditionalResourceID == 0)
    assert (class_type.AdditionalResourceSubURILengthBytes == 0)
    assert (class_type.AdditionalResourceSubURI == b'')
    return


@pytest.mark.parametrize("class_type", RedfishResourceAdditionalResources1())
def test_RedfishResourceAdditionalResources1(class_type):
    """Verify RedfishResourceAdditionalResources1 initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.AdditionalResourceID == 0)
    assert (class_type.AdditionalResourceSubURILengthBytes == 0)
    assert (class_type.AdditionalResourceSubURI == 0)
    return


@pytest.mark.parametrize("class_type", RedfishResourceOEMNames())
def test_RedfishResourceOEMNames(class_type):
    """Verify RedfishResourceOEMNames initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.OEMNameLengthBytes is None)
    assert (class_type.OEMName == b'')
    return


@pytest.mark.parametrize("class_type", CompactNumericSensorPDR())
def test_CompactNumericSensorPDR(class_type):
    """Verify CompactNumericSensorPDR initialization"""

    assert (len(class_type.fields_desc) == 23), "Incorrect number of fields"
    assert (class_type.PLDMTerminusHandle == 0)
    assert (class_type.SensorID == 0)
    assert (class_type.EntityType == 0)
    assert (class_type.EntityInstanceNumber == 0)
    assert (class_type.ContainerID == 0)

    assert (class_type.SensorNameStringByteLength == 0)
    assert (class_type.BaseUnit == 0)
    assert (class_type.UnitModifier == 0)
    assert (class_type.OccurenceRate == 0)
    assert (class_type.Reserved_1 == 0)

    assert (class_type.FatalLowSupported == 0)
    assert (class_type.FatalHighSupported == 0)
    assert (class_type.CriticalLowSupported == 0)
    assert (class_type.CriticalHighSupported == 0)
    assert (class_type.WarningLowSupported == 0)
    assert (class_type.WarningHighSupported == 0)

    assert (class_type.WarningHigh == 0)
    assert (class_type.WarningLow == 0)
    assert (class_type.CriticalHigh == 0)
    assert (class_type.CriticalLow == 0)
    assert (class_type.FatalHigh == 0)
    assert (class_type.FatalLow == 0)

    assert (class_type.sensorNameString == b"")
    return


@pytest.mark.parametrize("class_type", RedfishResourcePDR())
def test_RedfishResourcePDR(class_type):
    """Verify RedfishResourcePDR initialization"""

    assert (len(class_type.fields_desc) == 19), "Incorrect number of fields"
    assert (class_type.ResourceID == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.IsCollection == 0)
    assert (class_type.IsContainedInCollection == 0)
    assert (class_type.IsDeviceRoot == 0)
    assert (class_type.ContainingResourceID == 0)
    assert (class_type.ProposedContainingResourceLengthBytes == 0)
    assert (class_type.ProposedContainingResourceName == b'')
    assert (class_type.SubURILengthBytes == 0)

    assert (class_type.SubURI == 0)
    assert (class_type.AdditionalResourceIDCount == 0)
    assert (class_type.AdditionalResources is not None)
    assert (class_type.MajorSchemaVersion == 0)
    assert (class_type.MajorSchemaDictionaryLengthBytes == 0)
    assert (class_type.MajorSchemaDictionarySignature == 0)
    assert (class_type.MajorSchemaNameLength == 0)
    assert (class_type.MajorSchemaName == b'')
    assert (class_type.OEMNames is not None)
    return


@pytest.mark.parametrize("class_type", RedfishEntityAssociationPDR())
def test_RedfishEntityAssociationPDR(class_type):
    """Verify RedfishEntityAssociationPDR initialization"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.ContainingResourceID == 0)
    assert (class_type.ProposedContainingResourceLengthBytes == 0)
    assert (class_type.ProposedContainingResourceName == b"")
    assert (class_type.ContainedEntityCount == 0)
    assert (class_type.ContainedEntity == [])
    return


@pytest.mark.parametrize("class_type", RedfishActionRelatedResources())
def test_RedfishActionRelatedResources(class_type):
    """Verify RedfishActionRelatedResources initialization"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.RelatedResourceID == 0)
    return


@pytest.mark.parametrize("class_type", RedfishActionNames())
def test_RedfishActionNames(class_type):
    """Verify RedfishActionNames initialization"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.ActionNameLengthBytes is None)
    assert (class_type.ActionName == b'')
    assert (class_type.ActionPathLengthBytes is None)
    assert (class_type.ActionPath == b'')
    return


@pytest.mark.parametrize("class_type", RedfishActionPDR())
def test_RedfishActionPDR(class_type):
    """Verify RedfishActionPDR initialization"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.ActionPDRIndex == 0)
    assert (class_type.RelatedResourceCount == 0)
    assert (class_type.RelatedResources is not None)
    assert (class_type.ActionCount == 0)
    assert (class_type.ActionNames is not None)
    return


@pytest.mark.parametrize("class_type", PDR_HEADER())
def test_PDR_HEADER(class_type):
    """Verify PDR_HEADER initialization"""

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
