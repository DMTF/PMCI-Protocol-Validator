# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Initialization tests for PLDM Type 4 wrappers
##############################################################################

import pytest
from pmci_protocol_validator.pldm.classes.dsp0257 import *


@pytest.mark.parametrize("class_type", FRU_Field())
def test_FRU_Field(class_type):
    """ Verify FRU_Field initialization """

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.Type == 0)
    assert (class_type.Length == 0)
    assert (class_type.Value == [])
    return


@pytest.mark.parametrize("class_type", FRU_Record())
def test_FRU_Record(class_type):
    """ Verify FRU_Record iniitialization """

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.FRURecordSetIdentifier == 0)
    assert (class_type.FRURecordType == 0)
    assert (class_type.NumberOfFRUfields == 0)
    assert (class_type.EncodingTypeForFRUFields == 0)
    assert (class_type.Fields == [])
    return


@pytest.mark.parametrize("class_type", PLDM_TYPE_4_PAYLOAD())
def test_PLDM_TYPE_4_PAYLOAD(class_type):
    """ Verify PLDM_TYPE_4_PAYLOAD initialization """

    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetFRUTableMetadata_Request())
def test_GetFRUTableMetadata_Request(class_type):
    """ Verify FRU_Field initialization """

    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x01)
    return


@pytest.mark.parametrize("class_type", GetFRUTableMetadata_Response())
def GetFRUTableMetadata_Response(class_type):
    """ Verify GetFRUTableMetadata_Response initialization """

    assert (len(class_type.fields_desc) == 8), "Incorrect number of fields"
    assert (class_type.CommandValue == GetFRUTableMetadata_Request.CommandValue)

    assert (class_type.CompletionCode == 0)
    assert (class_type.FRUDATAMajorVersion == 0)
    assert (class_type.FRUDATAMinorVersion == 0)
    assert (class_type.FRUTableMaximumSize == 0)
    assert (class_type.FRUTableLength == 0)
    assert (class_type.TotalNumberRecordSetIdentifiers == 0)
    assert (class_type.TotalNumberRecords == 0)
    assert (class_type.FRUTableIntegrityChecksum == 0)

    return


@pytest.mark.parametrize("class_type", GetFRURecordTable_Request())
def test_GetFRURecordTable_Request(class_type):
    """ Verify GetFRURecordTable_Request initialization """

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CommandValue == 2)

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.TransferOperationFlag == 1)
    return


@pytest.mark.parametrize("class_type", GetFRURecordTable_Response())
def test_GetFRURecordTable_Response(class_type):
    """ Verify GetFRURecordTable_Response initialization """

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.CommandValue == GetFRURecordTable_Request.CommandValue)

    assert (class_type.CompletionCode == 0)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 5)
    assert (class_type.FRURecordData == [])
    return


@pytest.mark.parametrize("class_type", SetFRURecordTable_Request())
def test_SetFRURecordTable_Request(class_type):
    """ Verify SetFRURecordTable_Request initialization """

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CommandValue == 3)

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.TransferFlag == 5)
    assert (class_type.FRURecordData == [])
    return


@pytest.mark.parametrize("class_type", SetFRURecordTable_Response())
def test_SetFRURecordTable_Response(class_type):
    """ Verify SetFRURecordTable_Response initialization """

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CommandValue == SetFRURecordTable_Request.CommandValue)

    assert (class_type.CompletionCode == 0)
    assert (class_type.NextDataTransferHandle == 0)
    return


@pytest.mark.parametrize("class_type", GetFRURecordByOption_Request())
def test_GetFRURecordByOption_Request(class_type):
    """ Verify GetFRURecordByOption_Request initialization """

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (class_type.CommandValue == 4)

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.FRUTableHandle == 0)
    assert (class_type.RecordSetIdentifier == 0)
    assert (class_type.RecordType == 0)
    assert (class_type.FieldType == 0)
    assert (class_type.TransferOperationFlag == 1)
    return


@pytest.mark.parametrize("class_type", GetFRURecordByOption_Response())
def test_GetFRURecordByOption_Response(class_type):
    """ Verify GetFRURecordByOption_Response initialization """

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.CommandValue == GetFRURecordByOption_Request.CommandValue)

    assert (class_type.CompletionCode == 0)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.TransferFlag == 5)
    assert (class_type.FRURecordData == [])
    return
