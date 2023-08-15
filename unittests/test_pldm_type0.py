##############################################################################
#  File Abstract:
#  Contains initialization tests for the PLDM Type 0 (PLDM Messaging Control
#  and Discovery) wrappers
##############################################################################

import pytest
from pldm.type0 import *  # pylint: disable=unused-import, unused-wildcard-import


@pytest.mark.parametrize("class_type", PLDM_TYPE_0_PAYLOAD())
def test_PLDM_TYPE_0_PAYLOAD(class_type):
    """Verify PLDM_TYPE_0_PAYLOAD initialization"""

    assert (PLDM_TYPE_0_PAYLOAD.PldmPayloadType == 0), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", SetTID_Request())
def test_SetTID_Request(class_type):
    """Verify SetTID_Request initialization"""

    assert (class_type.CommandValue == 0x01), "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.TID == 0x01)
    return


@pytest.mark.parametrize("class_type", SetTID_Response())
def test_SetTID_Response(class_type):
    """Verify SetTID_Response initialization"""

    assert (class_type.CommandValue == SetTID_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", GetTID_Request())
def test_GetTID_Request(class_type):
    """Verify GetTID_Request initialization"""

    assert (class_type.CommandValue == 0x02), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetTID_Response())
def test_GetTID_Response(class_type):
    """Verify GetTID_Response initialization"""

    assert (class_type.CommandValue == GetTID_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    assert (class_type.TID == 0x00)
    return


@pytest.mark.parametrize("class_type", GetPldmVersion_Request())
def test_GetPldmVersion_Request(class_type):
    """Verify GetPldmVersion_Request initialization"""

    assert (class_type.CommandValue == 0x03), "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.DataTransferHandle == 0)
    assert (class_type.TransferOperationFlag == 0)
    assert (class_type.PldmType == 0)
    return


@pytest.mark.parametrize("class_type", GetPldmVersion_Response())
def test_GetPldmVersion_Response(class_type):
    """Verify GetPldmVersion_Response initialization"""

    assert (class_type.CommandValue == GetPldmVersion_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.CompletionCode == 0x00)
    assert (class_type.NextDataTransferHandle == 0x00)
    assert (class_type.TransferFlag == 0x01)
    assert (class_type.Version == [])
    assert (class_type.PLDMVersionDataIntegrityChecksum is None)
    return


@pytest.mark.parametrize("class_type", GetPldmTypes_Request())
def test_GetPldmTypes_Request(class_type):
    """Verify GetPldmTypes_Request initialization"""

    assert (class_type.CommandValue == 0x04), "Incorrect command code"
    assert (len(class_type.fields_desc) == 0), "Incorrect number of fields"
    return


@pytest.mark.parametrize("class_type", GetPldmTypes_Response())
def test_GetPldmTypes_Response(class_type):
    """Verify GetPldmTypes_Response initialization"""

    assert (class_type.CommandValue == GetPldmTypes_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 9), "Incorrect number of fields"

    assert (class_type.CompletionCode == 0x00)
    assert (class_type.Type7 == 0)
    assert (class_type.Type6 == 0)
    assert (class_type.Type5 == 0)
    assert (class_type.Type4 == 0)
    assert (class_type.Type3 == 0)
    assert (class_type.Type2 == 0)
    assert (class_type.Type1 == 0)
    assert (class_type.Type0 == 0)
    return


@pytest.mark.parametrize("class_type", GetPldmCommands_Request())
def test_GetPldmCommands_Request(class_type):
    """Verify GetPldmCommands_Request initialization"""

    assert (class_type.CommandValue == 0x05), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.PldmType == 0)
    assert (class_type.Version == 0)
    return


@pytest.mark.parametrize("class_type", GetPldmCommands_Response())
def test_GetPldmCommands_Response(class_type):
    """Verify GetPldmCommands_Response initialization"""

    assert (class_type.CommandValue == GetPldmCommands_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 257), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", SelectPLDMVersion_Request())
def test_SelectPLDMVersion_Request(class_type):
    """Verify SelectPLDMVersion_Request initialization"""

    assert (class_type.CommandValue == 0x06), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.PldmType == 1)
    assert (class_type.Version == 0)
    return


@pytest.mark.parametrize("class_type", SelectPLDMVersion_Response())
def test_SelectPLDMVersion_Response(class_type):
    """Verify SelectPLDMVersion_Response initialization"""

    assert (class_type.CommandValue == SelectPLDMVersion_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", NegotiateTransferParameters_Request())
def test_NegotiateTransferParameters_Request(class_type):
    """Verify NegotiateTransferParameters_Request initialization"""

    assert (class_type.CommandValue == 0x07), "Incorrect command code"
    assert (len(class_type.fields_desc) == 9), "Incorrect number of fields"

    assert (class_type.RequestorPartSize == 0x0000)
    assert (class_type.RequestorProtocolType7_Supported == 0)
    assert (class_type.RequestorProtocolType6_Supported == 0)
    assert (class_type.RequestorProtocolType5_Supported == 0)
    assert (class_type.RequestorProtocolType4_Supported == 0)
    assert (class_type.RequestorProtocolType3_Supported == 0)
    assert (class_type.RequestorProtocolType2_Supported == 0)
    assert (class_type.RequestorProtocolType1_Supported == 0)
    assert (class_type.RequestorProtocolType0_Supported == 0)
    return


@pytest.mark.parametrize("class_type", NegotiateTransferParameters_Response())
def test_NegotiateTransferParameters_Response(class_type):
    """Verify NegotiateTransferParameters_Response initialization"""

    assert (class_type.CommandValue == NegotiateTransferParameters_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 10), "Incorrect number of fields"

    assert (class_type.CompletionCode == 0x00)
    assert (class_type.ResponderPartSize == 0x0000)
    assert (class_type.ResponderProtocolType7_Supported == 0)
    assert (class_type.ResponderProtocolType6_Supported == 0)
    assert (class_type.ResponderProtocolType5_Supported == 0)
    assert (class_type.ResponderProtocolType4_Supported == 0)
    assert (class_type.ResponderProtocolType3_Supported == 0)
    assert (class_type.ResponderProtocolType2_Supported == 0)
    assert (class_type.ResponderProtocolType1_Supported == 0)
    assert (class_type.ResponderProtocolType0_Supported == 0)
    return


@pytest.mark.parametrize("class_type", MultipartSend_Request())
def test_MultipartSend_Request(class_type):
    """Verify MultipartSend_Request initialization"""

    assert (class_type.CommandValue == 0x08), "Incorrect command code"
    assert (len(class_type.fields_desc) == 10), "Incorrect number of fields"

    assert (class_type.PldmType == 0)
    assert (class_type.TransferFlag == 0x01)
    assert (class_type.TransferContext == 0)
    assert (class_type.DataTransferHandle == 0)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.SectionOffset == 0)
    assert (class_type.SectionLengthBytes == 0)
    assert (class_type.DataLengthBytes == 0)
    assert (class_type.Data == [])
    assert (class_type.DataIntegrityChecksum == 0)
    return


@pytest.mark.parametrize("class_type", MultipartSend_Response())
def test_MultipartSend_Response(class_type):
    """Verify MultipartSend_Response initialization"""

    assert (class_type.CommandValue == MultipartSend_Request.CommandValue), \
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.CompletionCode == 0x00)

    return


@pytest.mark.parametrize("class_type", MultipartReceive_Request())
def test_MultipartReceive_Request(class_type):
    """Verify MultipartReceive_Request initialization"""

    assert (class_type.CommandValue == 0x09), "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.PldmType == 0)
    assert (class_type.TransferOperation == 0)
    assert (class_type.TransferContext == 0)
    assert (class_type.DataTransferHandle == 0)
    assert (class_type.RequestedSectionOffset == 0)
    assert (class_type.RequestedSectionLengthBytes == 0)
    return


@pytest.mark.parametrize("class_type", MultipartReceive_Response())
def test_MultipartReceive_Response(class_type):
    """Verify MultipartReceive_Response initialization"""

    assert (class_type.CommandValue == MultipartReceive_Request.CommandValue),\
        "Incorrect command code"

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.CompletionCode == 0x00)
    assert (class_type.TransferFlag == 0x01)
    assert (class_type.NextDataTransferHandle == 0)
    assert (class_type.DataLengthBytes == 0)
    assert (class_type.Data == [])
    assert (class_type.DataIntegrityChecksum == 0)
    return
