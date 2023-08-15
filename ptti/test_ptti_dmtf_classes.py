##############################################################################
#  File Abstract:
#  PyTest suite to validate DSP0280 class field definitions.
##############################################################################

import pytest
from scapy.fields import *  # pylint: disable=unused-import, unused-wildcard-import
from ptti.dmtf import *     # pylint: disable=unused-import, unused-wildcard-import


EXPECTED_VERSION_COMPLIANCE = 0x10

@pytest.mark.parametrize("class_type", TestServiceWrapper())
def test_TestServiceWrapper(class_type):
    """Validate TestServiceWrapper class format"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XByteField))      # Version
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ProtocolType
    assert (isinstance(class_type.fields_desc[2], BitField))        # Reserved
    assert (isinstance(class_type.fields_desc[3], BitEnumField))    # Direction
    assert (isinstance(class_type.fields_desc[4], XLEIntField))     # TestClientID
    return


@pytest.mark.parametrize("class_type", Connect_Request())
def test_Connect_Request(class_type):
    """Verify Connect Request class format"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], FieldLenField))   # SecurityParameterLength
    assert (isinstance(class_type.fields_desc[2], FieldListField))  # SecurityParameter
    return


@pytest.mark.parametrize("class_type", Connect_Response())
def test_Connect_Response(class_type):
    """Validate Connect Response class format"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    assert (isinstance(class_type.fields_desc[2], XByteField))      # TestServiceVersion
    assert (isinstance(class_type.fields_desc[3], XLEIntField))       # TestClientID
    return


@pytest.mark.parametrize("class_type", Disconnect_Request())
def test_Disconnect_Request(class_type):
    """Verify Disconnect Request class format"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    return


@pytest.mark.parametrize("class_type", Disconnect_Response())
def test_Disconnect_Response(class_type):
    """Validate Disconnect Response class format"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    return


@pytest.mark.parametrize("class_type", QueryCapabilities_Request())
def test_QueryCapabilities_Request(class_type):
    """Validate QueryCapabilities Request class format"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    return


@pytest.mark.parametrize("class_type", TestServiceCapabilityEntry())
def test_TestServiceCapabilityEntry(class_type):
    """Validate TestServiceCapabilityEntry class format"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], ShortField))  # CapabilityID
    assert (isinstance(class_type.fields_desc[1], LEIntField))    # CapabilityValue
    return


@pytest.mark.parametrize("class_type", QueryCapabilities_Response())
def test_QueryCapabilities_Response(class_type):
    """Validate QueryCapabilities_Response class field types"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    assert (isinstance(class_type.fields_desc[2], XByteField))      # Reserved
    assert (isinstance(class_type.fields_desc[3], FieldLenField))   # NumberOfCapabilitiesFields
    assert (isinstance(class_type.fields_desc[4], PacketListField)) # TestServiceCapabilities
    return


@pytest.mark.parametrize("class_type", QueryStatus_Request())
def test_QueryStatus_Request(class_type):
    """Validate QueryStatus_Request class field types"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # QueryType
    return


@pytest.mark.parametrize("class_type", QueryStatus_Response())
def test_QueryStatus_Response(class_type):
    """Validate QueryStatus Response class format"""

    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    assert (isinstance(class_type.fields_desc[2], ByteEnumField))   # QueryType
    assert (isinstance(class_type.fields_desc[3], LEIntField))      # QueryResponseDataLength
    return


@pytest.mark.parametrize("class_type", QuerySystemInventory_Request())
def test_QuerySystemInventory_Request(class_type):
    """Validate QuerySystemInventory Request class format"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    return


@pytest.mark.parametrize("class_type", QuerySystemInventory_Response())
def test_QuerySystemInventory_Response(class_type):
    """Validate QuerySystemInventory Response class format"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    assert (isinstance(class_type.fields_desc[2], StrField))        # SystemInventory
    return


@pytest.mark.parametrize("class_type", ConfigureTestService_Request())
def test_ConfigureTestService_Request(class_type):
    """Validate ConfigureTestService Request class format"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], FieldLenField))   # NumberOfCapabilitiesFields
    assert (isinstance(class_type.fields_desc[2], PacketListField)) # TestServiceCapabilities
    return


@pytest.mark.parametrize("class_type", ConfigureTestService_Response())
def test_ConfigureTestService_Response(class_type):
    """Validate ConfigureTestService Response class format"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    return


@pytest.mark.parametrize("class_type", ConfigureDeviceUnderTest_Request())
def test_ConfigureDeviceUnderTest_Request(class_type):
    """Validate ConfigureDeviceUnderTest Request class format"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XLEIntField))     # TargetIdentifier
    assert (isinstance(class_type.fields_desc[2], FieldLenField))   # IdentifierCount
    assert (isinstance(class_type.fields_desc[3], FieldListField))  # IdentifierList
    return


@pytest.mark.parametrize("class_type", ConfigureDeviceUnderTest_Response())
def test_ConfigureDeviceUnderTest_Response(class_type):
    """Validate ConfigureDeviceUnderTest Response class format"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # DUTConnectionID
    assert (isinstance(class_type.fields_desc[3], FieldLenField))   # IdentifierCount
    assert (isinstance(class_type.fields_desc[4], FieldListField))  # IdentifierList
    return


@pytest.mark.parametrize("class_type", RegisterToProtocol_Request())
def test_RegisterToProtocol_Request(class_type):
    """Validate RegisterToProtocol Request class format"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # ProtocolType
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # DUTConnectionID
    assert (isinstance(class_type.fields_desc[3], FieldLenField))   # TypeCount
    assert (isinstance(class_type.fields_desc[4], FieldListField))  # TypeList
    return


@pytest.mark.parametrize("class_type", RegisterToProtocol_Response())
def test_RegisterToProtocol_Response(class_type):
    """Validate RegisterToProtocol Response class format"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # DUTConnectionID
    return


@pytest.mark.parametrize("class_type", RegisterAsyncMessageRecipient_Request())
def test_RegisterAsyncMessageRecipient_Request(class_type):
    """Validate RegisterAsyncMessageRecipient Request class format"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # ProtocolType
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # DUTConnectionID
    assert (isinstance(class_type.fields_desc[3], FieldLenField))   # TypeCount
    assert (isinstance(class_type.fields_desc[4], FieldListField))  # TypesList
    return


@pytest.mark.parametrize("class_type", RegisterAsyncMessageRecipient_Response())
def test_RegisterAsyncMessageRecipient_Response(class_type):
    """Validate RegisterAsyncMessageRecipient Response class format"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # DUTConnectionID
    return


@pytest.mark.parametrize("class_type", LogEvent_Request())
def test_LogEvent_Request(class_type):
    """Validate LogEvent Request class format"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # ReasonCode
    assert (isinstance(class_type.fields_desc[2], ByteEnumField))   # LogDataFormat
    assert (isinstance(class_type.fields_desc[3], FieldLenField))   # LogDataLength
    assert (isinstance(class_type.fields_desc[4], FieldListField))  # LogData
    return


@pytest.mark.parametrize("class_type", LogEvent_Response())
def test_LogEvent_Response(class_type):
    """Validate LogEvent Response class format"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    return


@pytest.mark.parametrize("class_type", VendorDefinedAdmin_Request())
def test_VendorDefinedAdmint_Request(class_type):
    """Validate VendorDefinedAdmin Request class format"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XLEIntField))    # IANA
    return


@pytest.mark.parametrize("class_type", VendorDefinedAdmin_Response())
def test_VendorDefinedAdmin_Response(class_type):
    """Validate VendorDefinedAdmin Response class format"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XLEIntField))     # IANA
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode
    return


@pytest.mark.parametrize("class_type", TestMessage_Request())
def test_TestMessage_Request(class_type):
    """Validate TestMessage Request class format"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XLEIntField)) # DUTConnectionID
    assert (isinstance(class_type.fields_desc[1], LEIntField))  # MaximumWaitTime
    return


@pytest.mark.parametrize("class_type", TestMessage_Response())
def test_TestMessage_Response(class_type):
    """Validate TestMessage Response class format"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # ResponseCode
    assert (isinstance(class_type.fields_desc[1], XLEIntField))     # DUTConnectionID
    assert (isinstance(class_type.fields_desc[2], LEIntField))      # Elapsed Time
    return
