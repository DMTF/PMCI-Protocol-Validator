# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  PyTest suite to validate DSP0280 class definitions and initialization.
##############################################################################

import pytest
from scapy.fields import *  # pylint: disable=unused-import, unused-wildcard-import
from ptti.dmtf import *  # pylint: disable=unused-import, unused-wildcard-import

EXPECTED_VERSION_COMPLIANCE = 0x11


@pytest.mark.parametrize("class_type", TestServiceWrapper())
def test_TestServiceWrapper(class_type):
    """ Validate TestServiceWrapper class initialization """

    # Verify the class contains the required number and types of fields
    assert (len(class_type.fields_desc) == 8)

    assert (isinstance(class_type.fields_desc[0], XByteField))      # Version
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ProtocolType
    assert (isinstance(class_type.fields_desc[2], BitField))        # Reserved_0
    assert (isinstance(class_type.fields_desc[3], BitEnumField))    # Direction
    assert (isinstance(class_type.fields_desc[4], BitField))        # Reserved_1
    assert (isinstance(class_type.fields_desc[5], XLEIntField))     # TestClientID
    assert (isinstance(class_type.fields_desc[6], LEShortField))    # TransferLength
    assert (isinstance(class_type.fields_desc[7], NBytesField))     # Reserved_3

    # Verify the class field names and initial values
    assert (class_type.Version == EXPECTED_VERSION_COMPLIANCE)
    assert (class_type.ProtocolType == 0xFF)
    assert (class_type.Reserved_0 == 0)
    assert (class_type.Direction == 0)
    assert (class_type.Reserved_1 == 0)
    assert (class_type.TestClientID == 0)
    assert (class_type.TransferLength == 0)
    assert (class_type.Reserved_3 == 0)
    return


@pytest.mark.parametrize("class_type", Connect_Request())
def test_Connect_Request(class_type):
    """ Verify Connect_Request class initialization """

    # Verify class command value matches specification
    assert (class_type.CommandValue == 0x00)

    # Verify the class contains the required number and types of fields
    assert (len(class_type.fields_desc) == 3)

    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], FieldLenField))   # SecurityParameterLength
    assert (isinstance(class_type.fields_desc[2], FieldListField))  # SecurityParameter

    # Verify the class field names and initial values
    assert (class_type.CommandCode == 0x00)
    assert (class_type.SecurityParameterLength == 0)
    assert (class_type.SecurityParameter == [])

    return


@pytest.mark.parametrize("class_type", Connect_Response())
def test_Connect_Response(class_type):
    """ Validate Connect_Response class initialization """

    assert (class_type.CommandValue == Connect_Request.CommandValue)

    assert (len(class_type.fields_desc) == 4)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))      # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))      # ResponseCode
    assert (isinstance(class_type.fields_desc[2], ConditionalField))    # TestServiceVersion
    assert (isinstance(class_type.fields_desc[3], ConditionalField))    # TestClientID

    assert (class_type.CommandCode == 0)
    assert (class_type.ResponseCode == 0)
    assert (class_type.TestServiceVersion == EXPECTED_VERSION_COMPLIANCE)
    assert (class_type.TestClientID == 0)
    return


@pytest.mark.parametrize("class_type", Disconnect_Request())
def test_Disconnect_Request(class_type):
    """ Verify Disconnect_Request class initialization """

    assert (class_type.CommandValue == 0x01)

    assert (len(class_type.fields_desc) == 1)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode

    assert (class_type.CommandCode == 0x01)
    return


@pytest.mark.parametrize("class_type", Disconnect_Response())
def test_Disconnect_Response(class_type):
    """ Validate Disconnect_Response class initialization """

    assert (class_type.CommandValue == Disconnect_Request.CommandValue)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    return


@pytest.mark.parametrize("class_type", QueryCapabilities_Request())
def test_QueryCapabilities_Request(class_type):
    """ Validate QueryCapabilities_Request class initialization """

    assert (class_type.CommandValue == 0x10)

    assert (len(class_type.fields_desc) == 1)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode

    assert (class_type.CommandCode == 0x10)
    return


@pytest.mark.parametrize("class_type", TestServiceCapabilityEntry())
def test_TestServiceCapabilityEntry(class_type):
    """ Validate TestServiceCapabilityEntry class format """

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], ShortField))  # CapabilityID
    assert (isinstance(class_type.fields_desc[1], LEIntField))  # CapabilityValue

    assert (class_type.CapabilityID == 0)
    assert (class_type.CapabilityValue == 0)
    return


@pytest.mark.parametrize("class_type", QueryCapabilities_Response())
def test_QueryCapabilities_Response(class_type):
    """ Validate _Response class initialization """

    assert (class_type.CommandValue == QueryCapabilities_Request.CommandValue)

    assert (len(class_type.fields_desc) == 5)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))      # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))      # ResponseCode
    assert (isinstance(class_type.fields_desc[2], ConditionalField))    # Reserved
    assert (isinstance(class_type.fields_desc[3], ConditionalField))    # NumberOfCapabilitiesFields
    assert (isinstance(class_type.fields_desc[4], ConditionalField))    # TestServiceCapabilities

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.Reserved == 0)
    assert (class_type.NumberOfCapabilitiesFields is None)
    assert (class_type.TestServiceCapabilities == [])
    return


@pytest.mark.parametrize("class_type", QueryStatus_Request())
def test_QueryStatus_Request(class_type):
    """ Validate QueryStatus_Request class initialization """

    assert (class_type.CommandValue == 0x11)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # QueryType

    assert (class_type.CommandCode == 0x11)
    assert (class_type.QueryType == 0)
    return


@pytest.mark.parametrize("class_type", QueryStatus_Response())
def test_QueryStatus_Response(class_type):
    """ Validate QueryStatus_Response class initialization """

    assert (class_type.CommandValue == QueryStatus_Request.CommandValue)

    assert (len(class_type.fields_desc) == 6)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))      # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))      # ResponseCode
    assert (isinstance(class_type.fields_desc[2], ConditionalField))    # QueryType
    assert (isinstance(class_type.fields_desc[3], ConditionalField))    # QueryResponseDataLength

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.QueryType == 0)
    assert (class_type.QueryResponseDataLength == 0)
    assert (class_type.QueryStatusDeviceData is None)
    return


@pytest.mark.parametrize("class_type", QuerySystemInventory_Request())
def test_QuerySystemInventory_Request(class_type):
    """ Validate QuerySystemInventory_Request class initialization """

    assert (class_type.CommandValue == 0x12)

    assert (len(class_type.fields_desc) == 1)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode

    assert (class_type.CommandCode == 0x12)
    return


@pytest.mark.parametrize("class_type", QuerySystemInventory_Response())
def test_QuerySystemInventory_Response(class_type):
    """ Validate QuerySystemInventory_Response class initialization """

    assert (class_type.CommandValue == QuerySystemInventory_Request.CommandValue)

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))      # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))      # ResponseCode
    assert (isinstance(class_type.fields_desc[2], ConditionalField))    # SystemInventory

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.SystemInventory is None)
    return


@pytest.mark.parametrize("class_type", ConfigureTestService_Request())
def test_ConfigureTestService_Request(class_type):
    """ Validate ConfigureTestService_Request class initialization """

    assert (class_type.CommandValue == 0x20)

    assert (len(class_type.fields_desc) == 3)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))   # CommandCode
    assert (isinstance(class_type.fields_desc[1], FieldLenField))    # NumberOfCapabilitiesFields
    assert (isinstance(class_type.fields_desc[2], PacketListField))  # TestServiceCapabilities

    assert (class_type.CommandCode == 0x20)
    assert (class_type.NumberOfCapabilitiesFields == 0)
    assert (class_type.TestServiceCapabilities == [])
    return


@pytest.mark.parametrize("class_type", ConfigureTestService_Response())
def test_ConfigureTestService_Response(class_type):
    """ Validate ConfigureTestService_Response class initialization """

    assert (class_type.CommandValue == ConfigureTestService_Request.CommandValue)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode

    assert (class_type.CommandCode == class_type.CommandCode)
    assert (class_type.ResponseCode == 0)
    return


@pytest.mark.parametrize("class_type", ConfigureDeviceUnderTest_Request())
def test_ConfigureDeviceUnderTest_Request(class_type):
    """ Validate ConfigureDeviceUnderTest_Request class initialization """

    assert (class_type.CommandValue == 0x21)

    assert (len(class_type.fields_desc) == 4)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XLEIntField))     # TargetIdentifier
    assert (isinstance(class_type.fields_desc[2], FieldLenField))   # IdentifierCount
    assert (isinstance(class_type.fields_desc[3], FieldListField))  # IdentifierList

    assert (class_type.CommandCode == 0x21)
    assert (class_type.TargetIdentifier == 0)
    assert (class_type.IdentifierCount == 0)
    assert (class_type.IdentifierList == [])
    return


@pytest.mark.parametrize("class_type", ConfigureDeviceUnderTest_Response())
def test_ConfigureDeviceUnderTest_Response(class_type):
    """ Validate ConfigureDeviceUnderTest_Response class initialization """

    assert (class_type.CommandValue == ConfigureDeviceUnderTest_Request.CommandValue)

    assert (len(class_type.fields_desc) == 5)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))      # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))      # ResponseCode
    assert (isinstance(class_type.fields_desc[2], ConditionalField))    # DUTConnectionID
    assert (isinstance(class_type.fields_desc[3], ConditionalField))    # IdentifierCount
    assert (isinstance(class_type.fields_desc[4], ConditionalField))    # IdentifierList

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.DUTConnectionID == 0)
    assert (class_type.IdentifierCount == 0)
    assert (class_type.IdentifierList == [])
    return


@pytest.mark.parametrize("class_type", RegisterToProtocol_Request())
def test_RegisterToProtocol_Request(class_type):
    """ Validate RegisterToProtocol_Request class initialization """

    assert (class_type.CommandValue == 0x22)

    assert (len(class_type.fields_desc) == 5)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # ProtocolType
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # DUTConnectionID
    assert (isinstance(class_type.fields_desc[3], FieldLenField))   # TypeCount
    assert (isinstance(class_type.fields_desc[4], FieldListField))  # TypeList

    assert (class_type.CommandCode == 0x22)
    assert (class_type.ProtocolType == 0)
    assert (class_type.DUTConnectionID == 0)
    assert (class_type.TypeCount == 0)
    assert (class_type.TypeList == [])
    return


@pytest.mark.parametrize("class_type", RegisterToProtocol_Response())
def test_RegisterToProtocol_Response(class_type):
    """ Validate RegisterToProtocol_Response class initialization """

    assert (class_type.CommandValue == RegisterToProtocol_Request.CommandValue)

    assert (len(class_type.fields_desc) == 3)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))      # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))      # ResponseCode
    assert (isinstance(class_type.fields_desc[2], ConditionalField))    # DUTConnectionID

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.DUTConnectionID == 0)
    return


@pytest.mark.parametrize("class_type", RegisterAsyncMessageRecipient_Request())
def test_RegisterAsyncMessageRecipient_Request(class_type):
    """ Validate RegisterAsyncMessageRecipient_Request class initialization """

    assert (class_type.CommandValue == 0x23)

    assert (len(class_type.fields_desc) == 5)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # ProtocolType
    assert (isinstance(class_type.fields_desc[2], XLEIntField))     # DUTConnectionID
    assert (isinstance(class_type.fields_desc[3], FieldLenField))   # TypeCount
    assert (isinstance(class_type.fields_desc[4], FieldListField))  # TypesList

    assert (class_type.CommandCode == 0x23)
    assert (class_type.ProtocolType == 0)
    assert (class_type.DUTConnectionID == 0)
    assert (class_type.TypeCount == 0)
    assert (class_type.TypeList == [])
    return


@pytest.mark.parametrize("class_type", RegisterAsyncMessageRecipient_Response())
def test_RegisterAsyncMessageRecipient_Response(class_type):
    """ Validate RegisterAsyncMessageRecipient_Response class initialization """

    assert (class_type.CommandValue == RegisterAsyncMessageRecipient_Request.CommandValue)

    assert (len(class_type.fields_desc) == 3)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))      # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))      # ResponseCode
    assert (isinstance(class_type.fields_desc[2], ConditionalField))    # DUTConnectionID

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.DUTConnectionID == 0)
    return


@pytest.mark.parametrize("class_type", LogEvent_Request())
def test_LogEvent_Request(class_type):
    """ Validate LogEvent_Request class initialization """

    assert (class_type.CommandValue == 0x30)

    assert (len(class_type.fields_desc) == 5)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], ByteEnumField))   # ReasonCode
    assert (isinstance(class_type.fields_desc[2], ByteEnumField))   # LogDataFormat
    assert (isinstance(class_type.fields_desc[3], FieldLenField))   # LogDataLength
    assert (isinstance(class_type.fields_desc[4], FieldListField))  # LogData

    assert (class_type.CommandCode == 0x30)
    assert (class_type.ReasonCode == 0)
    assert (class_type.LogDataFormat == 0)
    assert (class_type.LogDataLength == 0)
    assert (class_type.LogData == [])
    return


@pytest.mark.parametrize("class_type", LogEvent_Response())
def test_LogEvent_Response(class_type):
    """ Validate LogEvent_Response class initialization """

    assert (class_type.CommandValue == LogEvent_Request.CommandValue)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CommandCode
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    return


@pytest.mark.parametrize("class_type", VendorDefinedAdmin_Request())
def test_VendorDefinedAdmint_Request(class_type):
    """Validate VendorDefinedAdmin_Request class initialization """

    assert (class_type.CommandValue == 0xF1)

    assert (len(class_type.fields_desc) == 1)
    assert (isinstance(class_type.fields_desc[0], XLEIntField))  # IANA

    assert (class_type.IANA == 0x00000000)
    return


@pytest.mark.parametrize("class_type", VendorDefinedAdmin_Response())
def test_VendorDefinedAdmin_Response(class_type):
    """ Validate VendorDefinedAdmin_Response class initialization """

    assert (class_type.CommandValue == VendorDefinedAdmin_Request.CommandValue)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XLEIntField))     # IANA
    assert (isinstance(class_type.fields_desc[1], XByteEnumField))  # ResponseCode

    assert (class_type.IANA == 0x00000000)
    assert (class_type.ResponseCode == 0)
    return


@pytest.mark.parametrize("class_type", TestMessage_Request())
def test_TestMessage_Request(class_type):
    """ Validate TestMessage_Request class initialization """

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XLEIntField))  # DUTConnectionID
    assert (isinstance(class_type.fields_desc[1], LEIntField))   # MaximumWaitTime

    assert (class_type.DUTConnectionID == 0)
    assert (class_type.MaximumWaitTime == 0)
    return


@pytest.mark.parametrize("class_type", TestMessage_Response())
def test_TestMessage_Response(class_type):
    """ Validate TestMessage_Response class initialization """

    assert (len(class_type.fields_desc) == 3)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))    # ResponseCode
    assert (isinstance(class_type.fields_desc[1], ConditionalField))  # DUTConnectionID
    assert (isinstance(class_type.fields_desc[2], ConditionalField))  # Elapsed Time

    assert (class_type.ResponseCode == 0)
    assert (class_type.DUTConnectionID == 0)
    assert (class_type.ElapsedTime == 0)
    return
