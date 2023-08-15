##############################################################################
#  File Abstract:
#  PyTest suite to validate DSP0280 class definitions and initialization.
##############################################################################

import pytest
from ptti.dmtf import *  # pylint: disable=unused-import, unused-wildcard-import

EXPECTED_VERSION_COMPLIANCE = 0x10

@pytest.mark.parametrize("class_type", TestServiceWrapper())
def test_TestServiceWrapper(class_type):
    """Validate TestServiceWrapper class initialization"""

    assert (class_type.Version == EXPECTED_VERSION_COMPLIANCE), \
        "Incorrect specification version"

    assert (class_type.ProtocolType == 0)
    assert (class_type.Reserved == 0)
    assert (class_type.Direction == 0)
    assert (class_type.TestClientID == 0)
    return


@pytest.mark.parametrize("class_type", Connect_Request())
def test_Connect_Request(class_type):
    """Verify Connect_Request class initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x00), "Incorrect class command code"
    assert (class_type.CommandCode == 0x00), "Incorrect command code initial value"

    assert (class_type.SecurityParameterLength == 0)
    assert (class_type.SecurityParameter == [])

    return


@pytest.mark.parametrize("class_type", Connect_Response())
def test_Connect_Response(class_type):
    """Validate Connect_Response class initialization"""

    assert (class_type.CommandValue == Connect_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"

    assert (class_type.CommandCode == 0)
    assert (class_type.ResponseCode == 0)
    assert (class_type.TestServiceVersion == 0x10)
    assert (class_type.TestClientID == 0)
    return


@pytest.mark.parametrize("class_type", Disconnect_Request())
def test_Disconnect_Request(class_type):
    """Verify Disconnect_Request class initialization"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x01), "Incorrect class command code"
    assert (class_type.CommandCode == 0x01), "Incorrect command code initial value"
    return


@pytest.mark.parametrize("class_type", Disconnect_Response())
def test_Disconnect_Response(class_type):
    """Validate Disconnect_Response class initialization"""

    assert (class_type.CommandValue == Disconnect_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    return


@pytest.mark.parametrize("class_type", QueryCapabilities_Request())
def test_QueryCapabilities_Request(class_type):
    """Validate QueryCapabilities_Request class initialization"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x10), "Incorrect class command code"
    assert (class_type.CommandCode == 0x10), "Incorrect command code initial value"
    return


@pytest.mark.parametrize("class_type", QueryCapabilities_Response())
def test_QueryCapabilities_Response(class_type):
    """Validate _Response class initialization"""

    assert (class_type.CommandValue == QueryCapabilities_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.Reserved == 0)
    assert (class_type.NumberOfCapabilitiesFields == None)
    assert (class_type.TestServiceCapabilities == [])
    return


@pytest.mark.parametrize("class_type", QueryStatus_Request())
def test_QueryStatus_Request(class_type):
    """Validate QueryStatus_Request class initialization"""

    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x11), "Incorrect class command code"
    assert (class_type.CommandCode == 0x11), "Incorrect command code initial value"
    return


@pytest.mark.parametrize("class_type", QueryStatus_Response())
def test_QueryStatus_Response(class_type):
    """Validate QueryStatus_Response class initialization"""

    assert (class_type.CommandValue == QueryStatus_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.QueryType == 0)
    assert (class_type.QueryResponseDataLength == 0)
    return


@pytest.mark.parametrize("class_type", QuerySystemInventory_Request())
def test_QuerySystemInventory_Request(class_type):
    """Validate QuerySystemInventory_Request class initialization"""

    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x12), "Incorrect class command code"
    assert (class_type.CommandCode == 0x12), "Incorrect command code initial value"
    return


@pytest.mark.parametrize("class_type", QuerySystemInventory_Response())
def test_QuerySystemInventory_Response(class_type):
    """Validate QuerySystemInventory_Response class initialization"""

    assert (class_type.CommandValue == QuerySystemInventory_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.SystemInventory == None)
    return


@pytest.mark.parametrize("class_type", ConfigureTestService_Request())
def test_ConfigureTestService_Request(class_type):
    """Validate ConfigureTestService_Request class initialization"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x20), "Incorrect class command code"
    assert (class_type.CommandCode == 0x20), "Incorrect command code initial value"

    assert (class_type.NumberOfCapabilitiesFields == 0)
    assert (class_type.TestServiceCapabilities == [])
    return


@pytest.mark.parametrize("class_type", ConfigureTestService_Response())
def test_ConfigureTestService_Response(class_type):
    """Validate ConfigureTestService_Response class initialization"""

    assert (class_type.CommandValue == ConfigureTestService_Request.CommandValue), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.CommandCode == ConfigureTestService_Request.CommandValue), "Incorrect command code"

    assert (class_type.CommandCode == class_type.CommandCode)
    assert (class_type.ResponseCode == 0)
    return


@pytest.mark.parametrize("class_type", ConfigureDeviceUnderTest_Request())
def test_ConfigureDeviceUnderTest_Request(class_type):
    """Validate ConfigureDeviceUnderTest_Request class initialization"""

    assert (len(class_type.fields_desc) == 4), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x21), "Incorrect class command code"
    assert (class_type.CommandCode == 0x21), "Incorrect command code initial value"

    assert (class_type.TargetIdentifier == 0)
    assert (class_type.IdentifierCount == 0)
    assert (class_type.IdentifierList == [])
    return


@pytest.mark.parametrize("class_type", ConfigureDeviceUnderTest_Response())
def test_ConfigureDeviceUnderTest_Response(class_type):
    """Validate ConfigureDeviceUnderTest_Response class initialization"""

    assert (class_type.CommandValue == ConfigureDeviceUnderTest_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.DUTConnectionID == 0)
    assert (class_type.IdentifierCount == 0)
    assert (class_type.IdentifierList == [])
    return


@pytest.mark.parametrize("class_type", RegisterToProtocol_Request())
def test_RegisterToProtocol_Request(class_type):
    "Validate RegisterToProtocol_Request class initialization"

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x22), "Incorrect class command code"
    assert (class_type.CommandCode == 0x22), "Incorrect command code initial value"

    assert (class_type.ProtocolType == 0)
    assert (class_type.DUTConnectionID == 0)
    assert (class_type.TypeCount == 0)
    assert (class_type.TypeList == [])
    return


@pytest.mark.parametrize("class_type", RegisterToProtocol_Response())
def test_RegisterToProtocol_Response(class_type):
    "Validate RegisterToProtocol_Response class initialization"

    assert (class_type.CommandValue == RegisterToProtocol_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.DUTConnectionID == 0)
    return


@pytest.mark.parametrize("class_type", RegisterAsyncMessageRecipient_Request())
def test_RegisterAsyncMessageRecipient_Request(class_type):
    """Validate RegisterAsyncMessageRecipient_Request class initialization"""

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x23), "Incorrect class command code"
    assert (class_type.CommandCode == 0x23), "Incorrect command code initial value"

    assert (class_type.ProtocolType == 0)
    assert (class_type.DUTConnectionID == 0)
    assert (class_type.TypeCount == 0)
    assert (class_type.TypesList == [])
    return


@pytest.mark.parametrize("class_type", RegisterAsyncMessageRecipient_Response())
def test_RegisterAsyncMessageRecipient_Response(class_type):
    """Validate RegisterAsyncMessageRecipient_Response class initialization"""

    assert (class_type.CommandValue == RegisterAsyncMessageRecipient_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    assert (class_type.DUTConnectionID == 0)
    return


@pytest.mark.parametrize("class_type", LogEvent_Request())
def test_LogEvent_Request(class_type):
    "Validate LogEvent_Request class initialization"

    assert (len(class_type.fields_desc) == 5), "Incorrect number of fields"
    assert (class_type.CommandValue == 0x30), "Incorrect class command code"
    assert (class_type.CommandCode == 0x30), "Incorrect command code initial value"

    assert (class_type.ReasonCode == 0)
    assert (class_type.LogDataFormat == 0)
    assert (class_type.LogDataLength == 0)
    assert (class_type.LogData == [])
    return


@pytest.mark.parametrize("class_type", LogEvent_Response())
def test_LogEvent_Response(class_type):
    "Validate LogEvent_Response class initialization"

    assert (class_type.CommandValue == LogEvent_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.CommandCode == class_type.CommandValue)
    assert (class_type.ResponseCode == 0)
    return


@pytest.mark.parametrize("class_type", VendorDefinedAdmin_Request())
def test_VendorDefinedAdmint_Request(class_type):
    "Validate VendorDefinedAdmin_Request class initialization"

    assert (class_type.CommandValue == 0xF1), "Incorrect class command code"
    assert (len(class_type.fields_desc) == 1), "Incorrect number of fields"
    assert (class_type.IANA == 0x00000000)
    return


@pytest.mark.parametrize("class_type", VendorDefinedAdmin_Response())
def test_VendorDefinedAdmin_Response(class_type):
    "Validate VendorDefinedAdmin_Response class initialization"

    assert (class_type.CommandValue == VendorDefinedAdmin_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.IANA == 0x00000000)
    assert (class_type.ResponseCode == 0)
    return


@pytest.mark.parametrize("class_type", TestMessage_Request())
def test_TestMessage_Request(class_type):
    "Validate TestMessage_Request class initialization"

    assert (class_type.CommandValue == 0xF7), "Incorrect class command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.DUTConnectionID == 0)
    assert (class_type.MaximumWaitTime == 0)
    return


@pytest.mark.parametrize("class_type", TestMessage_Response())
def test_TestMessage_Response(class_type):
    "Validate TestMessage_Response class initialization"

    assert (class_type.CommandValue == TestMessage_Request.CommandValue), \
        "Incorrect command code"
    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0)
    assert (class_type.DUTConnectionID == 0)
    assert (class_type.ElapsedTime == 0)
    return
