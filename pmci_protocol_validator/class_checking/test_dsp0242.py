# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Verify PLDM for File Tranfser classes
##############################################################################

import pytest
from pmci_protocol_validator.pldm.classes.dsp0242 import *


@pytest.mark.parametrize("class_type", PLDM_TYPE_7_PAYLOAD())
def test_PLDM_TYPE_7_PAYLOAD_class(class_type):
    """Verify PLDM_TYPE_7_PAYLOAD class initialization"""

    assert (class_type.PldmPayloadType == 0x07)
    assert (len(class_type.fields_desc) == 0)
    return


@pytest.mark.parametrize("class_type", DfOpen_Request())
def test_DfOpen_Request(class_type):
    """ Verify DfOpen_Request initialization """

    assert (class_type.CommandValue == 0x01)

    assert (len(class_type.fields_desc) == 6)
    assert (isinstance(class_type.fields_desc[0], XShortField))   # FileIdentifier
    assert (isinstance(class_type.fields_desc[1], BitEnumField))  # DfOpenReadWrite
    assert (isinstance(class_type.fields_desc[2], BitEnumField))  # DfOpenExclusive
    assert (isinstance(class_type.fields_desc[3], BitEnumField))  # DfOpenRegFifo
    assert (isinstance(class_type.fields_desc[4], BitEnumField))  # DfOpenPolledPushed
    assert (isinstance(class_type.fields_desc[5], BitField))      # Reserved

    assert (class_type.FileIdentifier == 0)
    assert (class_type.DfOpenReadWrite == 0)
    assert (class_type.DfOpenExclusive == 0)
    assert (class_type.DfOpenRegFIFO == 0)
    assert (class_type.DfOpenPolledPushed == 0)
    assert (class_type.Reserved == 0)
    return


@pytest.mark.parametrize("class_type", DfOpen_Response())
def test_DfOpen_Response(class_type):
    """ Verify DfOpen_Response initialization """

    assert (class_type.CommandValue == DfOpen_Request.CommandValue)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))    # CompletionCode
    assert (isinstance(class_type.fields_desc[1], ConditionalField))  # FileDescriptor

    assert (class_type.CompletionCode == 0x00)
    assert (class_type.FileDescriptor == 0x00)
    return


@pytest.mark.parametrize("class_type", DfClose_Request())
def test_DfClose_Request(class_type):
    """ Verify DfClose_Request initialization """

    assert (class_type.CommandValue == 0x02)

    assert (len(class_type.fields_desc) == 3)
    assert (isinstance(class_type.fields_desc[0], XShortField))   # FileDescriptor
    assert (isinstance(class_type.fields_desc[1], BitEnumField))  # ZeroLength
    assert (isinstance(class_type.fields_desc[2], BitField))      # Reserved

    assert (class_type.FileDescriptor == 0)
    assert (class_type.ZeroLength == 0)
    assert (class_type.Reserved == 0)
    return


@pytest.mark.parametrize("class_type", DfClose_Response())
def test_DfClose_Response(class_type):
    """ Verify DfClose_Response initialization """

    assert (class_type.CommandValue == DfClose_Request.CommandValue)

    assert (len(class_type.fields_desc) == 1)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))  # CompletionCode

    assert (class_type.CompletionCode == 0x00)
    return


@pytest.mark.parametrize("class_type", DfHeartbeat_Request())
def test_DfHeartbeat_Request(class_type):
    """ Verify DfHeartbeat_Request initialization """

    assert (class_type.CommandValue == 0x03)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XShortField))  # FileDescriptor
    assert (isinstance(class_type.fields_desc[1], IntField))     # RequestorMaxInterval

    assert (class_type.FileDescriptor == 0x0000)
    assert (class_type.RequestorMaxInterval == 0)
    return


@pytest.mark.parametrize("class_type", DfHeartbeat_Response())
def test_DfHeartbeat_Response(class_type):
    """ Verify DfHeartbeat_Response initialization """

    assert (class_type.CommandValue == DfHeartbeat_Request.CommandValue)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))    # CompletionCode
    assert (isinstance(class_type.fields_desc[1], ConditionalField))  # ResponderMaxInterval

    assert (class_type.CompletionCode == 0x0000)
    assert (class_type.ResponderMaxInterval == 0)
    return


@pytest.mark.parametrize("class_type", DfProperties_Request())
def test_DfProperties_Request(class_type):
    """ Verify DfProperties initialization """

    assert (class_type.CommandValue == 0x10)

    assert (len(class_type.fields_desc) == 4)
    assert (isinstance(class_type.fields_desc[0], XShortField))   # FileDescriptor
    assert (isinstance(class_type.fields_desc[1], BitEnumField))  # MaxConcurrentMedium
    assert (isinstance(class_type.fields_desc[2], BitEnumField))  # MaxFileDescriptors
    assert (isinstance(class_type.fields_desc[3], BitField))      # Reserved

    assert (class_type.FileDescriptor == 0)
    assert (class_type.MaxConcurrentMedium == 0)
    assert (class_type.MaxFileDescriptors == 0)
    assert (class_type.Reserved == 0)
    return


@pytest.mark.parametrize("class_type", DfProperties_Response())
def test_DfProperties_Response(class_type):
    """ Verify DfProperties_Response initialization """

    assert (class_type.CommandValue == DfProperties_Request.CommandValue)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))    # CompletionCode
    assert (isinstance(class_type.fields_desc[1], ConditionalField))  # FileAttributeValue

    assert (class_type.CompletionCode == 0)
    assert (class_type.FileAttributeValue == 0)
    return


@pytest.mark.parametrize("class_type", DfGetFileAttribute_Request())
def test_DfGetFileAttribute_Request(class_type):
    """ Verify DfGetFileAttribute_Request initialization """

    assert (class_type.CommandValue == 0x11)

    assert (len(class_type.fields_desc) == 6)
    assert (isinstance(class_type.fields_desc[0], XShortField))   # FileIdentifier
    assert (isinstance(class_type.fields_desc[1], BitEnumField))  # ClientDeleteOnly
    assert (isinstance(class_type.fields_desc[2], BitField))      # Reserved_1_15
    assert (isinstance(class_type.fields_desc[3], BitEnumField))  # RequestCI
    assert (isinstance(class_type.fields_desc[4], BitEnumField))  # ReqMaxPoll
    assert (isinstance(class_type.fields_desc[5], BitField))      # CompletionCode

    assert (class_type.FileIdentifier == 0)
    assert (class_type.ClientDeleteOnly == 0)
    assert (class_type.Reserved_1_15 == 0)
    assert (class_type.RequestCI == 0)
    assert (class_type.ReqMaxPoll == 0)
    assert (class_type.Reserved_18_31 == 0)
    return


@pytest.mark.parametrize("class_type", DfGetFileAttribute_Response())
def test_DfGetFileAttribute_Response(class_type):
    """ Verify DfGetFileAttribute_Response initialization """

    assert (class_type.CommandValue == DfGetFileAttribute_Request.CommandValue)

    assert (len(class_type.fields_desc) == 2)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))    # CompletionCode
    assert (isinstance(class_type.fields_desc[1], ConditionalField))  # FileAttributeValue

    assert (class_type.CompletionCode == 0)
    assert (class_type.FileAttributeValue == 0)
    return


@pytest.mark.parametrize("class_type", DfSetFileAttribute_Request())
def test_DfSetFileAttribute_Request(class_type):
    """ Verify DfSetFileAttribute_Request initialization """

    assert (class_type.CommandValue == 0x12)

    assert (len(class_type.fields_desc) == 4)
    assert (isinstance(class_type.fields_desc[0], XShortField))   # FileIdentifier
    assert (isinstance(class_type.fields_desc[1], BitEnumField))  # ClientZeroLengthOnly
    assert (isinstance(class_type.fields_desc[2], BitField))      # Reserved_1_15
    assert (isinstance(class_type.fields_desc[3], IntField))      # FileAttributeValue

    assert (class_type.FileIdentifier == 0x0000)
    assert (class_type.ClientZeroLengthOnly == 0)
    assert (class_type.Reserved_1_15 == 0)
    assert (class_type.FileAttributeValue == 0)
    return


@pytest.mark.parametrize("class_type", DfSetFileAttribute_Response())
def test_DfSetFileAttribute_Response(class_type):
    """ Verify DfSetFileAttribute_Response initialization """

    assert (class_type.CommandValue == DfSetFileAttribute_Request.CommandValue)

    assert (len(class_type.fields_desc) == 1)
    assert (isinstance(class_type.fields_desc[0], XByteEnumField))    # CompletionCode

    assert (class_type.CompletionCode == 0x00)
    return
