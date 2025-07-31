# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Verify the Binary Encoded JSON class and type structures
##############################################################################

import pytest
from scapy.fields import *
from pmci_protocol_validator.pldm.classes.dsp0218_bej_types import *


# Validate bejTupleS[]
assert (type(bejTupleS[0]) == ByteField)
assert (type(bejTupleS[1]) == MultipleTypeField)


# Validate bejTupleF[]
assert (type(bejTupleF[0]) == BitEnumField)
assert (type(bejTupleF[1]) == BitEnumField)
assert (type(bejTupleF[2]) == BitEnumField)
assert (type(bejTupleF[3]) == BitEnumField)
assert (type(bejTupleF[4]) == BitEnumField)


# Validate bejTupleL[]
assert (type(bejTupleL[0]) == ByteField)
assert (type(bejTupleL[1]) == MultipleTypeField)


# Validate bejTupleV[]
assert (type(bejTupleV[0]) == MultipleTypeField)


@pytest.mark.parametrize("cls", BejNULL())
def test_BejNULL(cls):
    assert (len(cls.fields_desc) == 1)


@pytest.mark.parametrize("cls", BejInteger())
def test_BejNULL(cls):
    assert (len(cls.fields_desc) == 3)


@pytest.mark.parametrize("cls", BejEnum())
def test_BejEnum(cls):
    assert (len(cls.fields_desc) == 4)
    assert (cls.BytesOfValue == 0x00)
    assert (cls.Value == 0x00)


@pytest.mark.parametrize("cls", BejString())
def test_BejString(cls):
    assert (len(cls.fields_desc) == 3)
    assert (cls.Value == b'')


@pytest.mark.parametrize("cls", BejResourceLink())
def test_BejResourceLink(cls):
    assert (len(cls.fields_desc) == 4)
    assert (cls.BytesOfValue == 0x00)
    assert (cls.Value == 0x00)


@pytest.mark.parametrize("cls", BejTuple())
def test_BejTuple(cls):
    assert (len(cls.fields_desc) == 14)


@pytest.mark.parametrize("cls", BejSetTuple())
def test_BejSetTuple(cls):
    assert (len(cls.fields_desc) == 5)
