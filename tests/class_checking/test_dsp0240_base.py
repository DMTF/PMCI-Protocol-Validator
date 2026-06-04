# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Verify miscellaneous PLDM Scapy classes

File : test_dsp0240_base.py

Brief : Verify miscellaneous PLDM Scapy classes
"""

import pytest

from pmci_protocol_validator.pldm.dsp0240_base import (
    PLDM_HEADER,
    PLDM_PAYLOAD,
    PLDM_UUID,
    VAR_STRING,
    PLDM_TIMESTAMP104
)

@pytest.mark.parametrize("class_type", PLDM_HEADER())
def test_PLDM_HEADER_class(class_type):
    """Verify PLDM_HEADER class initialization"""

    assert (len(class_type.fields_desc) == 7), "Incorrect number of fields"

    assert (class_type.Request == 0)
    assert (class_type.Datagram == 0)
    assert (class_type.PldmHeaderReserved_1 == 0)
    assert (class_type.InstanceID == 0)
    assert (class_type.HeaderVersion == 0)
    assert (class_type.PldmType == 0)
    assert (class_type.CommandCode is None)
    return


@pytest.mark.parametrize("class_type", PLDM_PAYLOAD())
def test_PLDM_PAYLOAD_class(class_type):
    """Verify PLDM_PAYLOAD class structure"""

    assert (PLDM_PAYLOAD.MctpPayloadType == 0x01)
    assert (PLDM_PAYLOAD.PayloadType == 0x00)
    return


@pytest.mark.parametrize("class_type", PLDM_UUID())
def test_PLDM_UUID_class(class_type):
    """Verify PLDM_UUID class structure"""

    assert (PLDM_UUID.UUID_NODE_LEN == 6), "Incorrect Node size"
    assert (len(class_type.fields_desc) == 6), "Incorrect number of fields"

    assert (class_type.TimeLow == 0)
    assert (class_type.TimeMid == 0)
    assert (class_type.TimeHighAndVersion == 0)
    assert (class_type.ClockSeqHighAndReserved == 0)
    assert (class_type.ClockSeqLow == 0)
    assert (class_type.Node is None)
    return


@pytest.mark.parametrize("class_type", VAR_STRING())
def test_VAR_STRING_class(class_type):
    """Verify VAR_STRING class structure"""

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.stringFormat == 0)
    assert (class_type.stringLengthBytes is None)
    assert (class_type.stringData == b"")
    return


@pytest.mark.parametrize("class_type", PLDM_TIMESTAMP104())
def test_PLDM_TIMESTAMP104_class(class_type):
    """Verify PLDM_TIMESTAMP104 class structure"""

    assert (len(class_type.fields_desc) == 9), "Incorrect number of fields"

    assert (class_type.UTC_offset == 0)
    assert (class_type.Microseconds == 0)
    assert (class_type.Seconds == 0)
    assert (class_type.Minute == 0)
    assert (class_type.Hour == 0)
    assert (class_type.Day == 0)
    assert (class_type.Month == 0)
    assert (class_type.Year == 0)
    assert (class_type.Resolution == 0)
    return
