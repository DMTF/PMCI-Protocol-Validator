# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Verify the PLDM Payload Scapy classes

File : test_dsp0222_pldm_payload.py

Brief : Verify the PLDM Payload Scapy classes
"""

import pytest
from pmci_protocol_validator.ncsi.classes.dsp0222_pldm_payload import *


@pytest.mark.parametrize("class_type", NcsiPldm_Request())
def test_NcsiPldm_Request(class_type):
    """Verify NcsiPldm_Request initialization"""

    assert (class_type.CommandValue == 0x51), "Incorrect command code"
    return


@pytest.mark.parametrize("class_type", NcsiPldm_Response())
def test_NcsiPldm_Response(class_type):
    """Verify NcsiPldm_Response initialization"""

    assert (class_type.CommandValue == 0xD1), "Incorrect command code"
    assert (len(class_type.fields_desc) == 2), "Incorrect number of fields"

    assert (class_type.ResponseCode == 0x00)
    assert (class_type.ReasonCode == 0x12)
    return


@pytest.mark.parametrize("class_type", QueryPendingNcPldm_Request())
def test_QueryPendingNcPldm_Request(class_type):
    """Verify QueryPendingNcPldm_Request initialization"""

    assert (class_type.CommandValue == 0x56), "Incorrect command code"
    return


@pytest.mark.parametrize("class_type", QueryPendingNcPldm_Response())
def test_QueryPendingNcPldm_Response(class_type):
    """Verify QueryPendingNcPldm_Response initialization"""

    assert (class_type.CommandValue == 0xD6), "Incorrect command code"
    return
