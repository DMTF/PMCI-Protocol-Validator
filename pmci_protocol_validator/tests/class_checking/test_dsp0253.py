# Copyright Notice:
# Copyright 2025-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Verify DSP0253 Scapy classes

File : test_dsp0253.py

Brief : Verify DSP0253 Scapy classes
"""

import pytest
from scapy.fields import *
from pmci_protocol_validator.mctp.classes.dsp0253 import SERIAL


@pytest.mark.parametrize("class_type", SERIAL())
def test_mctp_serial_header(class_type):
    """ Verify MCTP serial binding header structure """

    # Verify the class contains the required number of fields
    assert (len(class_type.fields_desc) == 6)

    # Verify the fields data type
    assert (isinstance(class_type.fields_desc[0], XByteField))        # FramingFlagStart
    assert (isinstance(class_type.fields_desc[1], ByteField))         # ProtocolRevision
    assert (isinstance(class_type.fields_desc[2], ByteField))         # ByteCount
    assert (isinstance(class_type.fields_desc[3], ConditionalField))  # MctpHeader
    assert (isinstance(class_type.fields_desc[4], XShortField))       # FrameCheckSequence
    assert (isinstance(class_type.fields_desc[5], XByteField))        # FramingFlagEnd

    # Verify the class field names and initial values
    assert (class_type.FramingFlagStart == 0x7E)
    assert (class_type.ProtocolRevision == 1)
    assert (class_type.ByteCount is None)
    assert (class_type.MctpHeader is None)
    assert (class_type.FrameCheckSequence is None)
    assert (class_type.FramingFlagEnd is None)
    return
