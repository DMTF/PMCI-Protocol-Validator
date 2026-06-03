# Copyright Notice:
# Copyright 2025-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Verify DSP0237 classes

File : test_dsp0237.py

Brief : Verify DSP0237 Scapy classes
"""

import pytest
from scapy.fields import *
from pmci_protocol_validator.mctp.classes.dsp0237 import SMBUS


@pytest.mark.parametrize("class_type", SMBUS())
def test_mctp_smbus_header(class_type):
    """ Verify MCTP SM BUS binding header structure """

    # Verify the class contains the required number of fields
    assert (len(class_type.fields_desc) == 8)

    # Verify the fields data type
    assert (isinstance(class_type.fields_desc[0], BitField))     # DestAddr
    assert (isinstance(class_type.fields_desc[1], BitField))     # DestRW
    assert (isinstance(class_type.fields_desc[2], XByteField))   # CommandCode
    assert (isinstance(class_type.fields_desc[3], ByteField))    # ByteCount
    assert (isinstance(class_type.fields_desc[4], BitField))     # SrcAddr
    assert (isinstance(class_type.fields_desc[5], BitField))     # SrcRW
    assert (isinstance(class_type.fields_desc[6], PacketField))  # MctpHeader
    assert (isinstance(class_type.fields_desc[7], XByteField))   # PEC

    # Verify the class field names and initial values
    assert (class_type.DestAddr == 0)
    assert (class_type.DestRW == 0)
    assert (class_type.CommandCode == 0x0F)
    assert (class_type.ByteCount is None)
    assert (class_type.SrcAddr == 0)
    assert (class_type.SrcRW == 1)
    assert (class_type.MctpHeader is None)
    assert (class_type.PEC is None)
    return
