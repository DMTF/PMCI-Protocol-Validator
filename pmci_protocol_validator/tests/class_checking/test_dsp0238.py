# Copyright Notice:
# Copyright 2025-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Verify DSP0238 Scapy classes

File : test_dsp0238.py

Brief : Verify DSP0238 Scapy classes
"""

import pytest
from scapy.fields import *
from pmci_protocol_validator.mctp.classes.dsp0238 import PCIE_VDM


@pytest.mark.parametrize("class_type", PCIE_VDM())
def test_mctp_pcie_vdm_header(class_type):
    """ Verify MCTP PCIe VDM binding header structure """

    # Verify the class contains the required number of fields
    assert (len(class_type.fields_desc) == 22)

    # Verify the fields data type
    assert (isinstance(class_type.fields_desc[0], BitField))      # Format
    assert (isinstance(class_type.fields_desc[1], BitField))      # Type
    assert (isinstance(class_type.fields_desc[2], BitField))      # T9
    assert (isinstance(class_type.fields_desc[3], BitField))      # TC
    assert (isinstance(class_type.fields_desc[4], BitField))      # Reserved0
    assert (isinstance(class_type.fields_desc[5], BitField))      # TD
    assert (isinstance(class_type.fields_desc[6], BitField))      # EP
    assert (isinstance(class_type.fields_desc[7], BitField))      # Attr
    assert (isinstance(class_type.fields_desc[8], BitField))      # AT
    assert (isinstance(class_type.fields_desc[9], BitField))      # Length
    assert (isinstance(class_type.fields_desc[10], XByteField))   # RequesterBus
    assert (isinstance(class_type.fields_desc[11], BitField))     # RequesterDevice
    assert (isinstance(class_type.fields_desc[12], BitField))     # RequesterFunction
    assert (isinstance(class_type.fields_desc[13], BitField))     # Reserved1
    assert (isinstance(class_type.fields_desc[14], BitField))     # PadLen
    assert (isinstance(class_type.fields_desc[15], BitField))     # MctpVdmCode
    assert (isinstance(class_type.fields_desc[16], XByteField))   # MessageCode
    assert (isinstance(class_type.fields_desc[17], XByteField))   # TargetBus
    assert (isinstance(class_type.fields_desc[18], BitField))     # TargetDevice
    assert (isinstance(class_type.fields_desc[19], BitField))     # TargetFunction
    assert (isinstance(class_type.fields_desc[20], XShortField))  # VendorID
    assert (isinstance(class_type.fields_desc[21], PacketField))  # MctpHeader

    # Verify the class field names and initial values
    assert (class_type.Format == 3)
    assert (class_type.Type == 2)
    assert (class_type.T9 == 0)
    assert (class_type.TC == 0)
    assert (class_type.Reserved0 == 0)
    assert (class_type.TD == 0)
    assert (class_type.EP == 0)
    assert (class_type.Attr == 0)
    assert (class_type.AT == 0)
    assert (class_type.Length is None)
    assert (class_type.RequesterBus == 0)
    assert (class_type.RequesterDevice == 0)
    assert (class_type.RequesterFunction == 0)
    assert (class_type.Reserved1 == 0)
    assert (class_type.PadLen is None)
    assert (class_type.MctpVdmCode == 0)
    assert (class_type.MessageCode == 0x7F)
    assert (class_type.TargetBus == 0)
    assert (class_type.TargetDevice == 0)
    assert (class_type.TargetFunction == 0)
    assert (class_type.VendorID == 0x1AB4)
    assert (class_type.MctpHeader is None)
    return
