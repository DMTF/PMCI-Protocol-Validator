# Copyright Notice:
# Copyright 2025 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Verify xxx classes
########################################################

import pytest
from scapy.fields import *
from pmci_protocol_validator.mctp.classes.dsp283 import USB


@pytest.mark.parametrize("class_type", USB())
def test_mctp_usb_header(class_type):
    """Verify MCTP USB header structure """

    # Verify the class contains the required number of fields
    assert (len(class_type.fields_desc) == 4)

    # Verify the fields data type
    assert (isinstance(class_type.fields_desc[0], XShortField))  # DMTF_ID
    assert (isinstance(class_type.fields_desc[1], XByteField))   # RSVD
    assert (isinstance(class_type.fields_desc[2], ByteField))    # Length
    assert (isinstance(class_type.fields_desc[3], PacketField))  # MctpHeader

    # Verify the class field names and initial values
    assert (class_type.DMTF_ID == 0x1AB4)
    assert (class_type.RSVD == 0)
    assert (class_type.Length is None)
    assert (class_type.MctpHeader is None)
    return
