##############################################################################
#  File Abstract:
#  Test the RBT() class structure
##############################################################################

import pytest
from ncsi.rbt import RBT


@pytest.mark.parametrize("class_type", RBT())
def test_RBT_class(class_type):
    "Verify RBT class structure and initialization"

    assert (len(class_type.fields_desc) == 3), "Incorrect number of fields"

    assert (class_type.DA is not None)
    assert (class_type.SA is not None)
    assert (class_type.EtherType == 0x88F8)
