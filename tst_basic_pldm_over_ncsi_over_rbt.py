# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  DSP0222 basic test cases.
##############################################################################

from scapy.all import show_interfaces
from testframework.fixtures_rbt import c_PldmRbtFixture
from ncsi.pldm_payload import NcsiPldm_Request
from tests.tst_ncsi import test_select_package, test_clear_initial_state
from tests.tst_pldm0_commands import *  # pylint: disable=unused-import, unused-wildcard-import
from tests.tst_pldm2_commands import *  # pylint: disable=unused-import, unused-wildcard-import


# Select a communication interface
show_interfaces()
Index = int(input("\nEnter an interface index: "))

# Initialize the RBT communications interface
try:
    testFixture = c_PldmRbtFixture(Index)
except:
    print("ERROR: failed to initialize fixture")
    exit(1)

# Initialize up NC-SI interface
testFixture.PackageID = 3

try:
    test_select_package(testFixture, testFixture.physicalTransportHeader)
except: pass
"""
except Exception as Ex:
    testFixture.logMessage(Ex)
    testFixture
    exit(1)
"""

try:
    test_clear_initial_state(testFixture, testFixture.physicalTransportHeader)
except: pass
"""
except Exception as Ex:
    testFixture.logMessage(Ex)
    exit(2)
"""

# Initialize headers
Headers = testFixture.physicalTransportHeader / testFixture.get_ncsi_header()
Headers = Headers / NcsiPldm_Request()

# PLDM type 0 commands
test_GetTID(testFixture, Headers)

test_GetPldmVersion(testFixture, Headers)

test_GetPldmTypes(testFixture, Headers)

try: test_GetPldmCommands(testFixture, Headers)
except: testFixture.logMessage("INFO: Expected error")

try: test_SelectPLDMVersion(testFixture, Headers)
except: testFixture.logMessage("INFO: Expected error")

testFixture.commObject.Close()
exit(0)
