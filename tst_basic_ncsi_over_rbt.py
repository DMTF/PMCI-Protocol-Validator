##############################################################################
#  File Abstract:
#  DSP0222 basic test cases.
##############################################################################

from scapy.all import show_interfaces
from testframework.fixtures_rbt import c_RbtFixture
from tests.tst_ncsi import *  # pylint: disable=unused-import, unused-wildcard-import

# Select a communication interface
show_interfaces()
Index = int(input("\nEnter an interface index: "))

# Initialize the RBT communications interface
try:
    testFixture = c_RbtFixture(Index)
except:
    print("ERROR: failed to initialize fixture")
    exit(1)

# Execute tests
lowerLayerHeaders = testFixture.physicalTransportHeader

testFixture.PackageID = 3
try: test_select_package(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_clear_initial_state(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_get_asic_temperature(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_get_ambient_temperature(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_get_transceiver_temperature(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_get_channel_configuration(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_get_module_management_data(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_enable_channel(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_get_version_id(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_get_capabilities(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_get_parameters(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_disable_channel(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_reset_channel(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

try: test_deselect_package(testFixture, lowerLayerHeaders)
except Exception as Ex: testFixture.logMessage(Ex)

# Cleanup and exit
testFixture.commObject.Close()
exit(0)
