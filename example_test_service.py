##############################################################################
#  File Abstract:
#  Example DSP0280 Test Service.
##############################################################################

### Select a Test Service class ###
from  test_service.ts_service import c_TestServiceBase

### Network parameters for client connections ###
CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155

### Start the test service app ###
test_service = c_TestServiceBase()
exit_code = test_service.main(CONNECTION_ADDRESS, CONNECTION_PORT)
exit(exit_code)
