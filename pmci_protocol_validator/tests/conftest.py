# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.mdimport pytest

import pytest

from pmci_protocol_validator.framework.fixture_ptti import PTTI_fixture
from pmci_protocol_validator.ptti.lib.lib_dsp0280 import *

CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155

framework_context = None

@pytest.fixture()
def context():
    return framework_context


@pytest.fixture(scope="session")
def setup():
    global framework_context

    # Set up test session
    try:
        # Create the Test Framework Context
        framework_context = PTTI_fixture(CONNECTION_ADDRESS, CONNECTION_PORT)

        # Connect to Test Service
        _security_parameter = b'\x31\x32\x33\x34\x35\x36'

        _rc, _client_id = ptti_connect(framework_context, _security_parameter)
        assert _rc == True, "ERROR: Connect failed."

        framework_context.test_client_id = _client_id

    except Exception as _exception_info:
        pytest.exit(f"ERROR: Critical setup failure: {str(_exception_info)}")

    # Execute test suite
    yield "setup"

    # Disconnect from Test Service
    _rc = ptti_disconnect(framework_context, framework_context.test_client_id)

    # Cleanup the Test Framework Context
    framework_context.commObject.close()
    return
