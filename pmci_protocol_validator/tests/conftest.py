# Copyright Notice:
# Copyright 2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
PyTest session configuration

File : conftest.py

Brief : PyTest session configuration
"""

from enum import Enum
import pytest
from pmci_protocol_validator.framework.ptti_context import PTTI_Context
from pmci_protocol_validator.ptti.classes.dsp0280_comm import PTTIMedium
from pmci_protocol_validator.ptti.lib.lib_dsp0280 import *

CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155
SECURITY_PARAMETER = b'\x31\x32\x33\x34\x35\x36'


class SetupMode(str, Enum):
    TEST_SERVICE_CONNECTED = "test_service_connected"
    COMM_CONNECTION = "comm_connection"
    TEST_SERVICE_RECONNECT = "test_service_reconnect"


class FrameworkContext(PTTI_Context):
    def __init__(self, tcp_address: str, tcp_port: int, security_parameter: bytes):
        super().__init__(tcp_address, tcp_port)

        self.security_parameter = security_parameter
        self.test_client_id = 0
        self.tsw_connected = False
        self.comm_connected = True
        self.log_packets = True

    def has_test_service_connection(self):
        return self.tsw_connected is True and self.test_client_id != 0

    def reopen_comm_connection(self):
        try:
            self.commObject.close()
        except:
            pass

        self.commObject = PTTIMedium(self.tcp_address, self.tcp_port)
        self.comm_connected = True

    def connect_to_test_service(self, retry_on_failure: bool = True):
        _rc, _client_id = ptti_connect(self, self.security_parameter)

        if _rc is False and retry_on_failure is True:
            self.reopen_comm_connection()
            _rc, _client_id = ptti_connect(self, self.security_parameter)

        assert _rc == True, "ERROR: Connect failed."
        assert _client_id != 0, "ERROR: Connect returned invalid Test Client ID."

        self.set_test_client_id(_client_id)

    def ensure_connected_to_test_service(self):
        if self.has_test_service_connection() is True:
            # Verify the cached Test Client ID still maps to a live TSW session.
            if ptti_query_status_ping(self, self.test_client_id) is True:
                return

            self.clear_test_client_id()
            self.reopen_comm_connection()

        self.connect_to_test_service()

    def set_test_client_id(self, test_client_id: int):
        self.test_client_id = test_client_id
        self.tsw_connected = True

    def clear_test_client_id(self):
        self.test_client_id = 0
        self.tsw_connected = False

    def disconnect_from_test_service(self, check_response: bool = False):
        if self.has_test_service_connection() is True:
            _rc = ptti_disconnect(self, self.test_client_id)
            self.clear_test_client_id()
            if check_response is True:
                assert _rc == True, "ERROR: Disconnect failed."

    def close(self):
        if self.comm_connected is True:
            self.commObject.close()
            self.comm_connected = False


@pytest.fixture(scope="session")
def context():
    try:
        _context = FrameworkContext(CONNECTION_ADDRESS, CONNECTION_PORT, SECURITY_PARAMETER)
    except Exception as _exception_info:
        pytest.exit(f"ERROR: Critical setup failure: {str(_exception_info)}")

    try:
        yield _context
    finally:
        _context.disconnect_from_test_service()
        _context.close()


@pytest.fixture()
def setup(request, context):
    _setup_mode = SetupMode(getattr(request, "param", SetupMode.TEST_SERVICE_CONNECTED))

    # Set up test session
    try:
        if _setup_mode == SetupMode.TEST_SERVICE_CONNECTED:
            # Reuse an existing Test Service session when available.
            context.ensure_connected_to_test_service()
        elif _setup_mode == SetupMode.COMM_CONNECTION:
            context.disconnect_from_test_service(check_response=True)
        elif _setup_mode == SetupMode.TEST_SERVICE_RECONNECT:
            context.disconnect_from_test_service(check_response=True)
            context.connect_to_test_service()
        else:
            raise ValueError(f"Unsupported setup mode: {_setup_mode}")

    except Exception as _exception_info:
        context.close()
        pytest.exit(f"ERROR: Critical setup failure: {str(_exception_info)}")

    # Execute test suite
    yield _setup_mode

    return
