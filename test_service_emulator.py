# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Example DSP0280 Test Service.
##############################################################################

import socket
from scapy.all import *  # pylint: disable=unused-import, unused-wildcard-import
from ptti.dmtf import *  # pylint: disable=unused-import, unused-wildcard-import

### Network parameters for client connections ###
CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155

# Additional error codes
ERROR_OEM_INVALID_PARAMETER = 0xF0
ERROR_OEM_UNSUPPORTED = 0xF1

#
# This class implements the minimum functionality for a Test Service.
# It provides valid -though not meaningful- responses for all protocol
# messages defined in DSP0280 version 1.0.
class c_TestServiceBase():
    """ Example DSP0280 Test Server Application """

    def __init__(self):
        """ c_TestServiceBase class constructor """

        self._server_socket = None
        self._client_socket = None
        self._session_connected = False
        self._session_test_client_id = 0

        return

    def __del__(self):
        """ c_TestServiceBase class destructor """

        if self._server_socket != None:
            self._server_socket.close()

        if self._client_socket != None:
            self._client_socket.close()

        return

    def _socket_recv_ex(self, socket, read_size):
        """ Custom socket read function """

        try:    # TODO Add additional error handling
            _chunk = socket.recv(read_size)
            return ((len(_chunk) > 0), _chunk)
        except:
            pass

        return (False, None)

    def log(self, message):
        """Local log function"""

        print(message)
        return

    def _Connect(self, request):
        """DSP0280 section 10.2.2 Connect message"""

        if request.SecurityParameterLength > 0:
            self._session_connected = True
            response = Connect_Response(TestClientID=0xdeadbeef)
        else:
            response = Connect_Response(ResponseCode=ERROR_OEM_INVALID_PARAMETER)

        return response

    def _Disconnect(self):
        """ DSP0280 section 10.2.3 Disconnect message """

        self._session_connected = False
        return Disconnect_Response()

    def _QueryCapabilities(self):
        """ DSP0280 section 10.2.4 Query Capabilities message """

        capabilities = [
            # Maximum Watchdog timeout in seconds
            TestServiceCapabilityEntry(CapabilityID=1, CapabilityValue=0),
            # Current Watchdog timeout in seconds
            TestServiceCapabilityEntry(CapabilityID=2, CapabilityValue=0)
        ]

        response = QueryCapabilities_Response()
        response.NumberOfCapabilitiesFields = len(capabilities)
        response.TestServiceCapabilities = capabilities
        return response

    def _QueryStatus(self, query_type):
        """ DSP0280 section 10.2.5 Query Status message """
        return QueryStatus_Response(QueryType=query_type)

    def _QuerySystemInventory(self):
        """ DSP0280 section 10.2.6 Query System Inventory """

        response =  QuerySystemInventory_Response()
        response.SystemInventory = "{ ""SchemaDefinition"": ""SystemInventory.v1_0_0"" }"
        return response

    def _ConfigureTestService(self, request):
        """ DSP0280 section 10.2.7 Configure Test Service """
        return ConfigureTestService_Response()

    def _ConfigureDeviceUnderTest(self, request):
        """ DSP0280 section 10.2.8 Configure Device Under Test"""
        return ConfigureDeviceUnderTest_Response(ResponseCode=ERROR_OEM_UNSUPPORTED)

    def _RegisterToProtocol(self, conn_id):
        """ DSP0280 section 10.2.10 Register to Protocol """
        return RegisterToProtocol_Response(DUTConnectionID=conn_id)

    def _RegisterAsyncMessageRecipient(self, conn_id):
        """DSP0280 section 10.2.11 Register Async Message Recipient """
        return RegisterAsyncMessageRecipient_Response(DUTConnectionID=conn_id)

    def _LogEvent(self, request):
        """ DSP0280 section 10.2.12 Log Event """
        return LogEvent_Response()

    def process_admin_request(self, request):
        """ Process DSP0280 Admin Messages """

        if isinstance(request, Connect_Request):
            response = self._Connect(request)
        elif isinstance(request, Disconnect_Request):
            response = self._Disconnect()
        elif isinstance(request, QueryCapabilities_Request):
            response = self._QueryCapabilities()
        elif isinstance(request, QueryStatus_Request):
            response = self._QueryStatus(request.QueryType)
        elif isinstance(request, QuerySystemInventory_Request):
            response = self._QuerySystemInventory()
        elif isinstance(request, ConfigureTestService_Request):
            response = self._ConfigureTestService(request)
        elif isinstance(request, ConfigureDeviceUnderTest_Request):
            response = self._ConfigureDeviceUnderTest(request)
        elif isinstance(request, RegisterToProtocol_Request):
            response = self._RegisterToProtocol(request.DUTConnectionID)
        elif isinstance(request, RegisterAsyncMessageRecipient_Request):
            response = self._RegisterAsyncMessageRecipient(request.DUTConnectionID)
        elif isinstance(request, LogEvent_Request):
            response = self._LogEvent(request)
        else:
            self.log("ERROR: unknown request")
            response = None

        return response

    def process_vendor_admin_request(self, request):
        """ Process DSP0280 Vendor Defined Admin Messages """

        response = VendorDefinedAdmin_Response()
        response.IANA = request.IANA
        response.ResponseCode = ERROR_OEM_UNSUPPORTED
        return response

    def proccess_test_message(self, protocol_type, request):
        """Process Test Message Requests"""
        return TestMessage_Response(ResponseCode=ERROR_OEM_UNSUPPORTED)

    def process_unknown_request(self, command_code):
        """ Process an unknown or invalid request """

        rsp_packet = Packet([command_code, 0x02])

        self.log("ERROR: Invalid protocol")
        self.log(rsp_packet.show2(dump=True))

        return rsp_packet

    def main(self, host_name, host_port):
        """ Main application """

        # Create the server socket
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.bind((host_name, host_port))
            self._server_socket.listen(1)

        except:
            self.log("ERROR: server socket creation failed")
            return (1)

        # Main application processing
        _run_main = True
        while _run_main == True:

            # Wait for connections
            (self._client_socket, address) = self._server_socket.accept()

            # Process session requests
            while 1:
                (rc, req_raw_data) = self._socket_recv_ex(self._client_socket, 255)

                if rc == True:
                    tsw_req = TestServiceWrapper(req_raw_data)
                    rsp_proto_type = tsw_req.ProtocolType

                    if tsw_req.ProtocolType == 0xFF:
                        rsp_packet = self.process_admin_request(tsw_req.payload)

                    elif tsw_req.ProtocolType == 0xF1:
                        rsp_packet = self.process_vendor_admin_request(tsw_req.payload)

                    elif 0x00 <= tsw_req.ProtocolType and tsw_req.ProtocolType <= 0x7F:
                        rsp_packet = self.proccess_test_message(
                            tsw_req.ProtocolType,
                            tsw_req.payload)

                    else:
                        rsp_packet = self.process_unknown_request(tsw_req.payload[0])

                    if rsp_packet != None:
                        tsw_rsp = TestServiceWrapper()

                        tsw_rsp.Version = 0x10
                        tsw_rsp.ProtocolType = rsp_proto_type
                        tsw_rsp.Direction = 1
                        tsw_rsp.TestClientID = tsw_req.TestClientID

                        response = tsw_rsp / rsp_packet
                        self._client_socket.sendall(raw(response))

                else:
                    # ERROR: Most likely the Test Client closed the socket.
                    self._session_connected = False

                # End the session if necessary
                if self._session_connected == False:
                    self._client_socket.close()
                    break

        # Exit application
        return (0)

    # end main()
# end class c_TestServiceBase()


""" Example Test Service (TS) entry point """
if __name__ == '__main__':

    test_service = c_TestServiceBase()
    exit(test_service.main(CONNECTION_ADDRESS, CONNECTION_PORT))
