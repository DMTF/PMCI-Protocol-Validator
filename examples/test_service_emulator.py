# Copyright Notice:
# Copyright 2024-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Example DSP0280 Test Service

File : test_service_emulator.py

Brief : Example DSP0280 Test Service.
"""

import socket
from scapy.packet import Packet
from pmci_protocol_validator.ptti.dsp0280 import *
from pmci_protocol_validator.pldm.dsp0240_base import PLDM_HEADER
from pmci_protocol_validator.pldm.dsp0240 import GetTID_Request, GetTID_Response


### Network parameters for client connections ###
CONNECTION_ADDRESS = 'localhost'
CONNECTION_PORT = 49155
DMTF_VENDOR_ID = 0x1AB4


class TestServiceBase:
    """
    Example DSP0280 Test Server Application.
    This class implements the minimum functionality for a Test Service.
    It provides valid -though not meaningful- responses for all protocol
    messages defined in DSP0280 version 1.1.0.
   """

    SYSTEM_INVENTORY_STR = " \
        {\"SchemaDefinition\": \"SystemInventory.v1_0_0\", \
        \"ControlPlane\": { \
        \"Manufacturer\": \"Contoso\", \
        \"Model\": \"ContoBMC\", \
        \"FirmwareVersions\": [{\"Name\": \"name1\", \"Version\": \"version1\"}], \
        \"Interfaces\": [ \
        {\"Interface\": \"I2C\", \"MessageInitiationSupport\": \"ControlPlaneRequestorOnly\"}]}, \
        \"Devices\": [ \
        {\"Manufacturer\": \"ContosoSensors\", \
        \"Location\": \"motherboard\", \
        \"GeneralDeviceIdentifier\": 2, \
        \"Interfaces\": [ \
        {\"Interface\": \"I2C\", \
        \"InterfaceIdentifier\": 12, \
        \"ParentDeviceIdentifier\": 0, \
        \"ProtocolSupport\": [ \
        {\"Protocol\": \"MCTP\", \
        \"Types\": [ \
        {\"Type\": 0, \"Name\": \"MCTP Base\", \"Versions\": [\"1.2.0\"]}, \
        {\"Type\": 1, \"Name\": \"PLDM over MCTP\", \"Versions\": [\"1.0.0\"]}, \
        {\"Type\": 2, \"Name\": \"NC-SI over MCTP\", \"Versions\": [\"1.0.0\"]}]}, \
        {\"Protocol\": \"PLDM\", \
        \"Types\": [ \
        {\"Type\": 0, \"Name\": \"PLDM Base\", \"Versions\": [\"1.0.0\"]}, \
        {\"Type\": 2, \"Name\": \"PLDM for Platform Monitoring and Control\", \"Versions\": [\"1.2.0\"]}]}]} ]}]}"

    def __init__(self) -> None:
        """ c_TestServiceBase constructor """

        self._server_socket = None
        self._client_socket = None
        self._session_connected = False
        self._session_test_client_id = 0

        self._capabilities = {
            1: 60,
            2: 60,
            3: 1500
        }

        return

    def __del__(self) -> None:
        """ c_TestServiceBase destructor """

        if self._server_socket != None:
            self._server_socket.close()

        if self._client_socket != None:
            self._client_socket.close()

        return

    def _socket_recv_msg(self) -> tuple[bool, bytes|None]:
        """ Method to receive a full PTTI message from the Test Client """

        try:
            # Read packet header
            _chunk = self._client_socket.recv(16)
            if len(_chunk) >= 16:

                # Read the remainder of the packet
                _len = int.from_bytes(_chunk[8:9], byteorder='little')
                _chunk = _chunk + self._client_socket.recv(_len)

                # Return message
                return ((len(_chunk) > 0), _chunk)

        except:
            pass

        return (False, None)

    def _log(self, message: str):
        """ Local message logging function """

        print(message)
        return

    def _verify_tsw(self, tsw: TestServiceWrapper) -> int:
        """ Verify the fields in the Test Service Wrapper """

        if tsw.Version != VERSION_COMPLIANCE:
            return 0x08

        elif tsw.Direction != 0:
            return 0x11

        elif tsw.Reserved_0 != 0 or \
                tsw.Reserved_1 != 0 or \
                tsw.Reserved_2 != 0:
            return 0x0B

        return 0x00

    def _connect(self, request: Connect_Request) -> Connect_Response:
        """ Process Connect message """

        if request.SecurityParameterLength > 0:
            self._session_connected = True
            self._session_test_client_id = 0xdeadbeef
            response = Connect_Response(TestClientID=self._session_test_client_id)
        else:
            response = Connect_Response(ResponseCode=0x0B)

        return response

    def _disconnect(self) -> Disconnect_Response:
        """ Process Disconnect message """

        self._session_connected = False
        return Disconnect_Response()

    def _query_admin_messages(self) -> QueryAdminMessages_Response:
        supported_admin_messages = bytearray(32)
        for command_code in [0x00, 0x01, 0x02, 0x10, 0x11, 0x12, 0x13, 0x20, 0x21, 0x22, 0x23, 0x30]:
            supported_admin_messages[command_code // 8] |= 1 << (command_code % 8)

        return QueryAdminMessages_Response(SupportedAdminMessages=bytes(supported_admin_messages))

    def _query_capabilities(self) -> QueryCapabilities_Response:
        """ Process Query Capabilities message """

        capabilities = []

        for _key, _value in self._capabilities.items():
            item = TestServiceCapabilityEntry(CapabilityID=_key, CapabilityValue=_value)
            capabilities.append(item)

        response = QueryCapabilities_Response()
        response.NumberOfCapabilitiesFields = len(capabilities)
        response.TestServiceCapabilities = capabilities
        return response

    def _query_status(self, query_type) -> QueryStatus_Response:
        """ Process Query Status message """
        return QueryStatus_Response(QueryType=query_type)

    def _query_system_inventory(self) -> QuerySystemInventory_Response:
        """ Process Query System Inventory message """

        response = QuerySystemInventory_Response()
        response.SystemInventory = self.SYSTEM_INVENTORY_STR
        return response

    def _query_partial_system_inventory(self, fragment_handle: int) -> QueryPartialSystemInventory_Response:
        """ Process Query PartialSystem Inventory message """

        response = QueryPartialSystemInventory_Response()
        response[QueryPartialSystemInventory_Response].NextFragmentHandle = 0
        response[QueryPartialSystemInventory_Response].FragmentLength = len(self.SYSTEM_INVENTORY_STR)
        response[QueryPartialSystemInventory_Response].SystemInventory = self.SYSTEM_INVENTORY_STR
        return response

    def _configure_test_service(self, request: ConfigureTestService_Request) -> ConfigureTestService_Response:
        """ Process Configure Test Service message """

        _response_code = 0

        for _entry in request.TestServiceCapabilities:
            try:
                if self._capabilities[_entry.CapabilityID]:
                    self._capabilities[_entry.CapabilityID] = _entry.CapabilityValue
            except:
                _response_code = 0x0B
                break

        return ConfigureTestService_Response(ResponseCode=_response_code)

    def _configure_device_under_test(self, request: ConfigureDeviceUnderTest_Request) -> ConfigureDeviceUnderTest_Response:
        """ Process Configure Device Under Test message """

        if request.TargetIdentifier not in (2, 12):
            return ConfigureDeviceUnderTest_Response(
                ResponseCode=0x90,
                DUTConnectionID=0,
                IdentifierCount=0,
                IdentifierList=[]
            )

        response = ConfigureDeviceUnderTest_Response()
        response[ConfigureDeviceUnderTest_Response].DUTConnectionID = 0xabcdef
        response[ConfigureDeviceUnderTest_Response].IdentifierCount = 0

        return response

    def _register_to_protocol(self, conn_id: int) -> RegisterToProtocol_Response:
        """ Process Register to Protocol message """
        return RegisterToProtocol_Response(DUTConnectionID=conn_id)

    def _register_async_message_recipient(self, conn_id: int) -> RegisterAsyncMessageRecipient_Response:
        """ Process Register Async Message Recipient message """
        return RegisterAsyncMessageRecipient_Response(DUTConnectionID=conn_id)

    def _log_event(self, request: LogEvent_Request) -> LogEvent_Response:
        """ Process Log Event message """
        return LogEvent_Response()

    def process_admin_request(self, request: Packet) -> Packet|None:
        """ Process DSP0280 Admin Messages """

        if isinstance(request, Connect_Request):
            response = self._connect(request)
        elif isinstance(request, Disconnect_Request):
            response = self._disconnect()
        elif isinstance(request, QueryAdminMessages_Request):
            response = self._query_admin_messages()
        elif isinstance(request, QueryCapabilities_Request):
            response = self._query_capabilities()
        elif isinstance(request, QueryStatus_Request):
            response = self._query_status(request.QueryType)
        elif isinstance(request, QuerySystemInventory_Request):
            response = self._query_system_inventory()
        elif isinstance(request, QueryPartialSystemInventory_Request):
            fragment_handle = request[QueryPartialSystemInventory_Request].FragmentHandle
            response = self._query_partial_system_inventory(fragment_handle)
        elif isinstance(request, ConfigureTestService_Request):
            response = self._configure_test_service(request)
        elif isinstance(request, ConfigureDeviceUnderTest_Request):
            response = self._configure_device_under_test(request)
        elif isinstance(request, RegisterToProtocol_Request):
            response = self._register_to_protocol(request.DUTConnectionID)
        elif isinstance(request, RegisterAsyncMessageRecipient_Request):
            response = self._register_async_message_recipient(request.DUTConnectionID)
        elif isinstance(request, LogEvent_Request):
            response = self._log_event(request)
        else:
            self._log("ERROR: unknown request")
            response = None

        return response

    def process_vendor_admin_request(self, request: VendorDefinedAdmin_Request) -> VendorDefinedAdmin_Response:
        """ Process DSP0280 Vendor Defined Admin Messages """

        response = VendorDefinedAdmin_Response()
        response.IANA = request.IANA
        response.ResponseCode = 0x0D if request.IANA != DMTF_VENDOR_ID else 0
        return response

    def proccess_test_message(self, protocol_type: int, request: TestMessage_Request) -> TestMessage_Response:
        """ Process Test Message Requests """

        if protocol_type == 0x01 and isinstance(request, TestMessage_Request):
            pldm_header = request.payload

            if (
                isinstance(pldm_header, PLDM_HEADER)
                and pldm_header.Request == 1
                and pldm_header.PldmType == 0
                and pldm_header.CommandCode == GetTID_Request.CommandValue
            ):
                # Minimal PLDM GetTID stub response.
                response = TestMessage_Response(
                    ResponseCode=0,
                    DUTConnectionID=request.DUTConnectionID,
                    ElapsedTime=0
                )

                response = response / PLDM_HEADER(PldmType=0x00) / GetTID_Response(CompletionCode=0, TID=0x01)
                response[PLDM_HEADER].InstanceID = pldm_header.InstanceID
                response[PLDM_HEADER].PldmType = pldm_header.PldmType
                return response

        return TestMessage_Response(ResponseCode=0x0D)

    def process_unknown_request(self, command_code: int) -> Packet:
        """ Process an unknown or invalid request """

        rsp_packet = Packet(bytearray([command_code, 0x02]))

        self._log("ERROR: Invalid protocol")
        self._log(rsp_packet.show2(dump=True))

        return rsp_packet

    def main(self, host_name: str, host_port: int) -> int:
        """ Main application """

        # Create the server socket
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.bind((host_name, host_port))
            self._server_socket.listen(1)

        except:
            self._log("ERROR: server socket creation failed")
            return (1)

        # Main application processing
        _run_main = True
        while _run_main == True:

            # Wait for connections
            (self._client_socket, address) = self._server_socket.accept()

            # Process session requests
            while 1:
                (rc, req_raw_data) = self._socket_recv_msg()

                if rc == True:
                    tsw_req = TestServiceWrapper(req_raw_data)
                    rsp_proto_type = tsw_req.ProtocolType

                    rc = self._verify_tsw(tsw_req)

                    if rc != 0:
                        cmd_code = bytes(tsw_req[TestServiceWrapper].payload)[0]
                        rsp_packet = Packet(bytearray([cmd_code, rc]))


                    elif tsw_req.ProtocolType == 0xFF:
                        rsp_packet = self.process_admin_request(tsw_req.payload)

                    elif tsw_req.ProtocolType == 0xF1:
                        rsp_packet = self.process_vendor_admin_request(tsw_req.payload)

                    elif 0x00 <= tsw_req.ProtocolType and tsw_req.ProtocolType <= 0x7F:
                        rsp_packet = self.proccess_test_message(
                            tsw_req.ProtocolType,
                            tsw_req.payload)
                    else:
                        cmd_code = bytes(tsw_req[TestServiceWrapper].payload)[0]
                        rsp_packet = self.process_unknown_request(cmd_code)

                    if rsp_packet != None:
                        tsw_rsp = TestServiceWrapper()

                        tsw_rsp.ProtocolType = rsp_proto_type
                        tsw_rsp.Direction = 1
                        tsw_rsp.TestClientID = self._session_test_client_id

                        response = tsw_rsp / rsp_packet
                        self._client_socket.sendall(raw(response))

                        # If Disconnect invalidate the test client id after response being sent.
                        if isinstance(rsp_packet, Disconnect_Response):
                            self._session_test_client_id = 0
                else:
                    # ERROR: Most likely the Test Client closed the socket.
                    self._client_socket.close()
                    break

        # Exit application
        return (0)

    # end main()
# end class TestServiceBase()


""" Example Test Service (TS) entry point """
if __name__ == '__main__':

    test_service = TestServiceBase()
    exit(test_service.main(CONNECTION_ADDRESS, CONNECTION_PORT))
