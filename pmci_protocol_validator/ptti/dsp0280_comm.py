# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
DSP0280 communications binding

File : dsp0280_comm.py

Brief : Defines a socket based communications interface to DSP0280 Test Services.
"""

import socket
import threading
import ssl

from scapy.all import raw
from pmci_protocol_validator.framework.medium import CommMedium
from pmci_protocol_validator.ptti.dsp0280 import TestServiceWrapper


class PTTIMedium(CommMedium):
    """ Connection to Test Server supporting DSP0280 specification """

    DEFAULT_TIMEOUT = 2  # in seconds
    TLS_DISABLE = 0x00
    TLS_ENABLE = 0x01
    TLS_NO_HOSTNAME = 0x02

    def __init__(self, target_ip, target_port, flags: int = 0, fname_cert: str = "", hostname: str = ""):
        """ Initialize PTTIMedium class and underlying base class """

        # Initialize the base class
        super().__init__(self.DEFAULT_TIMEOUT)

        # Open the network connection
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((target_ip, target_port))

        # Configure TLS if requested
        if flags & self.TLS_ENABLE:
            _context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

            if flags & self.TLS_NO_HOSTNAME:
                _context.check_hostname = False
                _context.verify_mode = ssl.CERT_NONE
                self._socket = _context.wrap_socket(self._socket)  # Must match the certificate


            else:
                _context.check_hostname = True
                _context.load_verify_locations(fname_cert)
                self._socket = _context.wrap_socket(self._socket, server_hostname=hostname)  # Must match the certificate

        # Start up packet receiver thread
        self._terminate_read_thread = False
        self._read_thread_object = threading.Thread(target=self._read_thread)
        self._read_thread_object.start()

        return

    def _close(self):
        """ Override base class method """

        self._terminate_read_thread = True

        try:
            self._socket.shutdown(socket.SHUT_RDWR)
        except:
            pass

        try:
            self._socket.close()
        except:
            pass

        return

    def _write(self, payload):
        """ Override base class method """

        if self._terminate_read_thread is False:
            self._socket.sendall(raw(payload))

        return self.ERROR_SUCCESS

    def _packetize(self, rawData):
        """ Override base class method """

        return TestServiceWrapper(rawData)

    def __socket_recv(self, size: int) -> bytes | None:
        """Read exactly size bytes, or return None if socket closes/errors."""

        _data = bytearray()

        while len(_data) < size and self._terminate_read_thread is False:
            chunk = self._socket.recv(size - len(_data))

            if not chunk:
                return None

            _data.extend(chunk)

        if len(_data) != size:
            return None

        return bytes(_data)

    def _read_thread(self):
        """ private: Thread to process received messages """

        while self._terminate_read_thread is False:
            try:
                # Read fixed TSW header
                _msg = self.__socket_recv(16)

                # Get payload length from TSW
                _payload_len = int.from_bytes(_msg[8:10], byteorder="little")

                # Read payload if present
                if _payload_len > 0:
                    _payload = self.__socket_recv(_payload_len)
                    _msg = _msg + _payload

                # Queue complete message
                self._add_read_packet(_msg)

            except:
                if self._terminate_read_thread:
                    break

        try:
            self._socket.close()
        except:
            pass

        return
