# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
DSP0280 communications binding

File : dsp0280_comm.py

Brief : Defines a socket based communications interface to DSP0280 Test Services.
"""

import socket
import threading

from scapy.all import raw
from pmci_protocol_validator.framework.medium import CommMedium
from pmci_protocol_validator.ptti.classes.dsp0280 import TestServiceWrapper


class PTTIMedium(CommMedium):
    """ Connection to Test Server supporting DSP0280 specification """

    DEFAULT_TIMEOUT = 2  # in seconds

    def __init__(self, TargetIP, TargetPort):
        """ Initialize PTTIMedium class and underlying base class """

        # Initialize the base class
        super().__init__(self.DEFAULT_TIMEOUT)

        # Open the network connection
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((TargetIP, TargetPort))

        # Start up packet receiver thread
        self.__TerminateReadThread = False
        self.__readThread = threading.Thread(target=self.__readFn)
        self.__readThread.start()

        return

    def _close(self):
        """ Override base class method """

        self.__TerminateReadThread = True

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

        if self.__TerminateReadThread is False:
            self._socket.sendall(raw(payload))

        return self.ERROR_SUCCESS

    def _packetize(self, rawData):
        """ Override base class method """

        return TestServiceWrapper(rawData)

    def __readFn(self):
        """ private: Thread to process received messages """

        while self.__TerminateReadThread is False:
            try:
                # Read packet header
                _chunk = self._socket.recv(16)

                if len(_chunk) >= 16:

                    # Read the remainder of the packet
                    _len = int.from_bytes(_chunk[8:10], byteorder='little')
                    _chunk = _chunk + self._socket.recv(_len, socket.MSG_WAITALL)

                    # Add packet to RX queue
                    self._add_read_packet(_chunk)
            except:
                pass

        self._socket.close()
        return
