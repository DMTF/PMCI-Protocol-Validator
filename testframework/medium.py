# Copyright Notice:
# Copyright 2023-2025 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Base class defining a common communications interface object.
##############################################################################

import time
import queue
from scapy.all import wrpcap, Packet


def GetCurrMS() -> int:
    """ Get number of milliseconds since epoc """

    return int(round(time.time() * 1000))


# Time application started up
AppStartTime = GetCurrMS()


class physicalMedium:
    """ Base class for interface to send and receive manageability packets """

    # Common class return codes
    ERROR_SUCCESS = 0
    ERROR_READ_TIMEOUT = 1
    ERROR_WRITE_FAILED = 2
    ERROR_INVALID_MEDIUM = 3
    ERROR_UNKNOWN_ERROR = 4
    LAST_ERROR_CODE = ERROR_UNKNOWN_ERROR

    def ResponseToStr(self, resp: int) -> str:
        """ public: Returns a text description of the specified error code """

        try:
            _text = self.ErrorStrings[resp]
        except:
            _text = "Unknown error code"

        return _text

    def __init__(self, timeout: int) -> None:
        """ Class constructor """

        self._timeout = timeout          # Read/write timeout in seconds
        self.__recvPktQ = queue.Queue()  # Raw received packet queue
        self.__pcapFileName = None       # Name of PCAP file if logging packets
        self.__pcapFileAppend = False    # Flags PCAP log file write operations

        self.ErrorStrings = {
            self.ERROR_SUCCESS:        "SUCCESS",
            self.ERROR_READ_TIMEOUT:   "Timeout",
            self.ERROR_WRITE_FAILED:   "Write failed",
            self.ERROR_INVALID_MEDIUM: "Invalid medium",
            self.ERROR_UNKNOWN_ERROR:  "Unknown error"
        }

        return

    def __del__(self) -> None:
        """ Class destructor """

        self.Close()
        return

    def SetPcapFile(self, fileName: str = None) -> None:
        """ public: Specify a PCAP file for packet tracing """

        self.__pcapFileName = fileName
        self.__pcapFileAppend = False
        return

    def Close(self) -> None:
        """ public: Close communications session """

        self._close()
        return

    def Write(self, payload: bytes) -> int:
        """ public: Write a raw packet to the underlying medium """

        _error_code = self._write(payload)
        self._writeToPcap(payload)
        return _error_code

    def Read(self, timeoutOverride: int = None) -> tuple:
        """ public: Read a received packet """

        try:
            _retPkt = None
            _status = self._checkStatus()

            if _status == self.ERROR_SUCCESS:
                if timeoutOverride is None:
                    _timeoutValue = self._timeout
                else:
                    _timeoutValue = timeoutOverride

                _status, _rawData, _timestamp = self._read(_timeoutValue)

                if _status == self.ERROR_SUCCESS:
                    _retPkt = self._packetize(_rawData)
                    self._writeToPcap(_rawData)
                    _retPkt.ReceiveTimeStamp = _timestamp
        except:
            _status = self.ERROR_UNKNOWN_ERROR

        return _status, _retPkt

    def _read(self, readTimeout: float) -> tuple:
        """ protected virtual: Read a raw packet data from comm interface """

        _timestamp = None
        _rawData = None

        try:
            _timestamp, _rawData = self.__recvPktQ.get(block=True, timeout=readTimeout)
            _status = self.ERROR_SUCCESS
        except queue.Empty:
            _status = self.ERROR_READ_TIMEOUT
        except:
            _status = self.ERROR_UNKNOWN_ERROR

        return _status, _rawData, _timestamp

    def _packetize(self, rawData: bytes) -> Packet:
        """ protected pure virtual: Create a packet from raw binary data """

        raise Exception("physicalMedium: ERROR: Derived class MUST implement this method")
        return Packet(rawData)

    def _addReadPacket(self, rawPkt: bytes) -> None:
        """ protected virtual: Add a raw packet to the receive queue """

        _recvTimestamp = (GetCurrMS() - AppStartTime)
        self.__recvPktQ.put_nowait((_recvTimestamp, rawPkt))

        return

    def _close(self) -> None:
        """
        protected virtual: Tear down communication session.
        Derived classes SHOULD implement this method.
        """

        return

    def _write(self, payload: bytes) -> int:
        """ protected pure virtual: Send a message """

        raise Exception("physicalMedium: ERROR: Derived class MUST implement this method")
        return self.ERROR_WRITE_FAILED

    def _checkStatus(self) -> int:
        """
        protected virtual: Check the interface status
        Derived classes SHOULD implement this method.
        """

        return self.ERROR_SUCCESS

    def _writeToPcap(self, packet: bytes) -> None:
        """ private: Log packet to PCAP trace file """

        if self.__pcapFileName is not None:
            try:
                wrpcap(self.__pcapFileName, packet, append=self.__pcapFileAppend, linktype=12)
                self.__pcapFileAppend = True
            except:
                pass

        return
