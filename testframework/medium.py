# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Base class to represent physical medium to send and receive manageability
#  packets
##############################################################################

import time
import queue
from scapy.all import wrpcap


def GetCurrMS():
    """Get number of mseconds since epoc """

    return int(round(time.time() * 1000))


# Time application started up
AppStartTime = GetCurrMS()


class physicalMedium:
    """Base class for interface to send and receive manageability packets"""

    # Return codes for Read() function
    ERROR_SUCCESS = 0
    ERROR_READ_TIMEOUT = 1
    ERROR_WRITE_FAILED = 2
    ERROR_INVALID_MEDIUM = 3
    ERROR_UNKNOWN_ERROR = 4

    ErrorStrings = {
        ERROR_SUCCESS:        "SUCCESS",
        ERROR_READ_TIMEOUT:   "Timeout - a timeout of some kind ocurred",
        ERROR_WRITE_FAILED:   "Write failed",
        ERROR_INVALID_MEDIUM: "Invalid Medium - The PDI was either invalid, or has not been initialized",
        ERROR_UNKNOWN_ERROR:  "Unknown error"
    }

    @staticmethod
    def ResponseToStr(resp):
        """Returns an error description for the specified error code"""

        try:
            return physicalMedium.ErrorStrings[resp]
        except:
            return "Unknown"

    def __init__(self, instance, timeout):
        self.__inst = instance
        self.__received = queue.Queue()
        self._timeout = timeout
        self.__pcapFile = None
        self.__firstFileWrite = True
        self.__readThread = None

    def __del__(self):
        self.Close()

    def SetPcapFile(self, fileName=None):
        """specify a pcap file to save packets for tracability """
        self.__pcapFile = fileName
        self.__firstFileWrite = True

    def __writeToPcap(self, packet):
        """Store packet to PCAP file """

        if self.__pcapFile is not None:
            if self.__firstFileWrite is True:
                appendFlag = False
                self.__firstFileWrite = False

            else:
                appendFlag = True

            wrpcap(self.__pcapFile, packet, append=appendFlag)

    def Close(self):
        """Clean up before exiting"""

        self.__inst._close()

    def Write(self, payload):
        """Write packet to the underlying physical medium """

        _error_code = self.__inst._write(payload)
        writeTime = GetCurrMS() - AppStartTime

        self.__writeToPcap(payload)

        try:
            payload.SendTimeStamp = writeTime
        except:
            pass

        return _error_code

    def Read(self, timeoutOverride=None):
        """
        Called by framework to read data from a rx queue returns a tuple of
        READ_STATUS, READ_DATA where READ_STATUS is defined in physicalMedium
        and READ_DATA will be a scapy packet in medium specific packet format.

        Some commands may want a longer timeout (such as GetSystemInventory)
        so we have a way to change the timeout value.
        """
        try:
            status = self.__inst._checkStatus()
            if status is not None:
                return (status, None)

            if timeoutOverride is None:
                timeoutValue = self._timeout
            else:
                timeoutValue = timeoutOverride

            timeStamp, rawData = self.__received.get(block=True, timeout=timeoutValue)

            try:
                retPkt = self.__inst._packetize(rawData)
            except Exception as Ex:
                print("Error Packetizing received Data " + str(Ex))

            try:
                retPkt.ReceiveTimeStamp = timeStamp

            except Exception as ex:
                print("*********** " + str(ex))

            return (self.ERROR_SUCCESS, retPkt)

        except queue.Empty:
            return (self.ERROR_READ_TIMEOUT, None)

        except Exception as Ex:
            print(str(Ex))
            return (self.ERROR_UNKNOWN_ERROR, None)

    def _addReadPacket(self, arrivedPkt):
        """Save data in receive queue """

        assert (arrivedPkt is not None), "Received NULL packet"

        ReceiveTimeStamp = (GetCurrMS() - AppStartTime)
        self.__received.put_nowait((ReceiveTimeStamp, arrivedPkt))
