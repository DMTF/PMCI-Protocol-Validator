##############################################################################
#  File Abstract:
#  NC-SI over RBT test fixtures.
##############################################################################

from testframework.intel_pa_rbt import RbtMedium
from ncsi.rbt import RBT
from ncsi.dmtf import NCSI_HEADER


class c_RbtFixtureBase(object):
    """RBT base test fixture class"""

    IID = 1
    PackageID = 0
    ChannelID = 0

    def get_ncsi_header(self, pid=None, cid=None, iid=None):
        header = NCSI_HEADER()

        if pid is not None:
            header.PackageID = pid
        else:
            header.PackageID = self.PackageID

        if cid is not None:
            header.ChannelID = cid
        else:
            header.ChannelID = self.ChannelID

        if iid is not None:
            header.IID = iid
        else:
            header.IID = self.IID

        self.IID += 1
        if self.IID < 0 or self.IID > 20:
            self.IID = 1

        return header

    def VerifyCommonFields(self, rsp_pkt, req_pkt):
        """Verify common NC-SI header fields"""
        return

    def logMessage(self, msg_str):
        print(msg_str)
        return

    def showPacket(self, packet):
        packet.show2()
        return


class c_RbtFixture(c_RbtFixtureBase):
    """RBT test fixture class"""

    def __init__(self, deviceIndex):
        self.commObject = RbtMedium(deviceIndex)
        self.physicalTransportHeader = RBT(SA="ff:ff:ff:ff:ff:ff")
        return

    def __del__(self):
        if self.commObject is not None:
            self.commObject._close()
        return


class c_PldmRbtFixture(c_RbtFixture):
    """PLDM Over RBT test fixture class"""

    def __init__(self, deviceIndex):
        super().__init__(deviceIndex)
        self.InstanceID = 1
        return

    def __del__(self):
        super().__del__()
        return

    def getNextInstanceID(self):
        self.InstanceID += 1

        if self.InstanceID > 10:
            self.InstanceID = 0

        return self.InstanceID
