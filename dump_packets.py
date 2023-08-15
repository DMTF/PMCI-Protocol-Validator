##############################################################################
#  File Abstract:
#  Display the specified request and response packets.
##############################################################################

import argparse

from dump.dump_ncsi_packets import dump_packets as dump_ncsi
from dump.dump_ncsi_pldm_type0_packets import dump_packets as dump_ncsi_pldm0
from dump.dump_ncsi_pldm_type2_packets import dump_packets as dump_ncsi_pldm2
from dump.dump_pldm_type0_packets import dump_packets as dump_pldm0
from dump.dump_pldm_type2_packets import dump_packets as dump_pldm2
from dump.dump_pldm_type5_packets import dump_packets as dump_pldm5
from dump.dump_pldm_type6_packets import dump_packets as dump_pldm6

# Configure the command line parser
Parser = argparse.ArgumentParser(description="Dumps packet structures")

Parser.add_argument("-all", "--all",  action='store_true',
                    help="Show all packets")

Parser.add_argument("-ncsi", "--ncsi",  action='store_true',
                    help="Show NC-SI packets")
Parser.add_argument("-ncsi_pldm0", "--ncsi_pldm0",  action='store_true',
                    help="Show PLDM Type 0 over NC-SI packets")
Parser.add_argument("-ncsi_pldm2", "--ncsi_pldm2",  action='store_true',
                    help="Show PLDM Type 2 over NC-SI packets")
Parser.add_argument("-pldm0", "--pldm0",  action='store_true',
                    help="Show PLDM Type 0 packets")
Parser.add_argument("-pldm2", "--pldm2",  action='store_true',
                    help="Show PLDM Type 2 packets")
Parser.add_argument("-pldm5", "--pldm5",  action='store_true',
                    help="Show PLDM Type 5 packets")
Parser.add_argument("-pldm6", "--pldm6",  action='store_true',
                    help="Show PLDM Type 6 packets")

# Parse command line and perform operations
Args = Parser.parse_args()

if Args.all is True:
    Args.pldm0 = True
    Args.pldm2 = True
    Args.pldm5 = True
    Args.pldm6 = True
    Args.nsci = True
    Args.ncsi_pldm0 = True
    Args.ncsi_pldm2 = True

if Args.pldm0 is True:
    dump_pldm0()

if Args.pldm2 is True:
    dump_pldm2()

if Args.pldm5 is True:
    dump_pldm5()

if Args.pldm6 is True:
    dump_pldm6()

if Args.ncsi is True:
    dump_ncsi()

if Args.ncsi_pldm0 is True:
    dump_ncsi_pldm0()

if Args.ncsi_pldm2 is True:
    dump_ncsi_pldm2()
