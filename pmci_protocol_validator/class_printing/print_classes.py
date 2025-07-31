# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Prints structures of classes.
##############################################################################

import argparse

from pmci_protocol_validator.class_printing.print_dsp0222 import dump_packets as dump_ncsi
from pmci_protocol_validator.class_printing.print_dsp0240_over_dsp0222 import dump_packets as dump_ncsi_pldm0
from pmci_protocol_validator.class_printing.print_dsp0248_over_dsp0222 import dump_packets as dump_ncsi_pldm2
from pmci_protocol_validator.class_printing.print_dsp0240 import dump_packets as dump_pldm0
from pmci_protocol_validator.class_printing.print_dsp0248 import dump_packets as dump_pldm2
from pmci_protocol_validator.class_printing.print_dsp0257 import dump_packets as dump_pldm4
from pmci_protocol_validator.class_printing.print_dsp0267 import dump_packets as dump_pldm5
from pmci_protocol_validator.class_printing.print_dsp0218 import dump_packets as dump_pldm6
from pmci_protocol_validator.class_printing.print_dsp0242 import dump_packets as dump_pldm7
from pmci_protocol_validator.class_printing.print_dsp0280 import show_packets as dump_ptti

# Configure the command line parser
Parser = argparse.ArgumentParser(description="Dumps packet structures")

Parser.add_argument("-all", "--all",  action='store_true',
                    help="Show all packets")
Parser.add_argument("-ncsi", "--ncsi",  action='store_true',    #bug
                    help="Show NC-SI packets")
Parser.add_argument("-ncsi_pldm0", "--ncsi_pldm0",  action='store_true',
                    help="Show PLDM Type 0 over NC-SI packets")
Parser.add_argument("-ncsi_pldm2", "--ncsi_pldm2",  action='store_true',
                    help="Show PLDM Type 2 over NC-SI packets")
Parser.add_argument("-pldm0", "--pldm0",  action='store_true',
                    help="Show PLDM Type 0 packets")
Parser.add_argument("-pldm2", "--pldm2",  action='store_true',
                    help="Show PLDM Type 2 packets")
Parser.add_argument("-pldm4", "--pldm4",  action='store_true',
                    help="Show PLDM Type 4 packets")
Parser.add_argument("-pldm5", "--pldm5",  action='store_true',
                    help="Show PLDM Type 5 packets")
Parser.add_argument("-pldm6", "--pldm6",  action='store_true',
                    help="Show PLDM Type 6 packets")
Parser.add_argument("-pldm7", "--pldm7",  action='store_true',
                    help="Show PLDM Type 7 packets")
Parser.add_argument("-ptti", "--ptti",  action='store_true',
                    help="Show PTTI packets")

# Parse command line and perform operations
Args = Parser.parse_args()

if Args.all is True:
    Args.pldm0 = True
    Args.pldm2 = True
    Args.pldm4 = True
    Args.pldm5 = True
    Args.pldm6 = True
    Args.pldm7 = True
    Args.nsci = True
    Args.ncsi_pldm0 = True
    Args.ncsi_pldm2 = True
    Args.ptti = True

if Args.pldm0 is True:
    dump_pldm0()

if Args.pldm2 is True:
    dump_pldm2()

if Args.pldm4 is True:
    dump_pldm4()

if Args.pldm5 is True:
    dump_pldm5()

if Args.pldm6 is True:
    dump_pldm6()

if Args.pldm7 is True:
    dump_pldm7()

if Args.ncsi is True:
    dump_ncsi()

if Args.ncsi_pldm0 is True:
    dump_ncsi_pldm0()

if Args.ncsi_pldm2 is True:
    dump_ncsi_pldm2()

if Args.ptti is True:
    dump_ptti()
