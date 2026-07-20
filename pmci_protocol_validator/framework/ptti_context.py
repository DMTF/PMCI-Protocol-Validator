# Copyright Notice:
# Copyright 2024-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

"""
Class defining PTTI test framework context

File : ptti_context.py

Brief : Class defining PTTI test framework context.
"""

from pmci_protocol_validator.framework.context import FwkContext
from pmci_protocol_validator.framework.medium import CommMedium


class PTTI_Context(FwkContext):
    """ PTTI test fixture """

    def __init__(self, comm_obj: CommMedium, log_pkts:bool = False):
        """ c_PTTI_fixture class constructor """

        super().__init__(comm_obj, log_pkts)

        self.test_client_id = 0
        return
