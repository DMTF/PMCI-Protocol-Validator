# Copyright Notice:
# Copyright 2023 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Contains all of the base NC-SI protocol functionality as well as the
#  DMTF defined commands.  OEM commands are in separate files.
##############################################################################

STANDARD_RESPONSE_CODE_VALUES = {
    0x0000: "Command Completed",
    0x0001: "Command Failed",
    0x0002: "Command Unavailable",
    0x0003: "Command Unsupported",
    0x0004: "Delayed Response"
}

STANDARD_REASON_CODE_VALUES = {
    0x0000: "No Error / No Reason",
    0x0001: "Interface Initialization Required",
    0x0002: "Parameter Is Invalid, Unsupported, or Out-of-Range",
    0x0003: "Channel Not Ready",
    0x0004: "Package Not Ready",
    0x0005: "Invalid payload length",
    0x0006: "Information not available",
    0x0007: "Intervention Required",
    0x0008: "Link Command Failed-Hardware Access Error",
    0x0009: "Command Timeout",
    0x000A: "Secondary Device Not Powered",
    0x7FFF: "Unknown / Unsupported Command Type"
}

PROTOCOL_TYPE = {
    0x0: "PXE",
    0x1: "iSCSI",
    0x2: "FCoE",
    0x3: "FC",
    0x4: "NVMe"
}

FORWARD_FILTER_OUT = {
    0: "Filter out this packet type",
    1: "Forward this packet type"
}

INTERFACE = {0: "Does not have interface", 1: "Have interface"}

LINK_SETTINGS_REASON_CODES = {
    0x0901: "Set Link Host OS/ Driver Conflict",
    0x0902: "Set Link Media Conflict",
    0x0903: "Set Link Parameter Conflict",
    0x0904: "Set Link Power Mode Conflict",
    0x0905: "Set Link Speed Conflict",
    0x0906: "Link Command Failed-Hardware Access Error",
    0x0907: "Set Link Serdes Conflict",
    0x0908: "Set Link FEC Conflict",
    0x0909: "Set Link EEE Conflict",
    0x090A: "Set Link LT Conflict",
    0x090B: "Set Link Parallel Detection Conflict"
}

SUPPORTED_NOT_SUPPORTED = {
    0: "Not supported",
    1: "Supported"
}

ENABLE_DISABLE = {
    0: "Disable",
    1: "Enable"
}

ALLOWED_DISALLOWED = {
    0: "Disallow",
    1: "Allow"
}

STATS_TYPE = {
    0x01: "Ethernet",
    0x02: "iSCSI",
    0x04: "FCoE",
    0x08: "RDMA",
    0x10: "IB"
}
