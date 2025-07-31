# Copyright Notice:
# Copyright 2024 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
#   https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md
##############################################################################
#  File Abstract:
#  Enumerated values for NC-SI.
##############################################################################


# Configuration flags for DSP0222 v1.1.0 Set Link Request (0x09)
NCSI_09H_CTL_AUTO_NEG           = (1 << 0)
NCSI_09H_CTL_HALF_DUPLEX        = (1 << 1)
NCSI_09H_CTL_FULL_DUPLEX        = (1 << 2)
NCSI_09H_CTL_ENABLE_PAUSE       = (1 << 3)
NCSI_09H_CTL_ASYM_PAUSE_CAP     = (1 << 4)
NCSI_09H_CTL_OEM_SETTINGS_VALID = (1 << 5)
NCSI_09H_CTL_BASE_R_FEC         = (1 << 6)
NCSI_09H_CTL_RS_FEC             = (1 << 7)
NCSI_09H_CTL_EEE                = (1 << 8)
NCSI_09H_CTL_LINK_TRAINING      = (1 << 9)
NCSI_09H_CTL_PARALLEL_DETECT    = (1 << 10)
NCSI_09H_CTL_MOD_NRZ            = (1 << 11)
NCSI_09H_CTL_MOD_PAM4           = (1 << 12)

NCSI_09H_SPD_ENB_10_MBPS        = (1 << 0)
NCSI_09H_SPD_ENB_100_MBPS       = (1 << 1)
NCSI_09H_SPD_ENB_1_GBPS         = (1 << 2)
NCSI_09H_SPD_ENB_10_GBPS        = (1 << 3)
NCSI_09H_SPD_ENB_20_GBPS        = (1 << 4)
NCSI_09H_SPD_ENB_25_GBPS        = (1 << 5)
NCSI_09H_SPD_ENB_40_GBPS        = (1 << 6)
NCSI_09H_SPD_ENB_50_GBPS        = (1 << 7)
NCSI_09H_SPD_ENB_100_GBPS       = (1 << 8)
NCSI_09H_SPD_ENB_2_5_GBPS       = (1 << 9)
NCSI_09H_SPD_ENB_5_GBPS         = (1 << 10)
NCSI_09H_SPD_ENB_200_GBPS       = (1 << 11)
NCSI_09H_SPD_ENB_400_GBPS       = (1 << 12)
NCSI_09H_SPD_ENB_800_GBPS       = (1 << 13)


# Configuration flags for DSP0222 v1.1.0 Enable Global Multicast Filter Request (0x12)
NCSI_12H_MDNSV6 = (1 << 0)
NCSI_12H_MDNSV4 = (1 << 1)
NCSI_12H_LLDP = (1 << 2)
NCSI_12H_IPV6_NEIGHBOR_SOLICITATION = (1 << 3)
NCSI_12H_IPV6_MLD = (1 << 4)
NCSI_12H_DHCPV6_MC_FROMSERVER_TO_CLIENTS_LISTENING_ON_WELL_KNOWN_UDP_PORTS = (1 << 5)
NCSI_12H_DHCPV6_RELAY_AND_SERVER_MULTICAST = (1 << 6)
NCSI_12H_IPV6_ROUTER_ADVERTISEMENT = (1 << 7)
NCSI_12H_IPV6_NEIGHBOR_ADVERTISEMENT = (1 << 8)
