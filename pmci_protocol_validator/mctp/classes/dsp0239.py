# Copyright Notice:
# Copyright 2024-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
MCTP Codes & ID definitions from DSP0239 v1.11.1

File : dsp0239.py

Brief : MCTP Codes & ID definitions from DSP0239 v1.11.1
"""

""" DSP0239 MCTP Message Types """
MCTP_MESSAGE_TYPES = {
    0x00: "MCTP Control",
    0x01: "Platform Level Data Model (PLDM)",
    0x02: "NC-SI over MCTP",
    0x03: "Ethernet over MCTP",
    0x04: "NVM Express Management Messages over MCTP",
    0x05: "SPDM over MCTP",
    0x06: "Secured Messages",
    0x07: "CXL FM API over MCTP",
    0x08: "CXL CCI over MCTP",
    0x09: "PCIe-MI over MCTP",
    # All other values are reserved
    0x7E: "Vendor Defined - PCI",
    0x7F: "Vendor Defined - IANA"
}

""" DSP0239 MCTP Physical Medium Identifiers """
MCTP_PHYSICAL_MEDIUM_IDS = {
    0x00: "Unspecified",
    0x01: "SMBus 2.0 100 kHz compatible",
    0x02: "SMBus 2.0 or I2C 100 kHz compatible",
    0x03: "I2C 100 kHz compatible (Standard-mode)",
    0x04: "SMBus 3.0 or I2C 400 kHz compatible (Fast-mode)",
    0x05: "SMBus 3.0 or I2C 1 MHz compatible (Fast-mode Plus)",
    0x06: "I2C 3.4 MHz compatible (High-speed mode)",
    0x07: "Reserved",
    0x08: "PCIe revision 1.1 compatible",
    0x09: "PCIe revision 2.0 compatible",
    0x0A: "PCIe revision 2.1 compatible",
    0x0B: "PCIe revision 3.x compatible",
    0x0C: "PCIe revision 4.x compatible",
    0x0D: "PCIe revision 5.x compatible or CXL 1.x / 2.x compatible",
    0x0E: "PCIe revision 6.x Non-Flit Mode compatible",
    0x0F: "PCI compatible (PCI 1.0, 2.0, 2.1, 2.2, 2.3, 3.0, PCI-X 1.0, PCI-X 2.0)",
    0x10: "USB 1.1 compatible",
    0x11: "USB 2.0 compatible",
    0x12: "USB 3.0 compatible",
    0x18: "NC-SI over RBT (A physical interface based on RMII as defined in DSP0222)",
    0x19: "Management Component Transport Protocol (MCTP) UCIe™ Transport Specification DSP0290",
    0x1A: "Management Component Transport Protocol (MCTP) PCC Transport Binding Specification",
    0x20: "KCS Legacy (Fixed Address Decoding)",
    0x21: "KCS over PCI (Base Class 0xC0 Subclass 0x01)",
    0x22: "Serial Host Legacy (Fixed Address Decoding)",
    0x23: "Serial Host over PCI (Base Class 0x07 Subclass 0x00)",
    0x24: "Asynchronous Serial (Between MCs and IMDs)",
    0x30: "I3C Basic compatible",
    0x40: "PCIe revision 6.x Flit Mode Compatible or CXL 3.X compatible",
    # All other values are reserved
}

""" DSP0239 MCTP Physical Transport Binding Identifiers """
MCTP_PHYSICAL_TRANPORT_IDS = {
    0x01: "MCTP over SMBus (DSP0237)",
    0x02: "MCTP over PCIe VDM (DSP0238)",
    0x03: "MCTP over USB (DSP0283)",
    0x04: "MCTP over KCS (DSP0254)",
    0x05: "MCTP over Serial (DSP0253)",
    0x06: "MCTP over I3C (DSP0233)",
    0x07: "MCTP over MMBI (DSP0284)",
    0x08: "MCTP over PCC (DSP0292)",
    0x09: "MCTP over UCIe (DSP0290)",
    0xFF: "Vendor defined	"
    # All other values are reserved
}
