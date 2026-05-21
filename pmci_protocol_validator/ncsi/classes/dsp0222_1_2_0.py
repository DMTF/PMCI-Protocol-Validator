# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link: https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/pmci_protocol_validator/LICENSE.md

"""
Scapy classes for DSP0222 v1.2.0

File : dsp0222_1_2_0.py

Brief : Additional Scapy classes for NC-SI DSP0222 v1.2.0
"""

from scapy.all import *
from scapy.fields import *
from scapy.packet import Packet

from pmci_protocol_validator.ncsi.classes.dsp0222_enums import *
from pmci_protocol_validator.ncsi.classes.dsp0222 import *

# DSP0222 - Table 260
class NCSI_UUID(Packet):
    """This is the NC-SI format, per DSP0222"""

    name = "UUID"
    UUID_NODE_LEN = 6

    fields_desc = [
        XIntField("TimeLow", 0x00000000),
        XShortField("TimeMid", 0x0000),
        XShortField("TimeHighAndVersion", 0x0000),
        XShortField("ClockSeqAndReserved", 0x0000),
        scapy.layers.l2.DestMACField(
            "Node"
        ),  # it may not be a MAC, but is 6 bytes, so this works well
    ]

    def extract_padding(self, s):
        return (
            "",
            s,
        )  # this has no padding, but may have something following it (like an array of things, so override behavior)


# DSP0222 - Table 111
class GetNcCapabilitiesSettings_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get NC Capabilities and Settings Request"""

    name = "Get NC Capabilities and Settings Request"
    CommandValue = 0x25

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 112
class GetNcCapabilitiesSettings_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get NC Capabilities and Settings Response"""

    name = "Get NC Capabilities and Settings Response"
    CommandValue = GetNcCapabilitiesSettings_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ByteField("MaxPorts", 0),
        ByteField("EnabledPorts", 0),
        ByteField("MaxPCIeEndpoints", 0),
        ByteField("EnabledPCIeEndpoints", 0),

        ByteField("MaxPFs", 0),
        ByteField("EnabledPFs", 0),
        ShortField("MaxVFs", 0),

        BitField("Reserved_0", 0, 5),
        BitEnumField("FabricsInfiniBand", 0, 1, SUPPORTED_NOT_SUPPORTED),
        BitEnumField("FabricsFibreChannel", 0, 1, SUPPORTED_NOT_SUPPORTED),
        BitEnumField("FabricsEthernet", 0, 1, SUPPORTED_NOT_SUPPORTED),

        BitField("EnabledFabricsReserved", 0, 5),
        BitEnumField("EnabledFabricsInfiniBand", 0, 1, SUPPORTED_NOT_SUPPORTED),
        BitEnumField("EnabledFabricsFibreChannel", 0, 1, SUPPORTED_NOT_SUPPORTED),
        BitEnumField("EnabledFabricsEthernet", 0, 1, SUPPORTED_NOT_SUPPORTED),

        # Other Capabilities
        BitField("Reserved_1", 0, 7),
        XBitField("MaxDataTransferSizeExp", 0x00, 5),
        BitEnumField(
            "EnabledPFsFlag",
            0,
            1,
            {
                0: "The number of Enabled PFs is fixed",
                1: "The number of Enabled PFs is programmable",
            }
        ),
        BitEnumField(
            "EnabledPCIeEndpointsFlag",
            0,
            1,
            {
                0: "The number of Enabled PCIe Endpoints is fixed",
                1: "The number of Enabled PCIe Endpoints is programmable",
            }
        ),
        BitEnumField(
            "EnabledPortsFlag",
            0,
            1,
            {
                0: "The number of Enabled Ports is fixed",
                1: "The number of Enabled Ports is programmable",
            }
        ),
        BitEnumField(
            "VFAllocation",
            0,
            1,
            {
                0: "The Max VFs field is interpreted as per port",
                1: "The Max VFs field is interpreted as per device",
            }
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 116
class SetNcConfiguration_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set NC Configuration Request"""

    name = "Set NC Configuration Request"
    CommandValue = 0x26

    fields_desc = [
        ByteField("EnablePorts", 0),
        ByteField("EnablePCIeEndpoints", 0),
        ByteField("EnablePFs", 0),
        ByteField("Reserved", 0),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 117
class SetNcConfiguration_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set NC Configuration Response"""

    name = "Set NC Configuration Response"
    CommandValue = SetNcConfiguration_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 118
class GetPfAssignment_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get PF Assignment Request"""

    name = "Get PF Assignment Request"
    CommandValue = 0x27

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 119
class GetPfAssignment_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get PF Assignment Response"""

    name = "Get PF Assignment Response"
    CommandValue = GetPfAssignment_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

### TODO Implement variable length list

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 127
class SetPfAssignment_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set PF Assignment Request"""

    name = "Set PF Assignment Request"
    CommandValue = 0x28

    fields_desc = [

### TODO Implement variable length list

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 128
class SetPfAssignment_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set PF Assignment Response"""

    name = "Set PF Assignment Response"
    CommandValue = SetPfAssignment_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 129
class GetChannelConfiguration_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Channel Configuration Request"""

    name = "Get Channel Configuration Request"
    CommandValue = 0x29

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


class ChannelConfigurationEntry(Packet):
    """Get Channel Configuration response entry"""

    name = "Get Channel Configuration Response Entry"
    fields_desc = [
        ByteField("MaxTxBW", 0),
        ByteField("MinTxBW", 0)
    ]

    def extract_padding(self, s):
        return ("", s)


# DSP0222 v1.2.0 - Table 130
class GetChannelConfiguration_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Channel Configuration Response"""

    name = "Get Channel Configuration Response"
    CommandValue = GetChannelConfiguration_Request.CommandValue | 0x80

    class Data(Packet):
        name = "Get Channel Configuration Response Data"

        fields_desc = [
            ByteEnumField(
                "FabricType",
                0,
                {
                    1: "Ethernet operation is enabled",
                    2: "Fibre Channel operation is enabled",
                    3: "InfiniBand operation is enabled",
                }
            ),
            # Media field
            BitEnumField(
                "SharedInterface",
                0,
                1,
                {
                    0: "The media is dedicated to one NC-SI channel",
                    1: "The media is shared between multiple channels",
                }
            ),
            BitField("Reserved_0", 0, 4),
            BitEnumField(
                "SFFcage",
                0,
                1,
                {
                    0: "The media does not have an SFF-style interface",
                    1: "The media has an SFF-style interface",
                }
            ),
            BitEnumField(
                "BaseT",
                0,
                1,
                {
                    0: "The media does not have a Base-T interface",
                    1: "The media has a Base-T (RJ-45 style) interface",
                }
            ),
            BitEnumField(
                "Backplane",
                0,
                1,
                {
                    0: "The media does not have a backplane interface",
                    1: "The media has a backplane interface",
                }
            ),
            ShortField("MaxMTU", 0),
            X3BytesField("Reserved_1", 0x000000),
            FieldLenField(
                "NumEnabledPartitions", None, count_of="Bandwidth", fmt="B"
            ),
            PacketListField(
                "Bandwidth",
                None,
                ChannelConfigurationEntry,
                count_from=lambda pkt: pkt.NumEnabledPartitions
            )
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            PacketField("CfgData", Data(), Data),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 129
class SetChannelConfiguration_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set Channel Configuration Request"""

    name = "Set Channel Configuration Request"
    CommandValue = 0x2A

    fields_desc = [
        ByteEnumField(
            "FabricType",
            0,
            {
                1: "Ethernet operation is enabled",
                2: "Fibre Channel operation is enabled",
                3: "InfiniBand operation is enabled",
            }
        ),
        ByteField("NumPartitions", 0),
        ShortField("MaxMTU", 0),
        PacketListField(
            "Bandwidth",
            None,
            ChannelConfigurationEntry,
            count_from=lambda pkt: pkt.NumPartitions
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 130
class SetChannelConfiguration_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set Channel Configuration Response"""

    name = "Set Channel Configuration Response"
    CommandValue = SetChannelConfiguration_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 136
class GetPartitionConfiguration_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Partition Configuration Request"""

    name = "Get Partition Configuration Request"
    CommandValue = 0x2B

    fields_desc = [
        ByteField("PartitionID", 0),
        X3BytesField("Reserved", 0x000000),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 141
class AddressTlvEntry(Packet):
    """Table 141 - Address Type-Length-Value Field Bit Definitions"""

    fields_desc = [
        FieldLenField(
            "AddressLength", None, count_of="Address", fmt="B"
        ),
        XByteEnumField(
            "AddressType",
            0,
            {
                0x00: "Reserved",
                0x01: "Ethernet MAC",
                0x02: "iSCSI Offload (Ethernet MAC)",
                0x03: "Fibre Channel World Wide Node Name",
                0x04: "Fibre Channel World Wide Port Name",
                0x05: "FCoE-FIP MAC",
                0x06: "InfiniBand Node GUID",
                0x07: "InfiniBand Port GUID",
                0x08: "InfiniBand VPort/LID",
                0xF1: "Ethernet MAC",
                0xF2: "iSCSI Offload (Ethernet MAC)",
                0xF3: "Fibre Channel World Wide Node Name",
                0xF4: "Fibre Channel World Wide Port Name",
                0xF5: "FCoE-FIP MAC",
                0xF6: "InfiniBand Node GUID",
                0xF7: "InfiniBand Port GUID",
                0xF8: "InfiniBand VPort/LID",
            }
        ),
        MACField(
            "Address",
            "00:00:00:00:00:00"
        )
    ]

    def extract_padding(self, s):
        return ("", s)


# DSP0222 v1.2.0 - Table 137
class GetPartitionConfiguration_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Partition Configuration Response"""

    name = "Get Partition Configuration Response"
    CommandValue = GetPartitionConfiguration_Request.CommandValue | 0x80

    class Data(Packet):

        fields_desc = [
            # Personality Configuration Field
            BitField("Reserved_0", 0, 1),
            BitEnumField(
                "NVMeCfg",
                0,
                1,
                {
                    0: "NVMe operation is not enabled",
                    1: "NVMe operation is enabled",
                }
            ),
            BitEnumField(
                "RDMAStatusCfg",
                0,
                1,
                {
                    0: "RDMA operation is not enabled",
                    1: "RDMA operation is enabled",
                }
            ),
            BitEnumField(
                "iSCSIOffloadStatusCfg",
                0,
                1,
                {
                    0: "iSCSI Offload operation is not enabled",
                    1: "iSCSI Offload operation is enabled",
                }
            ),
            BitEnumField(
                "InfiniBandStatusCfg",
                0,
                1,
                {
                    0: "InfiniBand operation is not enabled",
                    1: "InfiniBand operation is enabled",
                }
            ),
            BitEnumField(
                "FibreChannelOverEthernetStatusCfg",
                0,
                1,
                {
                    0: "Fibre Channel over Ethernet operation is not enabled",
                    1: "Fibre Channel over Ethernet operation is enabled",
                }
            ),
            BitEnumField(
                "FibreChannelStatusCfg",
                0,
                1,
                {
                    0: "Fibre Channel operation is not enabled",
                    1: "Fibre Channel operation is enabled",
                }
            ),
            BitEnumField(
                "EthernetStatusCfg",
                0,
                1,
                {
                    0: "Ethernet operation is not enabled",
                    1: "Ethernet operation is enabled",
                }
            ),

            # Personality Support
            BitField("Reserved_1", 0, 1),
            BitEnumField(
                "NVMeSpt",
                0,
                1,
                {
                    0: "NVMe operation is not supported",
                    1: "NVMe operation is supported",
                }
            ),
            BitEnumField(
                "RDMAStatusSpt",
                0,
                1,
                {
                    0: "RDMA operation is not supported",
                    1: "RDMA operation is supported",
                }
            ),
            BitEnumField(
                "iSCSIOffloadStatusSpt",
                0,
                1,
                {
                    0: "iSCSI Offload operation is not supported",
                    1: "iSCSI Offload operation is supported",
                }
            ),
            BitEnumField(
                "InfiniBandStatusSpt",
                0,
                1,
                {
                    0: "InfiniBand operation is not supported",
                    1: "InfiniBand operation is supported",
                }
            ),
            BitEnumField(
                "FibreChannelOverEthernetStatusSpt",
                0,
                1,
                {
                    0: "Fibre Channel over Ethernet operation is not supported",
                    1: "Fibre Channel over Ethernet operation is supported",
                }
            ),
            BitEnumField(
                "FibreChannelStatusSpt",
                0,
                1,
                {
                    0: "Fibre Channel operation is not supported",
                    1: "Fibre Channel operation is supported",
                }
            ),
            BitEnumField(
                "EthernetStatusSpt",
                0,
                1,
                {
                    0: "Ethernet operation is not supported",
                    1: "Ethernet operation is supported",
                }
            ),

            # Configuration Flags Field
            BitField("Reserved_2", 0, 9),
            BitEnumField(
                "Bootable",
                0,
                1,
                {
                    0: "The partition does not support boot",
                    1: "The partition supports boot and reporting",
                }
            ),
            BitEnumField(
                "BootStatus",
                0,
                1,
                {
                    0: "The partition is not configured for boot",
                    1: "The partition is configured for boot",
                }
            ),
            BitEnumField(
                "PartitionLinkStatusReporting",
                0,
                1,
                {
                    0: "Partition Link Status reporting is not supported",
                    1: "Partition Link Status reporting (bit 2) is supported",
                }
            ),
            BitEnumField(
                "PartitionLinkStatus",
                0,
                2,
                {
                    0: "When reporting is supported, Partition Link is down",
                    1: "When reporting is supported, Partition Link is forced up",
                    2: "When reporting is supported, Partition Link follows Channel Link",
                    3: "Reserved"
                }
            ),
            BitEnumField(
                "HostDriverStatusReporting",
                0,
                1,
                {
                    0: "Host Driver status reporting is not supported",
                    1: "Host Driver status reporting (bit 0) is supported",
                }
            ),
            BitEnumField(
                "HostDriverStatus",
                0,
                1,
                {
                    0: "When reporting is supported, a Host driver is not present on the partition",
                    1: "When reporting is supported, a Host driver is present on the partition",
                }
            ),
            ByteField("MaxTxBW", 0),
            ByteField("MinTxBW", 0),
            XShortField("Reserved_3", 0x0000),
            XShortField("PCI_DID", 0x0000),
            XShortField("PCI_VID", 0x0000),
            XShortField("PCI_SSID", 0x0000),
            XShortField("PCI_SVID", 0x0000),

            XByteField("PCIeEndpointNum", 0x00),
            XByteField("PCIeBusNum", 0x00),
            XByteField("PCIeDeviceNum", 0x00),
            XByteField("PCIeFunctionNum", 0x00),

            XByteField("Reserved_4", 0x00),
            FieldLenField(
                "AddressCount", 0, count_of="AddressTLVs", fmt="B"
            ),
            PacketListField(
                "AddressTLVs",
                None,
                AddressTlvEntry,
                count_from=lambda pkt: pkt.AddressCount
            )
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            PacketField("CfgData", Data(), Data),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 142
class SetPartitionConfiguration_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set Partition Configuration Request"""

    name = "Set Partition Configuration Request"
    CommandValue = 0x2C

    fields_desc = [
        ByteField("PartitionID", 0),
        BitField("Reserved_0", 0, 1),
        BitEnumField(
            "NVMe",
            0,
            1,
            {
                0: "Disable NVMe operation",
                1: "Enable NVMe operation",
            },
        ),
        BitEnumField(
            "RDMAStatus",
            0,
            1,
            {
                0: "Disable RDMA operation",
                1: "Enable RDMA operation",
            }
        ),
        BitEnumField(
            "iSCSIOffloadStatus",
            0,
            1,
            {
                0: "Disable iSCSI Offload operation",
                1: "Enable iSCSI Offload operation",
            }
        ),
        BitEnumField(
            "InfiniBandStatus",
            0,
            1,
            {
                0: "Disable InfiniBand operation",
                1: "Enable InfiniBand operation",
            },
        ),
        BitEnumField(
            "FibreChannelOverEthernetStatus",
            0,
            1,
            {
                0: "Disable Fibre Channel over Ethernet operation",
                1: "Enable Fibre Channel over Ethernet operation",
            }
        ),
       BitEnumField(
            "FibreChannelStatus",
            0,
            1,
            {
                0: "Disable Fibre Channel operation",
                1: "Enable Fibre Channel operation",
            },
        ),
        BitEnumField(
            "EthernetStatus",
            0,
            1,
            {
                0: "Disable Ethernet operation",
                1: "Enable Ethernet operation",
            }
        ),
        XShortField("Reserved_1", 0x0000),
        XByteEnumField(
            "PartitionLinkControl",
            0x00,
            {
                0x00: "Partition Link is down",
                0x01: "Partition Link is forced up",
                0x02: "Partition Link follows Channel link state",
            }
        ),
        XByteField("Reserved_2", 0x00),
        ByteField("AddressCount", 0),
        # AddressTLV Field
        BitField("AddressLength", 0, 8),
        XBitField("AddressType", 0, 8),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 146
class SetPartitionConfiguration_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set Partition Configuration Response"""

    name = "Set Partition Configuration Response"
    CommandValue = SetPartitionConfiguration_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


class BootProtocolTlvPXE(Packet):
    """DSP0222 v1.2.0 - Table 151"""

    fields_desc = [
        XByteEnumField(
            "Type",
            0x00,
            {
                0x00: "VLAN ID (uint16)",
                0x01: "VLAN enable (bool8)",
            }
        ),
        FieldLenField(
            "Length",
            None,
            length_of="Value", fmt="B"
        ),
        FieldListField(
            "Value",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.Length,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class BootProtocolTlvFC(Packet):
    """DSP0222 v1.2.0 - Table 152"""

    fields_desc = [
        XByteEnumField(
            "Type",
            0x00,
            {
                0x00: "FCInitiatorBootSelection (uint8)",
                0x01: "FirstFCTargetWWPN (string)",
                0x02: "FirstFCTargetLUN (uint64)",
                0x03: "SecondFCTargetWWPN (string)",
                0x04: "SecondFCTargetLUN (uint64)",
                0x05: "ThirdFCTargetWWPN (string)",
                0x06: "ThirdFCTargetLUN (uint64)",
                0x07: "FourthFCTargetWWPN (string)",
                0x08: "FourthFCTargetLUN (uint64)",
                0x09: "FifthFCTargetWWPN (string)",
                0x0A: "FifthFCTargetLUN (uint64)",
                0x0B: "SixthFCTargetWWPN (string)",
                0x0C: "SixthFCTargetLUN (uint64)",
                0x0D: "SeventhFCTargetWWPN (string)",
                0x0E: "SeventhFCTargetLUN (uint64)",
                0x0F: "EighthFCTargetWWPN (string)",
                0x10: "EighthFCTargetLUN (uint64)"
            }
        ),
        FieldLenField(
            "Length",
            None,
            length_of="Value", fmt="B"
        ),
        FieldListField(
            "Value",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.Length,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class BootProtocolTlvFCoE(Packet):
    """DSP0222 v1.2.0 - Table 153"""

    fields_desc = [
        XByteEnumField(
            "Type",
            0x00,
            {
                0x00: "FCoEInitiatorBootSelection",
                0x01: "FirstFCoEWWPNTarget (string)",
                0x02: "FirstFCoEBootTargetLUN (uint64)",
                0x03: "FirstFCoEFCFVLANID (uint16)",
                0x04: "FCoETgTBoot (bool8)"
            }
        ),
        FieldLenField(
            "Length",
            None,
            length_of="Value", fmt="B"
        ),
        FieldListField(
            "Value",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.Length,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class BootProtocolTlvISCSI(Packet):
    """DSP0222 v1.2.0 - Table 154"""

    fields_desc = [
        XByteEnumField(
            "Type",
            0x00,
            {
                0x00: "IscsiInitiatorIPAddrType (uint8)",
                0x01: "IscsiInitiatorAddr (string)",
                0x02: "IscsiInitiatorName (string)",
                0x03: "IscsiInitiatorSubnet (string)",
                0x04: "IscsiInitiatorSubnetPrefix (string)",
                0x05: "IscsiInitiatorGateway (string)",
                0x06: "IscsiInitiatorFirstDNS (string)",
                0x07: "IscsiInitiatorSecondDNS (string)",

                0x10: "ConnectFirstTgt (bool8)",
                0x11: "FirstTgtIpAddress (string)",
                0x12: "FirstTgtTcpPort (uint16)",
                0x13: "FirstTgtBootLun (uint64)",
                0x14: "FirstTgtIscsiName (string)",
                0x15: "FirstTgtChapId (string)",
                0x16: "FirstTgtChapPwd (string)",
                0x17: "FirstTgtVLANEnable (bool8)",
                0x18: "FirstTgtVLAN (uint16)",

                0x20: "ConnectSecondTgt (bool8)",
                0x21: "SecondTgtIpAddress (string)",
                0x22: "SecondTgtTcpPort (uint16)",
                0x23: "SecondTgtBootLun (uint64)",
                0x24: "SecondTgtIscsiName (string)",
                0x25: "SecondTgtChapId (string)",
                0x26: "SecondTgtChapPwd (string)",
                0x27: "SecondTgtVLANEnable (bool8)",
                0x28: "SecondTgtVLAN (uint16)"
            }
        ),
        FieldLenField(
            "Length",
            None,
            length_of="Value", fmt="B"
        ),
        FieldListField(
            "Value",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.Length,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class BootProtocolTlvNVMeoFC(Packet):
    """DSP0222 v1.2.0 - Table 155"""

    fields_desc = [
        XByteEnumField(
            "Type",
            0x00,
            {
                0x00: "FirstNVMeTargetNQN (string)",
                0x01: "FirstNVMeTargetWWN (string)",
                0x02: "FirstNVMeTargetWWPN (string)",
                0x03: "FirstNVMeTgtConn (bool8)",
                0x04: "FirstNVMeTgtCntlrID (uint32)",
                0x05: "FirstNVMeTgtNSID (uint32)",

                0x08: "SecondNVMeTargetNQN (string)",
                0x09: "SecondNVMeTargetWWN (string)",
                0x0A: "SecondNVMeTargetWWPN (string)",
                0x0B: "SecondNVMeTgtConn (bool8)",
                0x0C: "SecondNVMeTgtCntlrID (uint32)",
                0x0D: "SecondNVMeTgtNSID (uint32)",

                0x10: "ThirdNVMeTargetNQN (string)",
                0x11: "ThirdNVMeTargetWWN (string)",
                0x12: "ThirdNVMeTargetWWPN (string)",
                0x13: "ThirdNVMeTgtConn (bool8)",
                0x14: "ThirdNVMeTgtCntlrID (uint32)",
                0x15: "ThirdNVMeTgtNSID (uint32)",

                0x18: "FourthNVMeTargetNQN (string)",
                0x19: "FourthNVMeTargetWWN (string)",
                0x1A: "FourthNVMeTargetWWPN (string)",
                0x1B: "FourthNVMeTgtConn (bool8)",
                0x1C: "FourthNVMeTgtCntlrID (uint32)",
                0x1D: "FourthNVMeTgtNSID (uint32)",

                0x20: "FifthNVMeTargetNQN (string)",
                0x21: "FifthNVMeTargetWWN (string)",
                0x22: "FifthNVMeTargetWWPN (string)",
                0x23: "FifthNVMeTgtConn (bool8)",
                0x24: "FifthNVMeTgtCntlrID (uint32)",
                0x25: "FifthNVMeTgtNSID (uint32)",

                0x28: "SixthNVMeTargetNQN (string)",
                0x29: "SixthNVMeTargetWWN (string)",
                0x2A: "SixthNVMeTargetWWPN (string)",
                0x2B: "SixthNVMeTgtConn (bool8)",
                0x2C: "SixthNVMeTgtCntlrID (uint32)",
                0x2D: "SixthNVMeTgtNSID (uint32)",

                0x30: "SeventhNVMeTargetNQN (string)",
                0x31: "SeventhNVMeTargetWWN (string)",
                0x32: "SeventhNVMeTargetWWPN (string)",
                0x33: "SeventhNVMeTgtConn (bool8)",
                0x34: "SeventhNVMeTgtCntlrID (uint32)",
                0x35: "SeventhNVMeTgtNSID (uint32)",

                0x38: "EighthNVMeTargetNQN (string)",
                0x39: "EighthNVMeTargetWWN (string)",
                0x3A: "EighthNVMeTargetWWPN (string)",
                0x3B: "EighthNVMeTgtConn (bool8)",
                0x3C: "EighthNVMeTgtCntlrID (uint32)",
                0x3D: "EighthNVMeTgtNSID (uint32)",
            }
        ),
        FieldLenField(
            "Length",
            None,
            length_of="Value", fmt="B"
        ),
        FieldListField(
            "Value",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.Length,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


class BootProtocolTlvGeneric(Packet):
    """Best guess at Unknown Boot Protocol TLV"""

    fields_desc = [
        XByteField(
            "Type",
            0x00,
        ),
        FieldLenField(
            "Length",
            None,
            length_of="Value", fmt="B"
        ),
        FieldListField(
            "Value",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.Length,
        )
    ]

    def extract_padding(self, s):
        return ("", s)


# DSP0222 v1.2.0 - Table 147
class GetBootConfig_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Boot Config Request"""

    name = "Get Boot Config Request"
    CommandValue = 0x2D

    fields_desc = [
        ByteField("PartitionID", 0),
        XShortField("Reserved", 0x0000),
        XByteEnumField(
            "ProtocolType",
            0x00,
            {
                0x00: "PXE",
                0x01: "iSCSI",
                0x02: "FCoE",
                0x03: "FC",
                0x04: "NVMeoFC",
            }
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 147
class GetBootConfig_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Boot Config Response"""

    name = "Get Boot Config Response"
    CommandValue = GetBootConfig_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            XShortField("Reserved", 0x0000),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            XByteEnumField(
                "ProtocolType",
                0x00,
                {
                    0x00: "PXE",
                    0x01: "iSCSI",
                    0x02: "FCoE",
                    0x03: "FC",
                    0x04: "NVMeoFC",
                    0xFF: "Unknown protocol type"
                }
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            FieldLenField(
                "NumberOfTLVs", None, count_of="TLVs", fmt="B"
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            PacketListField(
                "TLVs",
                [],
                BootProtocolTlvGeneric(),
                count_from=lambda pkt: pkt.NumberOfTLVs,
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 156
class SetBootConfig_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set Boot Config Request"""

    name = "Set Boot Config Request"
    CommandValue = 0x2E

    fields_desc = [
        ByteField("PartitionID", 0),
        ByteField("Reserved", 0),
        XByteField("ProtocolType", 0x00),
        FieldLenField(
            "NumberOfTLVs", None, count_of="TLVs", fmt="B"
        ),
        PacketListField(
            "TLVs",
            [],
            BootProtocolTlvGeneric(),
            count_from=lambda pkt: pkt.NumberOfTLVs,
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 157
class SetBootConfig_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set Boot Config Response"""

    name = "Set Boot Config Response"
    CommandValue = SetBootConfig_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 159
class GetPartitionStatistics_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Partition Statist Request"""

    name = "Get Partition Statist Request"
    CommandValue = 0x2F

    fields_desc = [
        ByteField("PartitionID", 0),
        XShortField("Reserved", 0x0000),
        XByteEnumField(
            "StatsType",
            0x01,
            {
                0x01: "Ethernet",
                0x02: "iSCSI",
                0x04: "FCoE",
                0x08: "RDMA",
                0x10: "IB",
                0x20: "FC"
            }
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


class GetPartitionStatisticsEthernet(Packet):
    """Table 161 - Get Partition Statistics (Ethernet) response"""

    fields_desc = [
        # Counter Sizes field
        BitEnumField(
            "TotalBroadcastBytesTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalMulticastBytesTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalUnicastBytesTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalBroadcastBytesReceivedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalMulticastBytesReceivedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalUnicastBytesReceivedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalBytesTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalBytesReceivedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        # Counters Cleared from Last Read
        BitField("Reserved", 0, 2),
        BitEnumField(
            "TotalBroadcastBytesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalMulticastBytesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalUnicastBytesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalBroadcastBytesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalMulticastBytesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalUnicastBytesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalBroadcastPacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalMulticastPacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalUnicastPacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalBroadcastPacketsReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalMulticastPacketsReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalUnicastPacketsReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalByteTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalBytesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),

        XIntField("TotalBytesReceivedUpper", 0x00000000),
        XIntField("TotalBytesReceivedLower", 0x00000000),
        XIntField("TotalBytesTransmittedUpper", 0x00000000),
        XIntField("TotalBytesTransmittedLower", 0x00000000),

        XIntField("TotalUnicastPacketsReceived", 0x00000000),
        XIntField("TotalMulticastPacketsReceived", 0x00000000),
        XIntField("TotalBroadcastPacketsReceived", 0x00000000),

        XIntField("TotalUnicastPacketsTransmitted", 0x00000000),
        XIntField("TotalMulticastPacketsTransmitted", 0x00000000),
        XIntField("TotalBroadcastPacketsTransmitted", 0x00000000),

        XIntField("TotalUnicastBytesReceivedUpper", 0x00000000),
        XIntField("TotalUnitcastBytesReceivedLower", 0x00000000),
        XIntField("TotalMulticastBytesReceivedUpper", 0x00000000),
        XIntField("TotalMulticastBytesReceivedLower", 0x00000000),
        XIntField("TotalBroadcastBytesReceivedUpper", 0x00000000),
        XIntField("TotalBroadcastBytesReceivedLower", 0x00000000),

        XIntField("TotalUnicastBytesTransmittedUpper", 0x00000000),
        XIntField("TotalUnitcastBytesTransmittedLower", 0x00000000),
        XIntField("TotalMulticastBytesTransmittedUpper", 0x00000000),
        XIntField("TotalMulticastBytesTransmittedLower", 0x00000000),
        XIntField("TotalBroadcastBytesTransmittedUpper", 0x00000000),
        XIntField("TotalBroadcastBytesTransmittedLower", 0x00000000),
    ]

    def extract_padding(self, s):
        return ("", s)


class GetPartitionStatisticsFCoE(Packet):
    """Table 164 - Get Partition Statistics (FCoE) response"""

    fields_desc = [
        # Counter Sizes field
        BitField(
            "Reserved_0",
            0,
            4,
        ),
        BitEnumField(
            "TotalFCoePacketsTransmitted",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalFCoePacketsReceived",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalFCoeBytesTransmitted",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalFCoeBytesReceived",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),

        # Counters Cleared from Last Read
        BitField("Reserved_1", 0, 12),
        BitEnumField(
            "TotalFCoePacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalFCoePacketsReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalFCoeBytesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalFCoeBytesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),

        XIntField("TotalFCoeBytesReceivedUpper", 0x00000000),
        XIntField("TotalFCoeBytesReceivedLower", 0x00000000),

        XIntField("TotalFCoeBytesTransmittedUpper", 0x00000000),
        XIntField("TotalFCoeBytesTransmittLower", 0x00000000),

        XIntField("TotalFCoePacketsReceivedUpper", 0x00000000),
        XIntField("TotalFCoePacketsReceivedLower", 0x00000000),

        XIntField("TotalFCoePacketsTransmittedUpper", 0x00000000),
        XIntField("TotalFCoePacketsTransmittLower", 0x00000000),
    ]

    def extract_padding(self, s):
        return ("", s)


class GetPartitionStatisticsISCSI(Packet):
    """Table 167 - Get Partition Statistics (iSCSI) response"""

    fields_desc = [
        # Counter Sizes field
        BitField(
            "Reserved_0",
            0,
            4,
        ),
        BitEnumField(
            "TotaliSCSIOffloadPDUsTransmitted",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotaliSCSiOffloadPDUsReceived",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotaliSCSIOffloadBytesTransmitted",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotaliSCSIOffloadBytesReceived",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitField(
            "Reserved_1",
            0,
            4,
        ),
        BitEnumField(
            "TotaliSCSIOffloadPDUsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),

        BitEnumField(
            "TotaliSCSIOffloadPDUsReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),

        BitEnumField(
            "TotaliSCSIOffloadBytesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),

        BitEnumField(
            "TotaliSCSIOffloadBytesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),

        XIntField("TotaliSCSIOffloadBytesReceivedUpper", 0x00000000),
        XIntField("TotaliSCSIOffloadBytesReceivedLower", 0x00000000),

        XIntField("TotaliSCSIOffloadBytesTransmittedUpper", 0x00000000),
        XIntField("TotaliSCSIOffloadBytesTransmittLower", 0x00000000),

        XIntField("TotaliSCSIOffloadPacketsReceivedUpper", 0x00000000),
        XIntField("TotaliSCSIOffloadPacketsReceivedLower", 0x00000000),

        XIntField("TotaliSCSIOffloadPacketsTransmittedUpper", 0x00000000),
        XIntField("TotaliSCSIOffloadPacketsTransmittLower", 0x00000000),
    ]

    def extract_padding(self, s):
        return ("", s)


class GetPartitionStatisticsIB(Packet):
    """Table 170 - Get Partition Statistics (IB) response"""

    fields_desc = [
        # Counter Sizes field
        BitEnumField(
            "TotalBroadcastBytesTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalMulticastBytesReceivededSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalUnicastBytesTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalUnicastBytesReceivedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalMulticastPacketsTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalMulticastPacketsReceivedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalUnicastPacketsTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalUnicastPacketsReceivedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        # Counters Cleared from Last Read
        BitField("Reserved", 0, 8),
        BitEnumField(
            "TotalMulticastBytesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalUnicastBytesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalMulticastBytesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalUnicastBytesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalMulticastPacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalUnicastPacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalMulticastPacketsReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalUnicastPacketsReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),

        IntField("TotalUnicastPacketsReceivedUpper", 0x00000000),
        IntField("TotalUn_icastPacketsReceivedLower", 0x00000000),

        IntField("TotalMulticastPacketsReceivedUpper", 0x00000000),
        IntField("TotalMulticastPacketsReceivedLower", 0x00000000),

        IntField("TotalUnicastPacketsTransmittedUpper", 0x00000000),
        IntField("TotalUnicastPacketsTransmittedLower", 0x00000000),

        IntField("TotalMulticastPacketsTransmittedUpper", 0x00000000),
        IntField("TotalMulticastPacketsTransmittedLower", 0x00000000),

        IntField("TotalUnicastBytesReceivedUpper", 0x00000000),
        IntField("TotalUnicastBytesReceivedLower", 0x00000000),

        IntField("TotalMulticastBytesReceivedUpper", 0x00000000),
        IntField("TotalMulticastBytesReceivedLower", 0x00000000),

        IntField("TotalUnicastBytesTransmittedUpper", 0x00000000),
        IntField("TotalUnicastBytesTransmittedLower", 0x00000000),

        IntField("TotalMulticastBytesTransmittedUpper", 0x00000000),
        IntField("TotalMulticastBytesTransmittedLower", 0x00000000),
    ]

    def extract_padding(self, s):
        return ("", s)


class GetPartitionStatisticsFC(Packet):
    """Table 176 - Get Partition Statistics (FC) response"""

    fields_desc = [
        XByteField("Reserved_0", 0x00),

        # Counters Cleared
        BitField("Reserved_1", 0, 7),
        BitEnumField(
            "InvalidCRCsCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "LossOfSignalCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "LinkFailuresCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "FCSequencesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "FCSequencesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TransmitKBCountCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "ReceiveKBCountCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalFCFramesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalFCFramesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),

        XIntField("TotalFCFramesReceived", 0x00000000),
        XIntField("TotalFCFramesTransmitted", 0x00000000),
        XIntField("ReceiveKBCount", 0x00000000),
        XIntField("TransmitKBCount", 0x00000000),
        XIntField("FCSequencesReceived", 0x00000000),
        XIntField("FCSequencesTransmitted", 0x00000000),
        XIntField("LinkFailures", 0x00000000),
        XIntField("LossOfSignal", 0x00000000),
        XIntField("InvalidCRCs", 0x00000000),
    ]

    def extract_padding(self, s):
        return ("", s)


class GetPartitionStatisticsRDMA(Packet):
    """Table 176 - Get Partition Statistics (FC) response"""

    fields_desc = [
        # Counter sizes
        BitField("Reserved_0", 0, 1),
        BitEnumField(
            "TotalWritePacketsTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalSendPacketsTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalReadRequestPacketsTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalRDMAPacketsTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalRDMAPacketsReceivedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalRDMABytesTransmittedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),
        BitEnumField(
            "TotalRDMABytesReceivedSize",
            0,
            1,
            {
                0: "32-bit",
                1: "64-bit",
            }
        ),

        # Counters cleared
        BitField("Reserved_1", 0, 9),
        BitEnumField(
            "TotalWritePacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalSendPacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalReadRequestPacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalRDMAPacketsTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalRDMAPacketsReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalRDMABytesTransmittedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),
        BitEnumField(
            "TotalRDMABytesReceivedCleared",
            0,
            1,
            {
                0: "Not Cleared",
                1: "Cleared",
            }
        ),

        XIntField("TotalRDMABytesReceivedUpper", 0x00000000),
        XIntField("TotalRDMABytesReceivedLower", 0x00000000),

        XIntField("TotalRDMABytesTransmittedUpper", 0x00000000),
        XIntField("TotalRDMABytesTransmittedLower", 0x00000000),
        XIntField("TotalRDMAPacketsReceivedUpper", 0x00000000),

        XIntField("TotalRDMAPacketsReceivedLower", 0x00000000),
        XIntField("TotalRDMAPacketsTransmittedUpper", 0x00000000),
        XIntField("TotalRDMAPacketsTransmittedLower", 0x00000000),

        XIntField("TotalReadRequestPacketsTransmittedUpper", 0x00000000),
        XIntField("TotalReadRequestPacketsTransmittedLower", 0x00000000),

        XIntField("TotalSendPacketsTransmittedUpper", 0x00000000),
        XIntField("TotalSendPacketsTransmittedLower", 0x00000000),

        XIntField("TotalWritePacketsTransmittedUpper", 0x00000000),
        XIntField("TotalWritePacketsTransmittedLower", 0x00000000),
    ]

    def extract_padding(self, s):
        return ("", s)


# DSP0222 v1.2.0 - Table 161
class GetPartitionStatistics_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Partition Statist Response"""

    name = "Get Partition Statist Response"
    CommandValue = GetPartitionStatistics_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            XByteEnumField(
                "StatsType",
                0,
                {
                    0x01: "Ethernet",
                    0x02: "iSCSI",
                    0x04: "FCoE",
                    0x08: "RDMA",
                    0x10: "IB",
                    0x20: "FC"
                }
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            PacketField(
                "StatsEthernet",
                GetPartitionStatisticsEthernet(),
                GetPartitionStatisticsEthernet),
                lambda pkt: pkt.StatsType == 0x01 and pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            PacketField(
                "StatsISCSI",
                GetPartitionStatisticsISCSI(),
                GetPartitionStatisticsISCSI),
                lambda pkt: pkt.StatsType == 0x02 and pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            PacketField(
                "StatsFCoE",
                GetPartitionStatisticsFCoE(),
                GetPartitionStatisticsFCoE),
                lambda pkt: pkt.StatsType == 0x04 and pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            PacketField(
                "StatsRDMA",
                GetPartitionStatisticsRDMA(),
                GetPartitionStatisticsRDMA),
                lambda pkt: pkt.StatsType == 0x08 and pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            PacketField(
                "StatsIB",
                GetPartitionStatisticsIB(),
                GetPartitionStatisticsIB),
                lambda pkt: pkt.StatsType == 0x10 and pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            PacketField(
                "StatsFC",
                GetPartitionStatisticsFC(),
                GetPartitionStatisticsFC),
                lambda pkt: pkt.StatsType == 0x20 and pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 179
class SetModuleManagementData_Request(NCSI_PAYLOAD):
    "DSP0222 v1.2.0 Set Module Management Data Request"

    name = "Set Module Management Data Request"
    CommandValue = 0x30

    fields_desc = [
        ByteField("RequestedBank", 0),
        ByteField("RequestedPage", 0),
        ByteField("Offset", 0),

        ### TODO: FIX in multiples of 4
        FieldLenField(
            "Length", None, length_of="ManagementData", fmt="B"
        ),
        FieldListField(
            "ManagementData",
            [],
            XByteField("", 0x00),
            count_from=lambda pkt: pkt.Length * 4,
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 180
class SetModuleManagementData_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set Module Management Data Response"""

    name = "Set Module Management Data Response"
    CommandValue = SetModuleManagementData_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]

# DSP0222 - Table 187
class GetModuleManagementData_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Module Management Data Request"""

    name = "Get Module Management Data Request"
    CommandValue = 0x32

    fields_desc = [
        ByteField("RequestedBank", 0),
        ByteField("RequestedPage", 0),
        ByteField("Reserved_0", 0),

        # Flags Field
        BitField("Reserved_1", 0, 7),
        BitEnumField("PageUpperFlag",
                     0,
                     1,
                     {
                         0 : "Requesting lower page data",
                         1 : "Requesting upper page data",
                     },
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4),
    ]


# DSP0222 - Table 188
class GetModuleManagementData_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Module Management Data Response"""

    name = "Get Module Management Data Response"
    CommandValue = GetModuleManagementData_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            ByteField("MaxBank", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            ByteField("MaxPage", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            ByteField("BankNumber", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            ByteField("PageNumber", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            FieldListField(
                "Data",
                [],
                XByteField("", 0x00),
                count_from=lambda pkt: 128
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]

# DSP0222 - Table 192
class SetPassThroughModeControl_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set Pass-through Mode Control Request"""

    name = "Set Pass-through Mode Control Request"
    CommandValue = 0x33

    fields_desc = [
        XShortField("Reserved_0", 0x0000),
        BitField("Reserved_1", 0, 5),
        BitEnumField("EmbeddedCpuBmcPassthroughTraffic", 0, 1, ALLOWED_DISALLOWED),
        BitEnumField("HostBmcPassthroughTraffic", 0, 1, ALLOWED_DISALLOWED),
        BitEnumField("NetworkBMCPassthroughTraffic", 0, 1, ALLOWED_DISALLOWED),
        XByteField("Reserved_2", 0x00),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 193
class SetPassThroughModeControl_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set Pass-through Mode Control Response"""

    name = "Set Pass-through Mode Controlx Response"
    CommandValue = SetPassThroughModeControl_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 194
class GetPassThroughModeControl_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Pass-through Mode Request"""

    name = "Get Pass-through Mode Request"
    CommandValue = 0x34

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 195
class GetPassThroughModeControl_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Pass-through Mode Response"""

    name = "Get Pass-through Mode Response"
    CommandValue = GetPassThroughModeControl_Request.CommandValue | 0x80

    class Data(Packet):

        fields_desc = [
            XShortField("Reserved_0", 0x0000),

            # Pass-through Mode Status
            BitField("Reserved_1", 0, 5),
            BitEnumField("EmbeddedCpuBmcPassthroughTraffic", 0, 1, ALLOWED_DISALLOWED),
            BitEnumField("HostBmcPassthroughTraffic", 0, 1, ALLOWED_DISALLOWED),
            BitEnumField("NetworkBMCPassthroughTraffic", 0, 1, ALLOWED_DISALLOWED),

            # Pass-through Pass-through Mode Capability
            BitField("Reserved_2", 0, 5),
            BitEnumField("EmbeddedCpuBmcPassthroughTrafficSupported", 0, 1, SUPPORTED_NOT_SUPPORTED),
            BitEnumField("HostBmcPassthroughTrafficSupported", 0, 1, SUPPORTED_NOT_SUPPORTED),
            BitEnumField("NetworkBMCPassthroughTrafficSupported", 0, 1, SUPPORTED_NOT_SUPPORTED),
        ]

        def extract_padding(self, s):
            return ("", s)

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            PacketField("ModeData", Data(), Data),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 198
class GetVfAllocation_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get VF Allocation Request"""

    name = "Get VF Allocation Request"
    CommandValue = 0x35

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 199
class GetVfAllocation_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get VF Allocation Response"""

    name = "Get VF Allocation Response"
    CommandValue = GetVfAllocation_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            FieldListField(
                "FunctionNumVfList",
                [],
                XByteField("FunctionNumVFs", None),
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 201
class SetVfAllocation_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set VF Allocation Request"""

    name = "Set VF Allocation Request"
    CommandValue = 0x36

    fields_desc = [
        FieldListField(
            "FunctionNumVfList",
            [],
            XByteField("FunctionNumVFs", None),
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 203
class SetVfAllocation_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Set VF Allocation Response"""

    name = "Set VF Allocation Response"
    CommandValue = SetVfAllocation_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 210
class SettingsCommit_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Settings Commit Request"""

    name = "Settings Commit Request"
    CommandValue = 0x47

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 211
class SettingsCommit_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Settings Commit Response"""

    name = "Settings Commit Response"
    CommandValue = SettingsCommit_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 212
class GetAsicTemperature_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get ASIC Temperature Request"""

    name = "Get ASIC Temperature Request"
    CommandValue = 0x48

    fields_desc = [
        XIntField("Reserved", 0x00000000),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 213
class GetAsicTemperature_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get ASIC Temperature Response"""

    name = "Get ASIC Temperature Response"
    CommandValue = GetAsicTemperature_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            ShortField("MaximumTemperature", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            ShortField("CurrentTemperature", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 214
class GetAmbientTemperature_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Ambient Temperature Request"""

    name = "Get Ambient Temperature Request"
    CommandValue = 0x49

    fields_desc = [
        XIntField("Reserved", 0x00000000),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 215
class GetAmbientTemperature_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Ambient Temperature Response"""

    name = "Get Ambient Temperature Response"
    CommandValue = GetAmbientTemperature_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            ByteField("TemperatureValue_3", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            ByteField("TemperatureValue_2", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            ByteField("TemperatureValue_1", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            ByteField("NumberOfSensors", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 216
class GetTransceiverTemperature_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Transceiver Temperature Request"""

    name = "Get Transceiver Temperature Request"
    CommandValue = 0x4A

    fields_desc = [
        XIntField("Reserved", 0x00000000),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 217
class GetTransceiverTemperature_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Transceiver Temperature Response"""

    name = "Get Transceiver Temperature Response"
    CommandValue = GetTransceiverTemperature_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),

        ConditionalField(
            ShortField("TempHighAlarmThreshold", 0),
             lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            ShortField("TempHighWarningThreshold", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            ShortField("TemperatureValue", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),
        ConditionalField(
            XShortField("Reserved", 0x0000),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000,
        ),

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 218
class ThermalShutdownControl_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Thermal Shutdown Control Request"""

    name = "Thermal Shutdown Control Request"
    CommandValue = 0x4B

    fields_desc = [
        X3BytesField("Reserved", 0x000000),
        ByteEnumField(
            "Operation",
            0,
            {
                0: "Thermal self-shutdown shall be disabled on the device",
                1: "Thermal self-shutdown shall be enabled on the device",
                2: "The currently configured shutdown setting shall be returned",
            }
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 219
class ThermalShutdownControl_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Thermal Shutdown Control Response"""

    name = "Thermal Shutdown Control Response"
    CommandValue = ThermalShutdownControl_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            XShortField("Reserved_0", 0x0000),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            BitField("Reserved_1", 0, 6),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            BitEnumField(
                "EnableDisableSupport",
                0,
                1,
                {
                    0: "Enable/Disable operations for thermal shutdown are not supported",
                    1: "Enable/Disable operations for thermal shutdown are supported",
                }
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            BitEnumField(
                "OperatingState",
                0,
                1,
                {
                    0: "Thermal self-shutdown is disabled on the device",
                    1: "Thermal self-shutdown is enabled on the device",
                }
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            ByteField("ShutdownTemperature", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 222
class TransmitDataNC_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Transmit Data to NC Request"""

    name = "Transmit Data to NC Request"
    CommandValue = 0x4C

    fields_desc = [
        X3BytesField("Reserved", 0x000000),
        ByteEnumField(
            "OpCode",
            0,
            {
                0x01: "First block of data in the transfer",
                0x02: "Intermediate block of data in the transfer",
                0x04: "Last block of data in the transfer",
                0x05: "First and last block of data in the transfer",
                0x08: "Terminate the transfer",
            }
        ),
        XIntField("Offset", 0x00000000),
        XIntField("DataHandle", 0x00000000),
        FieldListField(
            "Data",
            [],
            XByteField("Data", None),
            128
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 224
class TransmitDataNC_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Transmit Data to NC Response"""

    name = "Transmit Data to NC Response"
    CommandValue = TransmitDataNC_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 226
class RetrieveDataFromNC_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Receive Data from NC Request"""

    name = "Receive Data from NC Request"
    CommandValue = 0x4D

    fields_desc = [
        X3BytesField("Reserved", 0x000000),
        ByteEnumField(
            "OpCode",
            0,
            {
                0x00: "Request for the first chunk of the transfer to be returned",
                0x02: "Request for the next chunk of the transfer to be returned",
                0x03: "Termination of transfer by MC",
            }
        ),
        XIntField("Offset", 0x00000000),
        XIntField("DataHandle", 0x00000000),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 229
class RetrieveDataFromNC_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Receive Data from NC Response"""

    name = "Receive Data from NC Response"
    CommandValue = RetrieveDataFromNC_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            X3BytesField("Reserved", 0x000000),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            ByteEnumField(
                "OpCode",
                0,
                {
                    0x01: "First block of data in the transfer",
                    0x02: "Intermediate block of data in the transfer",
                    0x04: "Last block of data in the transfer",
                    0x05: "First and last block of data in the transfer",
                    0x08: "Terminate the transfer",
                }
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            FieldListField(
                "Data",
                [],
                XByteField("Data", None),
                128
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 232
class GetInventoryInformation_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Inventory Information Request"""

    name = "Get Inventory Information Request"
    CommandValue = 0x4E

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 234
class InventoryInfoEntry(Packet):
    """"DSP0222 v1.2.0 Get Inventory Information Response Data"""

    fields_desc = [
        FieldLenField(
            "Length", None, length_of="Value", fmt="B"
        ),
        XByteEnumField(
            "AttributeNameType",
            0,
            {
                0x00: "Manufacturer",
                0x01: "Product/Model",
                0x02: "Version",
                0x03: "Part Number",
                0x04: "Serial Number",
                0x05: "Manufacturing timestamp104",
            }
        ),
        FieldListField(
            "Value",
            [],
            XByteField("Data", None),
            count_from=lambda pkt: pkt.Length
        )
    ]

    def extract_padding(self, s):
        return ("", s)


# DSP0222 v1.2.0 - Table 233
class GetInventoryInformation_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Inventory Information Response"""

    name = "Get Inventory Information Response"
    CommandValue = GetInventoryInformation_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            FieldLenField(
                "NumberOfTLVs", None, count_of="TLVs", fmt="B"
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            PacketListField(
                "TLVs",
                InventoryInfoEntry(),
                InventoryInfoEntry,
                count_from=lambda pkt: pkt.NumberOfTLVs
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 258
class GetPackageUUID_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Package UUID Request"""

    name = "Get Package UUID Request"
    CommandValue = 0x52

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 259
class GetPackageUUID_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get Package UUID Response"""

    name = "Get Package UUID Response"
    CommandValue = 0xD2

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            PacketField("UUID", NCSI_UUID(), NCSI_UUID),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0261 - Table 10
class GetSupportedMedia_Request(NCSI_PAYLOAD):
    """DSP0261 v1.3.1 Get Supported Media Request"""

    name = "Get Supported Media Request"
    CommandValue = 0x54

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0261 - Table 12
class MediaDescriptor(Packet):
    """Repeated data within the GetSupportedMedia_Response"""

    name = "Media Descriptor"
    fields_desc = [
        XByteField("EID", 0x00),
        XShortField("BindingID", 0x00),
        XShortField("MediumID", 0x00),
        BitField("Status", 0, 1),
        BitField("MediaDescriptorReserved_1", 0, 6),
        BitField("PassthroughSupported", 0, 1),
        FieldLenField("PhysicalAddressSize", None, "PhysicalAddress", "B"),
        StrLenField(
            "PhysicalAddress", b"", length_from=lambda pkt: pkt.PhysicalAddressSize
        ),
    ]

    def extract_padding(self, s):  # all payloads need to do this
        return "", s


# DSP0261 - Table 11
class GetSupportedMedia_Response(NCSI_PAYLOAD):
    """DSP0261 v1.3.1 Get Supported Media Response"""

    name = "Get Supported Media Response"
    CommandValue = 0xD4

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            X3BytesField("GetSupportedMediaReserved_1", 0x000000),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            FieldLenField(
                "NumberOfSupportedMedias", None, count_of="MediaDescriptors", fmt="B"
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            PacketListField(
                "MediaDescriptors",
                None,
                MediaDescriptor,
                count_from=lambda pkt: pkt.NumberOfSupportedMedias,
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 244
class TransportSpecificAENEnable_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Transport-specific AEN Enable Request"""

    name = "Transport-specific AEN Enable Request"
    CommandValue = 0x55

    fields_desc = [
        XShortField("Reserved_0", 0x0000),
        BitField("Reserved_1", 0, 13),
        BitEnumField(
            "PendingSpdmRequestAEN",
            0,
            1,
            {
                0: "Disable Pending SPDM Request AEN",
                1: "Enable Pending SPDM Request AEN",
            }
        ),
        BitEnumField(
            "PendingPldmRequestAEN",
            0,
            1,
            {
                0: "Disable Pending PLDM Request AEN",
                1: "Enable Pending PLDM Request AEN",
            }
        ),
        BitEnumField(
            "MediumChangeAenControl",
            0,
            1,
            {
                0: "Disable Medium Change AEN",
                1: "Enable Medium Change AEN",
            }
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 246
class TransportSpecificAENEnable_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Transport-specific AEN Enable Response"""

    name = "Transport-specific AEN Enable Response"
    CommandValue = TransportSpecificAENEnable_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 250
class SendNCPLDMReply_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Send NC PLDM Reply Request"""

    name = "Send NC PLDM Reply Request"
    CommandValue = 0x57

    fields_desc = [
        # PLDM Message Common Fields
        X3BytesField("MessageCommonFields", 0x000000),
        XByteField("PLDMCompletionCode", 0x00),

        # PLDM Message payload + Payload Pad
        ### TODO Implement

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 251
class SendNCPLDMReply_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Send NC PLDM Reply Response"""

    name = "Send NC PLDM Reply Response"
    CommandValue = 0xD7

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            X3BytesField("Reserved", 0x000000),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            BitEnumField(
                "Flags",
                0,
                8,
                {
                    0: "No additional pending PLDM command from NC to MC",
                    1: "The NC has additional pending PLDM command to the MC",
                },
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 256
class GetMcMacAddress_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get MC MAC Address Request"""

    name = "Get MC MAC Address Request"
    CommandValue = 0x58

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 -  Table 257
class GetMcMacAddress_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Get MC MAC Address Response"""

    name = "Get MC MAC Address Response"
    CommandValue = 0xD8

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            FieldLenField("AddressCount", None, count_of="Addresses", fmt="B"),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        ConditionalField(
            X3BytesField("Reserved", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

        ConditionalField(
            FieldListField(
                "Addresses",
                [],
                MACField("", "ff:ff:ff:ff:ff:ff"),
                count_from=lambda pkt: pkt.AddressCount,
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 255
class SPDM_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 SPDM Request"""

    name = "SPDM Request"
    CommandValue = 0x60

    fields_desc = [
        ByteField("SpdmVersion", 0),
        ByteField("RequestCode", 0),
        XByteField("Param1", 0x00),
        XByteField("Param2", 0x00),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 256
class SPDM_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 SPDM Response"""

    name = "SPDM Response"
    CommandValue = SPDM_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            ByteField("SpdmVersion", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            ByteField("RequestCode", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            XByteField("Param1", 0x00),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            XByteField("Param2", 0x00),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 257
class QueryPendingNcSpdmRequest_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Query Pending NC SPDM Request"""

    name = "Query Pending NC SPDM Request"
    CommandValue = 0x61

    fields_desc = [
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 258
class QueryPendingNcSpdmRequest_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Query Pending NC SPDM Response"""

    name = "Query Pending NC SPDM Response"
    CommandValue = QueryPendingNcSpdmRequest_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            ByteField("SpdmVersion", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            ByteField("RequestCode", 0),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            XByteField("Param1", 0x00),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            XByteField("Param2", 0x00),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),

### TODO Implement variable payload

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 - Table 260
class SendNcSpdmReply_Request(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Send NC SPDM Reply"""

    name = "Send NC SPDM Reply"
    CommandValue = 0x62

    fields_desc = [
        ByteField("SpdmVersion", 0),
        ByteField("RequestCode", 0),
        XByteField("Param1", 0x00),
        XByteField("Param2", 0x00),

### TODO Implement variable payload

        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# DSP0222 v1.2.0 - Table 261
class SendNcSpdmReply_Response(NCSI_PAYLOAD):
    """DSP0222 v1.2.0 Send NC SPDM Reply Response"""

    name = "Send NC SPDM Reply Response"
    CommandValue = SendNcSpdmReply_Request.CommandValue | 0x80

    fields_desc = [
        XShortEnumField("ResponseCode", 0x0000, STANDARD_RESPONSE_CODE_VALUES),
        XShortEnumField("ReasonCode", 0x0000, STANDARD_REASON_CODE_VALUES),
        ConditionalField(
            X3BytesField("Reserved", 0x000000),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            BitField("ReservedFlags", 0, 7),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        ConditionalField(
            BitEnumField(
                "PendingRequest",
                0,
                1,
                {
                    0: "No additional pending SPDM command from NC to MC",
                    1: "The NC has additional pending SPDM command to the MC",
                }
            ),
            lambda pkt: pkt.ResponseCode == 0x0000 and pkt.ReasonCode == 0x0000
        ),
        NcsiReversePadField(XIntField("Checksum", None), 4)
    ]


# Register classes for auto lookup
register_ncsi_class(GetNcCapabilitiesSettings_Request)
register_ncsi_class(GetNcCapabilitiesSettings_Response)
register_ncsi_class(GetPfAssignment_Request)
register_ncsi_class(GetPfAssignment_Response)
register_ncsi_class(SetPfAssignment_Request)
register_ncsi_class(SetPfAssignment_Response)
register_ncsi_class(GetChannelConfiguration_Request)
register_ncsi_class(GetChannelConfiguration_Response)
register_ncsi_class(SetChannelConfiguration_Request)
register_ncsi_class(SetChannelConfiguration_Response)
register_ncsi_class(GetPartitionConfiguration_Request)
register_ncsi_class(GetPartitionConfiguration_Response)
register_ncsi_class(SetPartitionConfiguration_Request)
register_ncsi_class(SetPartitionConfiguration_Response)
register_ncsi_class(GetBootConfig_Request)
register_ncsi_class(GetBootConfig_Response)
register_ncsi_class(SetBootConfig_Request)
register_ncsi_class(SetBootConfig_Response)
register_ncsi_class(GetPartitionStatistics_Request)
register_ncsi_class(GetPartitionStatistics_Response)
register_ncsi_class(SetModuleManagementData_Request)
register_ncsi_class(SetModuleManagementData_Response)
register_ncsi_class(GetModuleManagementData_Request)
register_ncsi_class(GetModuleManagementData_Response)
register_ncsi_class(SetPassThroughModeControl_Request)
register_ncsi_class(SetPassThroughModeControl_Response)
register_ncsi_class(GetPassThroughModeControl_Request)
register_ncsi_class(GetPassThroughModeControl_Response)
register_ncsi_class(GetVfAllocation_Request)
register_ncsi_class(GetVfAllocation_Response)
register_ncsi_class(SetVfAllocation_Request)
register_ncsi_class(SetVfAllocation_Response)
register_ncsi_class(SettingsCommit_Request)
register_ncsi_class(SettingsCommit_Response)
register_ncsi_class(GetAsicTemperature_Request)
register_ncsi_class(GetAsicTemperature_Response)
register_ncsi_class(GetAmbientTemperature_Request)
register_ncsi_class(GetAmbientTemperature_Response)
register_ncsi_class(GetTransceiverTemperature_Request)
register_ncsi_class(GetTransceiverTemperature_Response)
register_ncsi_class(ThermalShutdownControl_Request)
register_ncsi_class(ThermalShutdownControl_Response)
register_ncsi_class(TransmitDataNC_Request)
register_ncsi_class(TransmitDataNC_Response)
register_ncsi_class(RetrieveDataFromNC_Request)
register_ncsi_class(RetrieveDataFromNC_Response)
register_ncsi_class(GetInventoryInformation_Request)
register_ncsi_class(GetInventoryInformation_Response)
register_ncsi_class(GetPackageUUID_Request)
register_ncsi_class(GetPackageUUID_Response)
register_ncsi_class(GetSupportedMedia_Request)
register_ncsi_class(GetSupportedMedia_Response)
register_ncsi_class(TransportSpecificAENEnable_Request)
register_ncsi_class(TransportSpecificAENEnable_Response)
register_ncsi_class(SendNCPLDMReply_Request)
register_ncsi_class(SendNCPLDMReply_Response)
register_ncsi_class(GetMcMacAddress_Request)
register_ncsi_class(GetMcMacAddress_Response)
register_ncsi_class(SPDM_Request)
register_ncsi_class(SPDM_Response)
register_ncsi_class(QueryPendingNcSpdmRequest_Request)
register_ncsi_class(QueryPendingNcSpdmRequest_Response)
register_ncsi_class(SendNcSpdmReply_Request)
register_ncsi_class(SendNcSpdmReply_Response)
