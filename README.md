# PMCI-Protocol-Validator

Copyright 2023-2026 DMTF. All rights reserved.

## About

PMCI-Protocol-Validator is a toolkit based on Python and used for building, sending, receiving, and validating PMCI protocol messages. The project provides:

- Packet definitions for most DMTF PMCI specifications,
- Transport and libraries for DSP0280 Test Service communication,
- Reusable helper APIs for common PTTI flows,
- Example Test Client and Test Service applications,
- Automated tests to verify packet/class behavior
- Automated tests for PTTI message and protocol sequences.

### License

BSD 3-Clause. See [LICENSE.md](https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md).

### Versioning and Packaging

- Package name: `pmci_protocol_validator`
- Current version: `0.1.0`
- Packaging metadata is in `setup.py`

## Specifications Covered

The repository includes class definitions and tests for protocol elements from these specifications:

- [DSP0280](https://www.dmtf.org/sites/default/files/standards/documents/DSP0280_1.0.0.pdf) PMCI Test Tools Interface and Design Specification
- [DSP0222](https://www.dmtf.org/sites/default/files/standards/documents/DSP0222_1.1.1.pdf) Network Controller Sideband Interface (NC-SI) Specification
- [DSP0236](https://www.dmtf.org/sites/default/files/standards/documents/DSP0236_1.3.3.pdf) Management Component Transport Protocol (MCTP) Base Specification
- [DSP0237](https://www.dmtf.org/sites/default/files/standards/documents/DSP0237_1.2.0.pdf) Management Component Transport Protocol (MCTP) SMBus/I2C Transport Binding 6 Specification
- [DSP0238](https://www.dmtf.org/sites/default/files/standards/documents/DSP0238_1.4.0.pdf) Management Component Transport Protocol (MCTP) PCIe(r) VDM Transport Binding Specification
- [DSP0239](https://www.dmtf.org/sites/default/files/standards/documents/DSP0239_1.12.0.pdf) Management Component Transport Protocol (MCTP) IDs and Codes
- [DSP0240](https://www.dmtf.org/sites/default/files/standards/documents/DSP0240_1.1.0.pdf) Platform Level Data Model (PLDM) Base Specification
- [DSP0242](https://www.dmtf.org/sites/default/files/standards/documents/DSP0242_1.0.1.pdf) Platform Level Data Model (PLDM) for File Transfer Specification
- [DSP0248](https://www.dmtf.org/sites/default/files/standards/documents/DSP0248_1.2.2.pdf) Platform Level Data Model (PLDM) for Platform 5 Monitoring and Control Specification
- [DSP0249](https://www.dmtf.org/sites/default/files/standards/documents/DSP0249_1.4.0.pdf) Platform Level Data Model (PLDM) State Set Specification
- [DSP0257](https://www.dmtf.org/sites/default/files/standards/documents/DSP0257_2.0.0.pdf) Platform Level Data Model (PLDM) for FRU Data Specification
- [DSP0267](https://www.dmtf.org/sites/default/files/standards/documents/DSP0267_1.2.0.pdf) Platform Level Data Model (PLDM) for Firmware Update Specification
- [DSP0283](https://www.dmtf.org/standards/mctp) [(MCTP Security)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0283_1.1.0.pdf)
- [DSP0218](https://www.dmtf.org/sites/default/files/standards/documents/DSP0218_1.2.0.pdf) Platform Level Data Model (PLDM) for Redfish Device Enablement

## Installation

### Requirements

- Python 3.10 or newer recommended
- pip
- scapy
- pytest

### Standard Install

```sh
python setup.py sdist
python -m pip install dist/pmci_protocol_validator-x.x.x.tar.gz
```

### Alternate Intall

From the repository root:

```sh
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pytest
```

Editable mode keeps imports bound to your working tree, so changes under `pmci_protocol_validator/` are immediately used without reinstalling.


### Optional: PYTHONPATH Environment Variable

For development, you can set `PYTHONPATH` to the repository root, for example `PYTHONPATH={your_path}/PMCI-Protocol-Validator/`. This imports the package from your working tree, but it only applies to the shell session where `PYTHONPATH` is set.

## Directory Structure

```text
pmci_protocol_validator/
	framework/   Core communication and test framework abstractions
	mctp/        MCTP message and constant definitions (DSP0236/DSP0237/DSP0238/DSP0239/DSP0253/DSP0283)
	ncsi/        NC-SI definitions (DSP0222)
	pldm/        PLDM message and PDR definitions (DSP0218/DSP0240/DSP0242/DSP0248/DSP0249/DSP0257/DSP0267)
	ptti/        DSP0280 protocol messages, transport, and helper function library

examples/
	test_service_emulator.py  Example DSP0280 Test Service emulator
	example_test_client.py    End-to-end client flow using raw packet composition
	example_test_client2.py   End-to-end client flow using helper library APIs

tests/
	class_checking/           Unit-style packet/class behavior tests
	dsp0280_protocol/         Protocol flow tests against a running test service
```

## Quick Start: Run the Example Service and Client

Open two terminals from the repository root.

Terminal 1: Start the emulator

```sh
python examples/test_service_emulator.py --tcp-addr 127.0.0.1 --tcp-port 49155
```

Terminal 2: Run a client sequence

```sh
python examples/example_test_client2.py --tcp-addr 127.0.0.1 --tcp-port 49155
```

You can also run the packet-composition example:

```sh
python examples/example_test_client.py --tcp-addr 127.0.0.1 --tcp-port 49155
```

### TLS Notes for Examples

By default, the Test Client exampless and Test Service Emulator use standard TCP communications. Command line parameters are necessary to enable TLS.

The Test Service Emulator in TLS mode expects both certificate and key paths to be specified:

```sh
python examples/test_service_emulator.py --tls-enable <cert.pem> <key.pem>
```

The Test Client examples in TLS mode requires a certificate path and an optional host name. The host name **MUST** match the host used to create the certificate.

```sh
python examples/example_test_client2.py --tls-enable <cert.pem> <hostname>
```

Host name verification may be disabled in the client examples using the `--tls-no-host-verify` command line option. If host name verificaiton is disabled, the hostname parameter to `--tls-enable` need not be specified. If specified, it will be ignored.

## PyTest Scripts

### class_checking/
Verifies packet class structure and default values.

```sh
pytest tests/class_checking
```

### dsp0280_protocol/
Basic tests to verify Test Client <-> Test Service communications and message processing. These tests expect a running Test Service at `localhost:49155`.

1. Start Test Service. In this case, the Test Service Emulator:

```sh
python examples/test_service_emulator.py --tcp-addr 127.0.0.1 --tcp-port 49155
```

2. In a separate terminal, run the PyTest scripts:

```sh
pytest tests/dsp0280_protocol
```
