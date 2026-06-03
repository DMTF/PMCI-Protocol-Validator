# PMCI-Protocol-Validator

Copyright 2023-2026 DMTF. All rights reserved.

## About

The PMCI-Protocol-Validator is a Python/Scapy based tool set that can be used to issue PMCI protocol messages to target devices. Its architecture is based on DSP0280.

Currently implemented specifications:
* [DSP0280](https://www.dmtf.org/sites/default/files/standards/documents/DSP0280_1.0.0.pdf)
* [DSP0222](https://www.dmtf.org/sites/default/files/standards/documents/DSP0222_1.1.1.pdf)
* [DSP0240](https://www.dmtf.org/sites/default/files/standards/documents/DSP0240_1.1.0.pdf)
* [DSP0248](https://www.dmtf.org/sites/default/files/standards/documents/DSP0248_1.2.2.pdf)
* [DSP0267](https://www.dmtf.org/sites/default/files/standards/documents/DSP0267_1.2.0.pdf)

## Installation

### System Installation

Install [Python 3](https://www.python.org/downloads/) and [pip](https://pip.pypa.io/en/stable/installing/).

Clone this repository and build the source distribution:

```sh
python setup.py sdist
```

Install the generated source distribution:

```sh
python -m pip install dist/pmci_protocol_validator-x.x.x.tar.gz
```

### Development Installation

For development, install the package in editable mode from the repository root:

```sh
python -m pip install -e .
```

> **Note:** In editable mode, Python imports the package from your working tree
> instead of copying it into site-packages. So if you edit files under
> `pmci_protocol_validator/`, those changes are immediately reflected without
> reinstalling.
>
> As an alternative for development, you can set `PYTHONPATH` to the repository
> root, for example `PYTHONPATH={your_path}/PMCI-Protocol-Validator/`. This
> also imports the package from your working tree, but it only applies to the
> shell session or command where `PYTHONPATH` is set.

### Pytest

To run tests, install [PyTest](https://docs.pytest.org/en/stable/getting-started.html):

```sh
python -m pip install pytest
```
