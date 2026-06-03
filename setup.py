# Copyright Notice:
# Copyright 2023-2026 DMTF. All rights reserved.
# License: BSD 3-Clause License. For full text see link:
# https://github.com/DMTF/PMCI-Protocol-Validator/blob/main/LICENSE.md

from codecs import open
from setuptools import find_packages, setup

with open("README.md", "r", "utf-8") as f:
    long_description = f.read()

setup(
    name="pmci_protocol_validator",
    version="0.1.0",
    description="PMCI Protocol Validator",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="DMTF, https://www.dmtf.org/standards/feedback",
    license="BSD 3-Clause",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Topic :: Communications",
    ],
    url="https://github.com/DMTF/PMCI-Protocol-Validator",
    packages=find_packages(
        include=[
            "pmci_protocol_validator",
            "pmci_protocol_validator.*",
        ]
    ),
    install_requires=[
        "scapy",
    ],
)
