#!/usr/bin/env python

import os
from setuptools import setup
from setuptools_rust import Binding, RustExtension


def find_stubs(package):
    stubs = ["py.typed"]
    for root, _, files in os.walk(package):
        for file in files:
            if ".pyi" not in file:
                continue
            path = os.path.join(root, file).replace(package + os.sep, "", 1)
            stubs.append(path)
    return {package: stubs}


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="signal-protocol",
    version="0.2.3-alpha1",
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)",
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Rust",
    ],
    description="Rust extension providing Python bindings to the signal protocol",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=["signal_protocol"],
    rust_extensions=[
        RustExtension(
            "signal_protocol.signal_protocol", "Cargo.toml", binding=Binding.PyO3
        )
    ],
    setup_requires=["setuptools-rust", "wheel"],
    package_data=find_stubs("signal_protocol"),
    zip_safe=False,  # Rust extensions are not zip safe
)
