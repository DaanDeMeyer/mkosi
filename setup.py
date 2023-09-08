#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1+

from setuptools import setup, find_packages

setup(
    name="mkosi",
    version="16",
    description="Build Bespoke OS Images",
    url="https://github.com/systemd/mkosi",
    maintainer="mkosi contributors",
    maintainer_email="systemd-devel@lists.freedesktop.org",
    license="LGPLv2+",
    python_requires=">=3.9",
    packages = find_packages(".", exclude=["tests"]),
    package_data = {"": ['*.conf', 'mkosi.md', 'mkosi.1']},
    include_package_data = True,
    entry_points = { "console_scripts": ["mkosi = mkosi.__main__:main"] },
)
