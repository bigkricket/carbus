import os
import subprocess as sp

from setuptools import find_packages, setup

setup(
    name="carbus",
    version="1.0-1",
    author="Ruben Perez",
    author_email="perezben37@gmail.com",
    description="Package to decode and work with OBD2 diagnostics",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
)