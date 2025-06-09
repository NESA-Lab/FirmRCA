#!/usr/bin/env python
"""
    Python package for the fuzzware emulator.
"""
import os
import subprocess
import sys
from distutils.command.build import build

from setuptools import setup


class Build(build):
    """Customized setuptools build command - builds native unicorn bindings on build."""
    def run(self):
        protoc_command = ["make", "-C", "fuzzware_harness/native", "clean", "all"]
        if subprocess.call(protoc_command) != 0:
            sys.exit(-1)
        build.run(self)

def get_packages(rel_dir):
    packages = [rel_dir]
    for x in os.walk(rel_dir):
        # break into parts
        base = list(os.path.split(x[0]))
        if base[0] == "":
            del base[0]

        for mod_name in x[1]:
            packages.append(".".join(base + [mod_name]))

    return packages


setup(name='fuzzware_harness',
    version='0.1',
    description='This is the Python library and native modules for the Fuzzware emulation component',
    author='Tobias Scharnowski, Eric Gustafson',
    author_email='tobias.scharnowski@rub.de, edg@cs.ucsb.edu',
    url='https://github.com/RUB-SysSec',
    packages=get_packages('fuzzware_harness'), requires=['PyYAML','intelhex', 'monkeyhex'],
    include_package_data=True,
    cmdclass = {
      'build': Build,
    },
    entry_points = {
        'console_scripts': [
            'fuzzware_harness = fuzzware_harness.harness:main',
        ]
    }
)
