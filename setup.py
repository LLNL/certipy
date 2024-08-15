###############################################################################
# Copyright (c) 2018, Lawrence Livermore National Security, LLC
# Produced at the Lawrence Livermore National Laboratory
# Written by Thomas Mendoza mendoza33@llnl.gov
# LLNL-CODE-754897
# All rights reserved
#
# This file is part of Certipy: https://github.com/LLNL/certipy
#
# SPDX-License-Identifier: BSD-3-Clause
###############################################################################

# Always prefer setuptools over distutils
from setuptools import setup, find_packages
# To use a consistent encoding
from codecs import open
from os import path
from setuptools import setup

try:
    from pypandoc import convert
    read_md = lambda f: convert(f, 'rst', 'md')
except ImportError:
    print("warning: pypandoc module not found, could not convert Markdown to RST")
    read_md = lambda f: f

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = read_md(f.read())

setup(
    name='certipy',

    version='0.1.3',

    description='Utility to create and sign CAs and certificates',
    long_description=long_description,

    url='https://github.com/LLNL/certipy',

    author='Thomas Mendoza',
    author_email='mendoza33@llnl.gov',

    license='BSD',

    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 4 - Beta',

        'Intended Audience :: Developers',
        'Topic :: Utilities',

        'License :: OSI Approved :: BSD License',

        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    keywords='pki ssl tls certificates',

    packages=find_packages(exclude=['contrib', 'docs', 'test']),

    install_requires=['cryptography', 'ipaddress'],

    extras_require={
        'dev': ['pytest'],
        'test': ['pytest'],
    },

    package_data={
    },

    data_files=[],

    entry_points={
        'console_scripts': [
            'certipy=certipy.command_line:main',
        ],
    },
)
