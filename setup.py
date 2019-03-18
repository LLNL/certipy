###############################################################################
# Copyright (c) 2018, Lawrence Livermore National Security, LLC
# Produced at the Lawrence Livermore National Laboratory
# Written by Thomas Mendoza mendoza33@llnl.gov
# LLNL-CODE-754897
# All rights reserved
#
# This file is part of Certipy. For details, see
# https://github.com/LLNL/certipy. Please also read this link - Additional
# BSD Notice.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the disclaimer below.
#     * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the disclaimer (as noted below) in
#     the documentation and/or other materials provided with the distribution.
#     * Neither the name of the LLNS/LLNL nor the names of its contributors may
#     be used to endorse or promote products derived from this software without
#     specific prior written permission.
#
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL LAWRENCE LIVERMORE NATIONAL SECURITY, LLC,
# THE U.S. DEPARTMENT OF ENERGY OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#
# Additional BSD Notice
#
# 1. This notice is required to be provided under our contract with the U.S.
# Department of Energy (DOE). This work was produced at Lawrence Livermore
# National Laboratory under Contract No. DE-AC52-07NA27344 with the DOE.
#
# 2. Neither the United States Government nor Lawrence Livermore National
# Security, LLC nor any of their employees, makes any warranty, express or
# implied, or assumes any liability or responsibility for the accuracy,
# completeness, or usefulness of any information, apparatus, product,
# or process disclosed, or represents that its use would not infringe
# privately-owned rights.
#
# 3. Also, reference herein to any specific commercial products, process, or
# services by trade name, trademark, manufacturer or otherwise does not
# necessarily constitute or imply its endorsement, recommendation, or favoring
# by the United States Government or Lawrence Livermore National Security, LLC.
# The views and opinions of authors expressed herein do not necessarily state
# or reflect those of the United States Government or Lawrence Livermore
# National Security, LLC, and shall not be used for advertising or product
# endorsement purposes.
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

    install_requires=['pyopenssl'],

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
