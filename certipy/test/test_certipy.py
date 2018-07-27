###############################################################################
# Copyright (c) 2018, Lawrence Livermore National Security, LLC
# Produced at the Lawrence Livermore National Laboratory
# Written by Thomas Mendoza mendoza33@llnl.gov
# LLNL-CODE-754897
# All rights reserved
#  
# This file is part of Certipy. For details, see https://github.com/LLNL/certipy.
# Please also read this link - Additional BSD Notice.
#  
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#  
#     * Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the disclaimer below.  
#     * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the disclaimer (as noted below) in the
#     documentation and/or other materials provided with the distribution.  
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
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
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
# The views and opinions of authors expressed herein do not necessarily state or
# reflect those of the United States Government or Lawrence Livermore National
# Security, LLC, and shall not be used for advertising or product endorsement
# purposes.
###############################################################################

import os
import pytest
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

from ..certipy import Certipy

def test_key_cert_pair_for_name():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        name = "foo"
        test_path = "{}/{}".format(td, name)
        cert_info = c.key_cert_pair_for_name(name)

        assert cert_info.dir_name == test_path

def test_store_add():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        name = "foo"
        cert_info = c.key_cert_pair_for_name(name)
        c.add(cert_info)

        assert name in c.certs

def test_store_get():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        name = "foo"
        cert_info = c.key_cert_pair_for_name(name)
        c.add(cert_info)

        loadedInfo = c.get(name)

        assert loadedInfo.key_file == "{}/{}.key".format(cert_info.dir_name, name)
        assert loadedInfo.cert_file == "{}/{}.crt".format(cert_info.dir_name, name)

def test_store_remove():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        name = "foo"
        cert_info = c.key_cert_pair_for_name(name)
        c.add(cert_info)
        cert_info = c.get(name)

        assert cert_info is not None

        c.remove(name)
        cert_info = c.get(name)

        assert cert_info is None

def test_store_save():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        name = "foo"
        cert_info = c.key_cert_pair_for_name(name)
        c.add(cert_info)

        assert os.stat("{}/store.json".format(td))

def test_store_load():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        name = "foo"
        cert_info = c.key_cert_pair_for_name(name)
        c.add(cert_info)

        loadedInfo = c.get(name)

        assert loadedInfo.key_file == "{}/{}.key".format(cert_info.dir_name, name)
        assert loadedInfo.cert_file == "{}/{}.crt".format(cert_info.dir_name, name)

def test_create_ca():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        name = "foo"
        cert_info = c.create_ca(name)

        assert os.stat(cert_info.key_file)
        assert os.stat(cert_info.cert_file)

def test_create_ca_bundle():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        name1 = "foo"
        name2 = "bar"
        cert_info1 = c.create_ca(name1)
        cert_info2 = c.create_ca(name2)
        bundle_file = c.create_ca_bundle([name1, name2], 'bundle')
        with open(bundle_file) as bundle_handle,\
             open(cert_info1.cert_file) as cert1_handle,\
             open(cert_info2.cert_file) as cert2_handle:
            bundle = bundle_handle.read()
            cert1 = cert1_handle.read()
            cert2 = cert2_handle.read()
            assert cert1 in bundle
            assert cert2 in bundle

def test_create_key_pair():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        name = "foo"
        ca_name = "bar"
        c.create_ca(ca_name)
        cert_info = c.create_signed_pair(name, ca_name)

        assert os.stat(cert_info.key_file)
        assert os.stat(cert_info.cert_file)

def test_increment_serial():
    with TemporaryDirectory() as td:
        c = Certipy(store_dir=td)
        ca_name = "bar"
        c.create_ca(ca_name)
        for name in ['foo', 'bar', 'baz']:
            cert_info = c.create_signed_pair(name, ca_name)

        assert c.serial == 4
