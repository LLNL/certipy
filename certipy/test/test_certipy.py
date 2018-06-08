import os
import pytest
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

from ..certipy import Certipy

def test_key_cert_pair_for_name():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        testPath = "{}/{}".format(td, name)
        certInfo = c.key_cert_pair_for_name(name)

        assert certInfo.dirName == testPath

def test_store_add():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        certInfo = c.key_cert_pair_for_name(name)
        c.store_add(certInfo)

        assert name in c.certs

def test_store_get():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        certInfo = c.key_cert_pair_for_name(name)
        c.store_add(certInfo)

        loadedInfo = c.store_get(name)

        assert loadedInfo.key_file == "{}/{}.key".format(certInfo.dirName, name)
        assert loadedInfo.cert_file == "{}/{}.crt".format(certInfo.dirName, name)

def test_store_remove():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        certInfo = c.key_cert_pair_for_name(name)
        c.store_add(certInfo)
        certInfo = c.store_get(name)

        assert certInfo is not None

        c.store_remove(name)
        certInfo = c.store_get(name)

        assert certInfo is None

def test_store_save():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        certInfo = c.key_cert_pair_for_name(name)
        c.store_add(certInfo)
        c.store_save()

        assert os.stat("{}/store.json".format(td))

def test_store_load():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        certInfo = c.key_cert_pair_for_name(name)
        c.store_add(certInfo)
        c.store_save()
        c.store_load()

        loadedInfo = c.store_get(name)

        assert loadedInfo.key_file == "{}/{}.key".format(certInfo.dirName, name)
        assert loadedInfo.cert_file == "{}/{}.crt".format(certInfo.dirName, name)

def test_create_ca():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        certInfo = c.create_ca(name)

        assert os.stat(certInfo.key_file)
        assert os.stat(certInfo.cert_file)

def test_create_key_pair():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        ca_name = "bar"
        c.create_ca(ca_name)
        certInfo = c.create_signed_pair(name, ca_name)

        assert os.stat(certInfo.key_file)
        assert os.stat(certInfo.cert_file)
