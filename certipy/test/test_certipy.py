import os
import pytest
import shutil
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

from ..certipy import Certipy

def test_dir_for_name():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        testPath = "{}/{}".format(td, name)

        assert c.dir_for_name(name) == testPath

def test_store_add():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        outDir = c.dir_for_name(name)
        c.store_add(name)

        assert name in c.certs

def test_store_get():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        outDir = c.dir_for_name(name)
        c.store_add(name)

        certInfo = c.store_get(name)

        assert certInfo.keyFile == "{}/{}.key".format(outDir, name)
        assert certInfo.certFile == "{}/{}.crt".format(outDir, name)

def test_store_remove():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        outDir = c.dir_for_name(name)
        c.store_add(name)
        certInfo = c.store_get(name)

        assert certInfo is not None

        c.store_remove(name)
        certInfo = c.store_get(name)

        assert certInfo is None

def test_store_save():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        c.store_add(name)
        c.store_save()

        assert os.stat("{}/store.json".format(td))

def test_store_load():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        outDir = c.dir_for_name(name)
        c.store_add(name)
        c.store_save()
        c.store_load()

        certInfo = c.store_get(name)

        assert certInfo.keyFile == "{}/{}.key".format(outDir, name)
        assert certInfo.certFile == "{}/{}.crt".format(outDir, name)

def test_create_ca():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        c.create_ca(name)
        certInfo = c.store_get(name)

        assert os.stat(certInfo.keyFile)
        assert os.stat(certInfo.certFile)

def test_create_key_pair():
    with TemporaryDirectory() as td:
        c = Certipy(storeDir=td)
        name = "foo"
        caName = "bar"
        c.create_ca(caName)
        c.create_signed_pair(name, caName)
        certInfo = c.store_get(name)

        assert os.stat(certInfo.keyFile)
        assert os.stat(certInfo.certFile)
