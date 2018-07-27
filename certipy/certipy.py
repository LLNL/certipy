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
import json
import argparse
import logging
from OpenSSL import crypto
from collections import namedtuple

KeyCertPair = namedtuple("KeyCertPair", "name dir_name key_file cert_file ca_file")

class Certipy():
    def __init__(self, store_dir="out", record_file="store.json",
            log_file=None, log_level=logging.WARN):
        """
        Init the class

        Arguments: store_dir   - The base path to use for the store
                   record_file - The name of the file to write store info
        Returns:   None
        """
        self.certs = {}
        self.store_dir = store_dir
        self.record_file = record_file
        self.serial = 0
        logging.basicConfig(filename=log_file, level=log_level)
        self.log = logging.getLogger('Certipy')
        self._load()

    def _save(self):
        """
        Save a JSON file detailing certs known by certipy

        Arguments: None
        Returns:   None
        """
        file_path = "{}/{}".format(self.store_dir, self.record_file)
        try:
            with open(file_path, 'w') as fh:
                out = {}
                out['serial'] = self.serial
                out['cert_info'] = self.certs
                fh.write(json.dumps(out))
        except FileNotFoundError:
            self.log.warn("Could not open file {} for writing.".format(file_path))

    def _load(self):
        """
        Load a JSON file detailing certs known by certipy

        Arguments: None
        Returns:   None
        """
        file_path = "{}/{}".format(self.store_dir, self.record_file)
        try:
            with open(file_path) as fh:
                store = json.load(fh)
                self.serial = store['serial']
                cert_info = store['cert_info']
                for name, info in cert_info.items():
                    self.certs[name] = KeyCertPair(*info)

        except FileNotFoundError:
            self.log.info("No store file at {}. Creating a new one.".format(file_path))
            os.makedirs(self.store_dir, mode=0o755,  exist_ok=True)
        except TypeError as err:
            self.log.warn("Problems loading store:", err)
        except ValueError as err:
            self.log.warn("Problems loading store:", err)

    def get(self, name):
        """
        Get info about a cert in the store

        Arguments: name - The name of the cert to find
        Returns:   KeyCertPair object with location info
        """
        try:
            info = self.certs[name]
            dir_name = os.path.abspath(info.dir_name)
            cert_file = os.path.abspath(info.cert_file)
            key_file = os.path.abspath(info.key_file)
            ca_file = os.path.abspath(info.ca_file)
            info_copy = KeyCertPair(info.name, dir_name, key_file, cert_file, ca_file)

            return info_copy
        except KeyError:
            self.log.warn("No certificates found with name {}".format(name))

    def key_cert_pair_for_name(self, name, dir_name="", key_file="", cert_file="", ca_file=""):
        if not dir_name:
            dir_name = "{}/{}".format(self.store_dir, name)
        if not key_file:
            key_file = "{0}/{1}.key".format(dir_name, name)
        if not cert_file:
            cert_file = "{0}/{1}.crt".format(dir_name, name)
        if not ca_file:
            ca_file = cert_file
        return KeyCertPair(name, dir_name, key_file, cert_file, ca_file)

    def add(self, keyCertPair):
        """
        Add a cert reference to the store

        Arguments: keyCerPair - The KeyCertPair object to add
        Returns:   None
        """
        self.certs[keyCertPair.name] = keyCertPair
        self._save()

    def remove(self, name):
        """
        Remove a cert reference from the store

        Arguments: name - The name of the cert
        Returns:   None
        """
        try:
            del self.certs[name]
            self._save()
        except KeyError:
            self.log.warn("No certificates found with name {}".format(name))

    def create_key_pair(self, cert_type, bits):
        """
        Create a public/private key pair.

        Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
                   bits - Number of bits to use in the key
        Returns:   The public/private key pair in a PKey object
        """
        pkey = crypto.PKey()
        pkey.generate_key(cert_type, bits)
        return pkey

    def create_request(self, pkey, digest="sha256", **name):
        """
        Create a certificate request.

        Arguments: pkey   - The key to associate with the request
                   digest - Digestion method to use for signing, default is sha256
                   exts   - X509 extensions see:
                            https://www.openssl.org/docs/manmaster/man5/
                            x509v3_config.html#STANDARD-EXTENSIONS
                            Dict in format:
                            key -> (val, critical)
                   **name - The name of the subject of the request, possible
                            arguments are:
                              C     - Country name
                              ST    - State or province name
                              L     - Locality name
                              O     - Organization name
                              OU    - Organizational unit name
                              CN    - Common name
                              emailAddress - E-mail address


        Returns:   The certificate request in an X509Req object
        """
        req = crypto.X509Req()
        subj = req.get_subject()

        if name is not None:
            for key, value in name.items():
                setattr(subj, key, value)

        req.set_pubkey(pkey)
        req.sign(pkey, digest)
        return req

    def sign(self, req, issuer_cert_key, validity_period, digest="sha256",
            extensions=None):
        """
        Generate a certificate given a certificate request.

        Arguments: req        - Certificate request to use
                   issuer_cert - The certificate of the issuer
                   issuer_key  - The private key of the issuer
                   not_before  - Timestamp (relative to now) when the certificate
                                starts being valid
                   not_after   - Timestamp (relative to now) when the certificate
                                stops being valid
                   digest     - Digest method to use for signing, default is sha256
        Returns:   The signed certificate in an X509 object
        """
        issuer_cert, issuer_key = issuer_cert_key
        not_before, not_after = validity_period
        cert = crypto.X509()
        cert.set_serial_number(self.serial)
        cert.gmtime_adj_notBefore(not_before)
        cert.gmtime_adj_notAfter(not_after)
        cert.set_issuer(issuer_cert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())

        self.serial += 1

        if extensions:
            for ext in extensions:
                if callable(ext):
                    ext = ext(cert)
                cert.add_extensions([ext])

        cert.sign(issuer_key, digest)

        return cert

    def write_key_cert_pair(self, name, key, cert, signing_cert=''):
        """
        Write a key cert pair to individual files.

        Arguments: name - The name of the key-cert pair
                   key  - The X509 object key
                   cert - The X509 object cert
        Returns:   None
        """
        try:
            cert_info = self.key_cert_pair_for_name(name, ca_file=signing_cert)
            os.makedirs(cert_info.dir_name, mode=0o755,  exist_ok=True)
            with open(cert_info.key_file, 'w') as fh:
                fh.write(
                    crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
                        .decode("utf-8")
                )

            with open(cert_info.cert_file, 'w') as fh:
                fh.write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                        .decode("utf-8")
                )

            os.chmod(cert_info.key_file, 0o600)
            os.chmod(cert_info.cert_file, 0o644)

            self.add(cert_info)
            self._save()
            return cert_info

        except FileNotFoundError as err:
            self.log.warn("Could not write file:", err)

    def load_key_cert_pair(self, name):
        """
        Load a key cert pair to individual X509 objects

        Arguments: name - The name of the key-cert pair
        Returns:   (key, cert) tuple of X509 objects
        """
        key = None
        cert = None
        try:
            cert_info = self.get(name)
            with open(cert_info.key_file) as fh:
                key = crypto.load_privatekey(crypto.FILETYPE_PEM, fh.read())
            with open(cert_info.cert_file) as fh:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, fh.read())
            return (key, cert)
        except FileNotFoundError as err:
            self.log.warn("Could not load file:", err)
            raise

    def create_ca_bundle(self, ca_names, bundle_name):
        """
        Create a bundle of CA public certs for trust distribution

        Arguments: ca_names    - The names of CAs to include in the bundle
                   bundle_name - The name of the bundle file to output
        Returns:   Path to the bundle file
        """
        ca_certs = []
        for name in ca_names:
            cert = self.load_key_cert_pair(name)[1]
            if cert:
                ca_certs.append(cert)

        bundle = "".join(
                    [crypto.dump_certificate(crypto.FILETYPE_PEM, cert)\
                        .decode("utf-8") for cert in ca_certs]
                 )
        file_path = "{out}/{name}.crt".format(out=self.store_dir,
                name=bundle_name)
        try:
            with open(file_path, 'w') as fh:
                fh.write(bundle)
            return file_path
        except FileNotFoundError as err:
            self.log.warn("Could not open {} for writing:".format(file_path),
                    err)

    def create_ca(self, name, cert_type=crypto.TYPE_RSA, bits=2048,
            alt_names=b"", years=5):
        """
        Create a self-signed certificate authority

        Arguments: name     - The name of the CA
                   cert_type - The type of the cert. TYPE_RSA or TYPE_DSA
                   bits     - The number of bits to use
                   alt_names - A byte string of alternative names for the CA
        Returns:   KeyCertPair for the new CA
        """
        cakey = self.create_key_pair(cert_type, bits)
        req = self.create_request(cakey, CN=name)
        extensions = [
            crypto.X509Extension(b"basicConstraints", True,
                b"CA:true, pathlen:0"),
            crypto.X509Extension(b"keyUsage", True,
                b"keyCertSign, cRLSign"),
            crypto.X509Extension(b"extendedKeyUsage", True,
                b"serverAuth, clientAuth"),
            lambda cert: crypto.X509Extension(b"subjectKeyIdentifier", False,
                b"hash", subject=cert),
            lambda cert: crypto.X509Extension(b"authorityKeyIdentifier", False,
                b"keyid:always", issuer=cert),
        ]

        if alt_names:
            extensions.append(
                crypto.X509Extension(b"subjectAltName", False, alt_names)
            )

        cacert = self.sign(req, (req, cakey), (0, 60*60*24*365*years),
                extensions=extensions)

        self.write_key_cert_pair(name, cakey, cacert)
        return self.get(name)

    def create_signed_pair(self, name, ca_name, cert_type=crypto.TYPE_RSA,
            bits=2048, years=5, alt_names=b""):
        """
        Create a key-cert pair

        Arguments: name     - The name of the key-cert pair
                   ca_name   - The name of the CA to sign this cert
                   cert_type - The type of the cert. TYPE_RSA or TYPE_DSA
                   bits     - The number of bits to use
                   alt_names - A byte string of alternative names for this cert
        Returns:   KeyCertPair for the new signed pair
        """
        key = self.create_key_pair(cert_type, bits)
        req = self.create_request(key, CN=name)
        extensions = [
            crypto.X509Extension(b"extendedKeyUsage", True,
                b"serverAuth, clientAuth"),
        ]

        if alt_names:
            extensions.append(
                crypto.X509Extension(b"subjectAltName", False, alt_names)
            )

        cakey, cacert = self.load_key_cert_pair(ca_name)
        cert = self.sign(req, (cacert, cakey), (0, 60*60*24*365*years),
                extensions=extensions)

        ca_info = self.get(ca_name)
        self.write_key_cert_pair(name, key, cert, signing_cert=ca_info.ca_file)
        return self.get(name)
