# -*- coding: latin-1 -*-
#
# Copyright (C) AB Strakt
# Copyright (C) Jean-Paul Calderone
# Methods adapted from PyOpenssl's example cergen.py by Thomas Mendoza
# See LICENSE for details.

import os
import json
from OpenSSL import crypto
from collections import namedtuple

KeyCertPair = namedtuple("KeyCertPair", "name dirName keyFile certFile")

class Certipy():
    def __init__(self, storeDir="out", recordFile="store.json"):
        """
        Init the class

        Arguments: storeDir   - The base path to use for the store
                   recordFile - The name of the file to write store info
        Returns:   None
        """
        self.certs = {}
        self.storeDir = storeDir
        self.recordFile = recordFile

    def store_save(self):
        """
        Save a JSON file detailing certs known by certipy

        Arguments: None
        Returns:   None
        """
        filePath = "{}/{}".format(self.storeDir, self.recordFile)
        try:
            with open(filePath, 'w') as fh:
                fh.write(json.dumps(self.certs))
        except FileNotFoundError:
            print("Could not open file {} for writing.".format(filePath))

    def store_load(self):
        """
        Load a JSON file detailing certs known by certipy

        Arguments: None
        Returns:   None
        """
        filePath = "{}/{}".format(self.storeDir, self.recordFile)
        try:
            with open(filePath) as fh:
                certInfo = json.load(fh)
                for name, info in certInfo.items():
                    self.certs[name] = KeyCertPair(*info)

        except FileNotFoundError:
            print("Could not find or open store file at {}.".format(filePath))
        except TypeError as err:
            print("Problems loading store:", err)
        except ValueError as err:
            print("Problems loading store:", err)

    def store_get(self, name):
        """
        Get info about a cert in the store

        Arguments: name - The name of the cert to find
        Returns:   KeyCertPair object with location info
        """
        try:
            return self.certs[name]
        except KeyError:
            print("No certificates found with name {}".format(name))

    def dir_for_name(self, name):
        """
        Create a path string to a named directory

        Arguments: name - The name to use for the path
        Returns:   A path string
        """
        return "{}/{}".format(self.storeDir, name)

    def key_cert_pair_for_name(self, name, dirName="", keyFile="", certFile=""):
        if not dirName:
            dirName = "{}/{}".format(self.storeDir, name) 
        if not keyFile:
            keyFile = "{0}/{1}.key".format(dirName, name)
        if not certFile:
            certFile = "{0}/{1}.crt".format(dirName, name)
        return KeyCertPair(name, dirName, keyFile, certFile)

    def store_add(self, keyCertPair):
        """
        Add a cert reference to the store

        Arguments: keyCerPair - The KeyCertPair object to add
        Returns:   None
        """
        self.certs[keyCertPair.name] = keyCertPair

    def store_remove(self, name):
        """
        Remove a cert reference from the store

        Arguments: name - The name of the cert
        Returns:   None
        """
        try:
            del self.certs[name]
        except KeyError:
            print("No certificates found with name {}".format(name))

    def create_key_pair(self, certType, bits):
        """
        Create a public/private key pair.

        Arguments: type - Key type, must be one of TYPE_RSA and TYPE_DSA
                   bits - Number of bits to use in the key
        Returns:   The public/private key pair in a PKey object
        """
        pkey = crypto.PKey()
        pkey.generate_key(certType, bits)
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

    def sign(self, req, issuerCertKey, serial, validityPeriod, digest="sha256",
            extensions=None):
        """
        Generate a certificate given a certificate request.

        Arguments: req        - Certificate request to use
                   issuerCert - The certificate of the issuer
                   issuerKey  - The private key of the issuer
                   serial     - Serial number for the certificate
                   notBefore  - Timestamp (relative to now) when the certificate
                                starts being valid
                   notAfter   - Timestamp (relative to now) when the certificate
                                stops being valid
                   digest     - Digest method to use for signing, default is sha256
        Returns:   The signed certificate in an X509 object
        """
        issuerCert, issuerKey = issuerCertKey
        notBefore, notAfter = validityPeriod
        cert = crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(notBefore)
        cert.gmtime_adj_notAfter(notAfter)
        cert.set_issuer(issuerCert.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())

        if extensions:
            for ext in extensions:
                if callable(ext):
                    ext = ext(cert)
                cert.add_extensions([ext])

        cert.sign(issuerKey, digest)

        return cert

    def write_key_cert_pair(self, name, key, cert):
        """
        Write a key cert pair to individual files.

        Arguments: name - The name of the key-cert pair
                   key  - The X509 object key
                   cert - The X509 object cert
        Returns:   None
        """
        try:
            certInfo = self.key_cert_pair_for_name(name)
            os.makedirs(certInfo.dirName, mode=0o755,  exist_ok=True)
            with open(certInfo.keyFile, 'w') as fh:
                fh.write(
                    crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
                        .decode("utf-8")
                )

            with open(certInfo.certFile, 'w') as fh:
                fh.write(
                    crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
                        .decode("utf-8")
                )

            os.chmod(certInfo.keyFile, 0o600)
            os.chmod(certInfo.certFile, 0o644)

            self.store_add(certInfo)

        except FileNotFoundError as err:
            print("Could not write file:", err)

    def load_key_cert_pair(self, name):
        """
        Load a key cert pair to individual X509 objects

        Arguments: name - The name of the key-cert pair
        Returns:   (key, cert) tuple of X509 objects
        """
        key = None
        cert = None
        try:
            certInfo = self.store_get(name)
            with open(certInfo.keyFile) as fh:
                key = crypto.load_privatekey(crypto.FILETYPE_PEM, fh.read())
            with open(certInfo.certFile) as fh:
                cert = crypto.load_certificate(crypto.FILETYPE_PEM, fh.read())
            return (key, cert)
        except FileNotFoundError as err:
            print("Could not load file:", err)


    def create_ca(self, name, certType=crypto.TYPE_RSA, bits=2048,
            altNames=b""):
        """
        Create a self-signed certificate authority

        Arguments: name     - The name of the CA
                   certType - The type of the cert. TYPE_RSA or TYPE_DSA
                   bits     - The number of bits to use
                   altNames - A byte string of alternative names for the CA
        Returns:   None
        """
        cakey = self.create_key_pair(certType, bits)
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

        if altNames:
            extensions.append(
                crypto.X509Extension(b"subjectAltName", False, altNames)
            )

        cacert = self.sign(req, (req, cakey), 0, (0, 60*60*24*365*5),
                extensions=extensions)

        self.write_key_cert_pair(name, cakey, cacert)

    def create_signed_pair(self, name, caName, certType=crypto.TYPE_RSA,
            bits=2048, altNames=b""):
        """
        Create a key-cert pair

        Arguments: name     - The name of the key-cert pair
                   caName   - The name of the CA to sign this cert
                   certType - The type of the cert. TYPE_RSA or TYPE_DSA
                   bits     - The number of bits to use
                   altNames - A byte string of alternative names for this cert
        Returns:   None
        """
        key = self.create_key_pair(certType, bits)
        req = self.create_request(key, CN=name)
        extensions = [
            crypto.X509Extension(b"extendedKeyUsage", True,
                b"serverAuth, clientAuth"),
        ]

        if altNames:
            extensions.append(
                crypto.X509Extension(b"subjectAltName", False, altNames)
            )

        cakey, cacert = self.load_key_cert_pair(caName)
        cert = self.sign(req, (cacert, cakey), 0, (0, 60*60*24*365*5),
                extensions=extensions)

        self.write_key_cert_pair(name, key, cert)
