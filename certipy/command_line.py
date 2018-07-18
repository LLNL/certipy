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

import argparse
import shutil
import sys
from OpenSSL import crypto
from certipy import Certipy

def main():
    describe_certipy = """
        Certipy: Create simple, self-signed certificate authorities and certs.
    """
    parser = argparse.ArgumentParser(description=describe_certipy)
    parser.add_argument('name', help="""Name of the cert to create,
                                defaults to creating a CA cert. If no signing
                                --ca-name specified.""")
    parser.add_argument('--ca-name', help="The name of the CA to sign this cert."
                                , default="")
    parser.add_argument('--rm', action="store_true",
            help="Remove the cert specified by name.")
    parser.add_argument('--cert-type', default="rsa", choices=['rsa', 'dsa'],
            help="The type of cert to create.")
    parser.add_argument('--bits', type=int, default=2048,
                                help="The number of bits to use.")
    parser.add_argument('--valid', type=int, default=5,
                                help="Years the cert is valid for.")
    parser.add_argument('--alt-names', default="",
                                help="Alt names for the certificate.")
    parser.add_argument('--store-dir', default="out",
                                help="The location for the store and certs.")

    args = parser.parse_args()

    cert_store = Certipy(store_dir=args.store_dir)
    cert_info = None
    cert_type = crypto.TYPE_RSA if args.cert_type is "rsa" else crypto.TYPE_DSA

    if args.rm:
            cert_info = cert_store.get(args.name)
            if cert_info:
                shutil.rmtree(cert_info.dir_name)
                cert_store.remove(args.name)
            else:
                print("Unable to remove cert with name {}.".format(args.name))
            sys.exit(0)

    if args.ca_name:
            ca_info = cert_store.get(args.ca_name)
            if ca_info:
                cert_info = cert_store.create_signed_pair(args.name, args.ca_name,
                        cert_type=cert_type, bits=args.bits, years=args.valid,
                        alt_names=args.alt_names)
            else:
                print("CA {} not found. Must specify an exisiting authority to sign this cert.".format(args.ca_name))
    else:
        cert_info = cert_store.create_ca(args.name,
                cert_type=cert_type, bits=args.bits, years=args.valid,
                alt_names=args.alt_names)

    if cert_info:
        print(cert_info)
