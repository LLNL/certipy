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
