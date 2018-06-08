import argparse
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
    parser.add_argument('--cert-type', default="rsa", help="[rsa|dsa]")
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
    cert_store.store_load()
    cert_info = None
    cert_type = crypto.TYPE_RSA if args.cert_type is "rsa" else crypto.TYPE_DSA

    if args.ca_name:
            ca_info = cert_store.store_get(args.ca_name)
            if ca_info:
                cert_info = cert_store.create_signed_pair(args.name, args.ca_name,
                        cert_type=cert_type, bits=args.bits, years=args.valid,
                        alt_names=args.alt_names)
            else:
                print("Must specify an exisiting authority to sign this cert.")
    else:
        cert_info = cert_store.create_ca(args.name,
                cert_type=cert_type, bits=args.bits, years=args.valid,
                alt_names=args.alt_names)

    cert_store.store_save()

    if cert_info:
        print(cert_info)
