import argparse
import asn1tools
from utils import x509
from utils import io
from utils import crypto

VALID_ASN_FILE = 'valid.asn'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root_key_file')
    parser.add_argument('--root_cert_file')
    parser.add_argument('--asn_dir')
    args = parser.parse_args()

    # Compile the ASN.1 specification
    asn = asn1tools.compile_files(args.asn_dir + VALID_ASN_FILE, 'der')

    # Generate an RSA public key pair
    (privkey, pubkey) = crypto.new_rsa_keypair(2048)

    # Export key so other certs can be signed with it
    io.export_private_key(privkey, args.root_key_file)

    # Encode tbsCertificate
    tbs = x509.default_tbs(issuer_public_key=pubkey,
                           subject_public_key=pubkey,
                           issuer_cn='root',
                           subject_cn='root',
                           is_ca=True,
                           additional_extensions=[],
                           asn=asn)
    tbs_der = asn.encode('TBSCertificate', tbs)

    # Sign the tbsCertificate
    sig = crypto.rsa_sha256_sign(privkey, tbs_der)

    # Create the certificate
    cert_der = x509.certificate(tbs, sig, asn)

    # Write the certificate into file
    io.export_cert(cert_der, args.root_cert_file)


if __name__ == "__main__":
    main()
