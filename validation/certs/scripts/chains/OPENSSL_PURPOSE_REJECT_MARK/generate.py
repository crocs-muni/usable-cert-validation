import asn1tools
import os
from utils import x509
from utils import io
from utils import misc
from utils import crypto

VALID_ASN_FILE = 'valid.asn'
EXPORTED_KEY_NAME = 'key.pem'
EXPORTED_CHAIN_NAME = 'chain.pem'


def extended_key_usage_server(asn):
    return x509.ext_key_usage(['id-kp-serverAuth'], asn)


def main():
    args = misc.parse_arguments()

    # Compile the ASN.1 specification
    asn = asn1tools.compile_files(args.asn_dir + VALID_ASN_FILE, 'der')

    # Import the root private key and cert
    (root_privkey, root_pubkey) = crypto.new_rsa_keypair(2048)

    # Encode root tbsCertificate
    root_tbs = x509.default_tbs(issuer_public_key=root_pubkey,
                                subject_public_key=root_pubkey,
                                issuer_cn='root',
                                subject_cn='root',
                                is_ca=True,
                                additional_extensions=[],
                                asn=asn)
    root_tbs_der = asn.encode('TBSCertificate', root_tbs)

    # Sign the root tbsCertificate
    root_sig = crypto.rsa_sha256_sign(root_privkey, root_tbs_der)

    # Encode the root CA Certificate
    root_cert_der = x509.certificate(root_tbs, root_sig, asn)

    # Generate an RSA public key pair for intermediate CA
    (sub_privkey, sub_pubkey) = crypto.new_rsa_keypair(2048)

    # Encode intermediate tbsCertificate
    sub_tbs = x509.default_tbs(issuer_public_key=root_pubkey,
                               subject_public_key=sub_pubkey,
                               issuer_cn='root',
                               subject_cn='intermediate',
                               is_ca=True,
                               additional_extensions=[],
                               asn=asn)
    sub_tbs_der = asn.encode('TBSCertificate', sub_tbs)

    # Sign the intermediate tbsCertificate
    sub_sig = crypto.rsa_sha256_sign(root_privkey, sub_tbs_der)

    # Encode the intermediate CA Certificate
    sub_cert_der = x509.certificate(sub_tbs, sub_sig, asn)

    # Generate an RSA public key pair for end entity certificate
    (end_privkey, end_pubkey) = crypto.new_rsa_keypair(2048)

    # Extended key usage
    ext_key_usage = extended_key_usage_server(asn)

    # Encode end entity tbsCertificate
    end_tbs = x509.default_tbs(issuer_public_key=sub_pubkey,
                               subject_public_key=end_pubkey,
                               issuer_cn='intermediate',
                               subject_cn='localhost',
                               is_ca=False,
                               additional_extensions=[ext_key_usage],
                               asn=asn)
    end_tbs_der = asn.encode('TBSCertificate', end_tbs)

    # Sign the end entity tbsCertificate
    end_sig = crypto.rsa_sha256_sign(sub_privkey, end_tbs_der)

    # Encode the end entity Certificate
    end_cert_der = x509.certificate(end_tbs, end_sig, asn)

    # Write the chain into file
    io.export_chain([end_cert_der, sub_cert_der],
                    args.build_dir + EXPORTED_CHAIN_NAME)

    rt = args.build_dir + 'marked_root.pem'

    io.export_cert(root_cert_der, rt)
    os.system('openssl x509 -addreject serverAuth -in ' + rt + ' -out ' + rt)

    # Export the private key
    io.export_private_key(end_privkey, args.build_dir + EXPORTED_KEY_NAME)


if __name__ == "__main__":
    main()
