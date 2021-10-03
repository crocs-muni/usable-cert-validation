import asn1tools
from utils import x509
from utils import io
from utils import misc
from utils import crypto

VALID_ASN_FILE = 'valid.asn'
EXPORTED_KEY_NAME = 'key.pem'
EXPORTED_CHAIN_NAME = 'chain.pem'


def nonsense_name_constraints(asn):
    name = {
        'type-id': '1.2.3.4.5',
        'value': b'\xff\xff'
    }
    constraint = x509.general_subtree(('otherName', name))
    return x509.name_constraints(asn, permitted=[constraint])


def nonsense_san(asn):
    name = {
        'type-id': '1.2.3.4.5',
        'value': b'\xff\xff'
    }
    return x509.subject_alt_name([('otherName', name)], asn)


def main():
    args = misc.parse_arguments()

    # Compile the ASN.1 specification
    asn = asn1tools.compile_files(args.asn_dir + VALID_ASN_FILE, 'der')

    # Import the root private key and cert
    root_privkey = io.import_rsa_private_key(args.root_key_file)
    root_pubkey = root_privkey.publickey()

    # Generate an RSA public key pair for intermediate CA
    (sub_privkey, sub_pubkey) = crypto.new_rsa_keypair(2048)

    # Create empty nc extension
    nc = nonsense_name_constraints(asn)

    # Encode intermediate tbsCertificate
    sub_tbs = x509.default_tbs(issuer_public_key=root_pubkey,
                               subject_public_key=sub_pubkey,
                               issuer_cn='root',
                               subject_cn='intermediate',
                               is_ca=True,
                               additional_extensions=[nc],
                               asn=asn)
    sub_tbs_der = asn.encode('TBSCertificate', sub_tbs)

    # Sign the intermediate tbsCertificate
    sub_sig = crypto.rsa_sha256_sign(root_privkey, sub_tbs_der)

    # Encode the intermediate CA Certificate
    sub_cert_der = x509.certificate(sub_tbs, sub_sig, asn)

    # Generate an RSA public key pair for end entity certificate
    (end_privkey, end_pubkey) = crypto.new_rsa_keypair(2048)

    # Creaa a SAN extension with a single IP
    san = nonsense_san(asn)

    # Encode end entity tbsCertificate
    end_tbs = x509.default_tbs(issuer_public_key=sub_pubkey,
                               subject_public_key=end_pubkey,
                               issuer_cn='intermediate',
                               subject_cn='localhost',
                               is_ca=False,
                               additional_extensions=[san],
                               asn=asn)
    end_tbs_der = asn.encode('TBSCertificate', end_tbs)

    # Sign the end entity tbsCertificate
    end_sig = crypto.rsa_sha256_sign(sub_privkey, end_tbs_der)

    # Encode the end entity Certificate
    end_cert_der = x509.certificate(end_tbs, end_sig, asn)

    # Write the chain into file
    io.export_chain([end_cert_der, sub_cert_der],
                    args.build_dir + EXPORTED_CHAIN_NAME)

    # Export the private key
    io.export_private_key(end_privkey, args.build_dir + EXPORTED_KEY_NAME)


if __name__ == "__main__":
    main()
