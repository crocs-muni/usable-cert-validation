import asn1tools
from utils import x509
from utils import io
from utils import misc
from utils import crypto

VALID_ASN_FILE = 'valid.asn'
EXPORTED_KEY_NAME = 'key.pem'
EXPORTED_CHAIN_NAME = 'chain.pem'


def set_path_len_constraint_0(tbs, asn):
    new_bc = x509.basic_constraints(True, asn, 0)
    extensions = tbs['extensions']
    tbs['extensions'] = [new_bc
                         if ext['extnID'] == x509.oid_map['basicConstraints']
                         else ext
                         for ext in extensions]


def main():
    args = misc.parse_arguments()

    # Compile the ASN.1 specification
    asn = asn1tools.compile_files(args.asn_dir + VALID_ASN_FILE, 'der')

    # Import the root private key and cert
    root_privkey = io.import_rsa_private_key(args.root_key_file)
    root_pubkey = root_privkey.publickey()

    # Generate an RSA public key pair for intermediate CA
    (sub1_privkey, sub1_pubkey) = crypto.new_rsa_keypair(2048)

    # Encode intermediate tbsCertificate
    sub1_tbs = x509.default_tbs(issuer_public_key=root_pubkey,
                                subject_public_key=sub1_pubkey,
                                issuer_cn='root',
                                subject_cn='intermediate1',
                                is_ca=True,
                                additional_extensions=[],
                                asn=asn)

    # Set pathLenConstraint to 0 in the first intermediate CA
    set_path_len_constraint_0(sub1_tbs, asn)

    sub1_tbs_der = asn.encode('TBSCertificate', sub1_tbs)

    # Sign the intermediate tbsCertificate
    sub1_sig = crypto.rsa_sha256_sign(root_privkey, sub1_tbs_der)

    # Encode the intermediate CA Certificate
    sub1_cert_der = x509.certificate(sub1_tbs, sub1_sig, asn)

    # Generate an RSA public key pair for intermediate CA
    (sub2_privkey, sub2_pubkey) = crypto.new_rsa_keypair(2048)

    # Encode intermediate tbsCertificate
    sub2_tbs = x509.default_tbs(issuer_public_key=sub1_pubkey,
                                subject_public_key=sub2_pubkey,
                                issuer_cn='intermediate1',
                                subject_cn='intermediate2',
                                is_ca=True,
                                additional_extensions=[],
                                asn=asn)
    sub2_tbs_der = asn.encode('TBSCertificate', sub2_tbs)

    # Sign the intermediate tbsCertificate
    sub2_sig = crypto.rsa_sha256_sign(sub1_privkey, sub2_tbs_der)

    # Encode the intermediate CA Certificate
    sub2_cert_der = x509.certificate(sub2_tbs, sub2_sig, asn)

    # Generate an RSA public key pair for end entity certificate
    (end_privkey, end_pubkey) = crypto.new_rsa_keypair(2048)

    # Encode end entity tbsCertificate
    end_tbs = x509.default_tbs(issuer_public_key=sub2_pubkey,
                               subject_public_key=end_pubkey,
                               issuer_cn='intermediate2',
                               subject_cn='localhost',
                               is_ca=False,
                               additional_extensions=[],
                               asn=asn)
    end_tbs_der = asn.encode('TBSCertificate', end_tbs)

    # Sign the end entity tbsCertificate
    end_sig = crypto.rsa_sha256_sign(sub2_privkey, end_tbs_der)

    # Encode the end entity Certificate
    end_cert_der = x509.certificate(end_tbs, end_sig, asn)

    # Write the chain into file
    io.export_chain([end_cert_der, sub2_cert_der, sub1_cert_der],
                    args.build_dir + EXPORTED_CHAIN_NAME)

    # Export the private key
    io.export_private_key(end_privkey, args.build_dir + EXPORTED_KEY_NAME)


if __name__ == "__main__":
    main()
