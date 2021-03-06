import asn1tools
from utils import x509
from utils import io
from utils import misc
from utils import crypto

VALID_ASN_FILE = 'valid.asn'
EXPORTED_KEY_NAME = 'key.pem'
EXPORTED_CHAIN_NAME = 'chain.pem'

INVALID_ASN_FILE = 'notbefore_invalid.asn'


def validity_field(not_before, not_after):
    return {
        'notBefore': not_before,
        'notAfter': ('generalTime', not_after)
    }


def invalid_tbs(issuer_public_key,
                subject_public_key,
                issuer_cn,
                subject_cn,
                additional_extensions,
                asn):
    pub_info = x509.subject_public_key_info(subject_public_key, asn)
    sigalg = x509.algorithm_identifier('sha256WithRSAEncryption')
    issuer_cn = x509.attribute_type_and_value('commonName', issuer_cn)
    issuer = x509.name([issuer_cn])
    subject_cn = x509.attribute_type_and_value('commonName', subject_cn)
    subject = x509.name([subject_cn])
    valid = validity_field('not a time', misc.current_time_offset(365))
    skid = x509.subject_key_identifier(subject_public_key, asn)
    akid = x509.authority_key_identifier(issuer_public_key, asn)
    usage = x509.key_usage(['digitalSignature', 'keyEncipherment'], asn)
    bc = x509.basic_constraints(False, asn)

    extensions = [
        akid,
        skid,
        usage,
        bc
    ] + additional_extensions

    tbs = {
        'version': 2,
        'serialNumber': 2,
        'signature': sigalg,
        'issuer': issuer,
        'validity': valid,
        'subject': subject,
        'subjectPublicKeyInfo': pub_info,
        'extensions': extensions
    }
    return tbs


def main():
    args = misc.parse_arguments()

    # Compile the ASN.1 specification
    asn = asn1tools.compile_files(args.asn_dir + VALID_ASN_FILE, 'der')

    # Import the root private key and cert
    root_privkey = io.import_rsa_private_key(args.root_key_file)
    root_pubkey = root_privkey.publickey()

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

    # Load the invalid asn specification
    wrong_asn = asn1tools.compile_files(args.asn_dir + INVALID_ASN_FILE,
                                        'der')

    # Generate an RSA public key pair for end entity certificate
    (end_privkey, end_pubkey) = crypto.new_rsa_keypair(2048)

    # Encode end entity tbsCertificate
    end_tbs = invalid_tbs(issuer_public_key=sub_pubkey,
                          subject_public_key=end_pubkey,
                          issuer_cn='intermediate',
                          subject_cn='localhost',
                          additional_extensions=[],
                          asn=wrong_asn)
    end_tbs_der = wrong_asn.encode('TBSCertificate', end_tbs)

    # Sign the end entity tbsCertificate
    end_sig = crypto.rsa_sha256_sign(sub_privkey, end_tbs_der)

    # Encode the end entity Certificate
    end_cert_der = x509.certificate(end_tbs, end_sig, wrong_asn)

    # Write the chain into file
    io.export_chain([end_cert_der, sub_cert_der],
                    args.build_dir + EXPORTED_CHAIN_NAME)

    # Export the private key
    io.export_private_key(end_privkey, args.build_dir + EXPORTED_KEY_NAME)


if __name__ == "__main__":
    main()
