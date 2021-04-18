import asn1tools
from utils import x509
from utils import io
from utils import misc
from utils import crypto

VALID_ASN_FILE = 'valid.asn'
EXPORTED_KEY_NAME = 'key.pem'
EXPORTED_CHAIN_NAME = 'chain.pem'


def proxy_extension_with_constraint(asn):
    return x509.proxy_cert_info('id-ppl-inheritAll', asn, 0)


def proxy_extension(asn):
    return x509.proxy_cert_info('id-ppl-inheritAll', asn)


def add_another_cn(tbs):
    subject_cn = x509.attribute_type_and_value('commonName', 'localhost')
    proxy_cn = x509.attribute_type_and_value('commonName', 'proxy')
    tbs['subject'] = x509.name([subject_cn, proxy_cn])


def add_two_other_cn(tbs):
    subject_cn = x509.attribute_type_and_value('commonName', 'localhost')
    proxy_cn = x509.attribute_type_and_value('commonName', 'proxy')
    proxy2_cn = x509.attribute_type_and_value('commonName', 'proxy2')
    tbs['subject'] = x509.name([subject_cn, proxy_cn, proxy2_cn])
    tbs['issuer'] = x509.name([subject_cn, proxy_cn])


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

    # Generate an RSA public key pair for end entity certificate
    (end_privkey, end_pubkey) = crypto.new_rsa_keypair(2048)

    # Encode end entity tbsCertificate
    end_tbs = x509.default_tbs(issuer_public_key=sub_pubkey,
                               subject_public_key=end_pubkey,
                               issuer_cn='intermediate',
                               subject_cn='localhost',
                               is_ca=False,
                               additional_extensions=[],
                               asn=asn)
    end_tbs_der = asn.encode('TBSCertificate', end_tbs)

    # Sign the end entity tbsCertificate
    end_sig = crypto.rsa_sha256_sign(sub_privkey, end_tbs_der)

    # Encode the end entity Certificate
    end_cert_der = x509.certificate(end_tbs, end_sig, asn)

    # Generate an RSA public key pair for proxy certificate
    (proxy_privkey, proxy_pubkey) = crypto.new_rsa_keypair(2048)

    # Create proxy extension
    proxy_ext = proxy_extension_with_constraint(asn)

    # Encode proxy tbsCertificate
    proxy_tbs = x509.default_tbs(issuer_public_key=end_pubkey,
                                 subject_public_key=proxy_pubkey,
                                 issuer_cn='localhost',
                                 subject_cn='localhost',
                                 is_ca=False,
                                 additional_extensions=[proxy_ext],
                                 asn=asn)

    add_another_cn(proxy_tbs)

    proxy_tbs_der = asn.encode('TBSCertificate', proxy_tbs)

    # Sign the proxy tbsCertificate
    proxy_sig = crypto.rsa_sha256_sign(end_privkey, proxy_tbs_der)

    # Encode the proxy Certificate
    proxy_cert_der = x509.certificate(proxy_tbs, proxy_sig, asn)

    # Generate an RSA public key pair for second proxy certificate
    (proxy2_privkey, proxy2_pubkey) = crypto.new_rsa_keypair(2048)

    # Create proxy extension
    proxy2_ext = proxy_extension(asn)

    # Encode end entity tbsCertificate
    proxy2_tbs = x509.default_tbs(issuer_public_key=proxy_pubkey,
                                  subject_public_key=proxy2_pubkey,
                                  issuer_cn='localhost',
                                  subject_cn='localhost',
                                  is_ca=False,
                                  additional_extensions=[proxy2_ext],
                                  asn=asn)

    add_two_other_cn(proxy2_tbs)

    proxy2_tbs_der = asn.encode('TBSCertificate', proxy2_tbs)

    # Sign the end entity tbsCertificate
    proxy2_sig = crypto.rsa_sha256_sign(proxy_privkey, proxy2_tbs_der)

    # Encode the end entity Certificate
    proxy2_cert_der = x509.certificate(proxy2_tbs, proxy2_sig, asn)

    # Write the chain into file
    io.export_chain([proxy2_cert_der,
                     proxy_cert_der,
                     end_cert_der,
                     sub_cert_der],
                    args.build_dir + EXPORTED_CHAIN_NAME)

    # Export the private key
    io.export_private_key(proxy2_privkey, args.build_dir + EXPORTED_KEY_NAME)


if __name__ == "__main__":
    main()
