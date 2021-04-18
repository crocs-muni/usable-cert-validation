import os
import base64
from Cryptodome.PublicKey import RSA


CERT_LABEL = 'CERTIFICATE'
CRL_LABEL = 'X509 CRL'


def export_cert(cert_der, filename):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    cert_pem = _der_to_pem(cert_der, CERT_LABEL)
    with open(filename, "w") as file:
        file.write(cert_pem)


def export_chain(chain, filename):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "w") as file:
        for cert_der in chain:
            cert_pem = _der_to_pem(cert_der, CERT_LABEL)
            file.write(cert_pem)


def export_crl(crl_der, filename):
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    crl_pem = _der_to_pem(crl_der, CRL_LABEL)
    with open(filename, "w") as file:
        file.write(crl_pem)


def _der_to_pem(bytes_der, label):
    f = str(base64.standard_b64encode(bytes_der), 'ASCII', 'strict')
    ss = ['-----BEGIN ' + label + '-----']
    ss += [f[i:i + 64] for i in range(0, len(f), 64)]
    ss.append('-----END ' + label + '-----' + '\n')
    return '\n'.join(ss)


def _pem_to_der(string_pem, expected_label):
    beg = '-----BEGIN ' + expected_label + '-----'
    end = '-----END ' + expected_label + '-----'
    if not string_pem.startswith(beg) or not string_pem.strip().endswith(end):
        raise ValueError('Invalid PEM label')
    d = string_pem.strip()[len(beg):-len(end)]
    return base64.decodebytes(d.encode('ASCII', 'strict'))


def import_rsa_private_key(filename):
    with open(filename, "r") as file:
        key_pem = file.read()
    return RSA.import_key(key_pem)


def import_cert(filename, asn):
    with open(filename, "r") as file:
        cert_pem = file.read()
    cert_der = _pem_to_der(cert_pem, "CERTIFICATE")
    return asn.decode('Certificate', cert_der)


def export_private_key(key, filename):
    key_bytes = key.exportKey(pkcs=8)
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, 'bw') as file:
        file.write(key_bytes)
