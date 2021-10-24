import functools
from . import misc
from . import crypto

oid_map = {
    'sha256WithRSAEncryption': '1.2.840.113549.1.1.11',
    'sha512WithRSAEncryption': '1.2.840.113549.1.1.13',
    'md5WithRSAEncryption': '1.2.840.113549.1.1.4',
    'commonName': '2.5.4.3',
    'subjectKeyIdentifier': '2.5.29.14',
    'authorityKeyIdentifier': '2.5.29.35',
    'keyUsage': '2.5.29.15',
    'basicConstraints': '2.5.29.19',
    'nameConstraints': '2.5.29.30',
    'subjectAltName': '2.5.29.17',
    'issuerAltName': '2.5.29.18',
    'policyConstraints': '2.5.29.36',
    'extKeyUsage': '2.5.29.37',
    'policyMappings': '2.5.29.33',
    'certificatePolicies': '2.5.29.32',
    'certificateIssuer': '2.5.29.29',
    'cRLDistributionPoints': '2.5.29.31',
    'cRLNumber': '2.5.29.20',
    'reasonCode': '2.5.29.21',
    'invalidityDate': '2.5.29.24',
    'deltaCRLIndicator': '2.5.29.27',
    'issuingDistributionPoint': '2.5.29.28',
    'freshestCRL': '2.5.29.46',
    'inhibitAnyPolicy': '2.5.29.54',
    'authorityInfoAccess': '1.3.6.1.5.5.7.1.1',
    'id-pe-ipAddrBlocks': '1.3.6.1.5.5.7.1.7',
    'subjectInfoAccess': '1.3.6.1.5.5.7.1.11',
    'id-pe-proxyCertInfo': '1.3.6.1.5.5.7.1.14',
    'id-kp-serverAuth': '1.3.6.1.5.5.7.3.1',
    'id-kp-clientAuth': '1.3.6.1.5.5.7.3.2',
    'anyExtendedKeyUsage': '2.5.29.37.0',
    'id-ppl-inheritAll': '1.3.6.1.5.5.7.21.1',
    'id-ppl-independent': '1.3.6.1.5.5.7.21.2',
    'id-ad-ocsp': '1.3.6.1.5.5.7.48.1',
    'ext-TLSFeatures': '1.3.6.1.5.5.7.1.24'
}


def subject_public_key_info(public_key, asn):
    pubkey_info_der = public_key.exportKey('DER')
    pubkey_info = asn.decode('SubjectPublicKeyInfo', pubkey_info_der)
    return pubkey_info


def algorithm_identifier(oid_name):
    return {
        'algorithm': oid_map[oid_name],
        'parameters': None
    }


def name(name_list):
    return ('rdnSequence', [[n] for n in name_list])


def attribute_type_and_value(attr_type, attr_value):
    return {
        'type': oid_map[attr_type],
        'value': ('printableString', attr_value)
    }


def validity(not_before, not_after):
    return {
        'notBefore': ('generalTime', not_before),
        'notAfter': ('generalTime', not_after)
    }


def _key_digest_SHA_1(public_key, asn):
    key_info = subject_public_key_info(public_key, asn)
    key_bytes = key_info['subjectPublicKey'][0]
    return crypto.sha1_hash(key_bytes)


def subject_key_identifier(public_key, asn):
    skid = _key_digest_SHA_1(public_key, asn)
    skid_der = asn.encode('SubjectKeyIdentifier', skid)
    return {
        'extnID': oid_map['subjectKeyIdentifier'],
        'critical': False,
        'extnValue': skid_der
    }


def authority_key_identifier(public_key, asn):
    key_digest = _key_digest_SHA_1(public_key, asn)
    akid = {
        'keyIdentifier': key_digest
    }
    akid_der = asn.encode('AuthorityKeyIdentifier', akid)
    return {
        'extnID': oid_map['authorityKeyIdentifier'],
        'critical': False,
        'extnValue': akid_der
    }


def ip_addr_blocks(prefix_ips, asn):
    prefix_b = [bytes(map(int, ip.split('.'))) for ip in prefix_ips]
    prefix_tuples = [('addressPrefix', (ip, len(ip) * 8)) for ip in prefix_b]
    addr_blocks = [
        {
            'addressFamily': b'\x00\x01',
            'ipAddressChoice': ('addressesOrRanges', prefix_tuples)
        }
    ]
    addr_blocks_der = asn.encode('IPAddrBlocks', addr_blocks)

    return {
        'extnID': oid_map['id-pe-ipAddrBlocks'],
        'critical': True,
        'extnValue': addr_blocks_der
    }


def key_usage(usage_list, asn):
    usage_map = {
        'digitalSignature': 0x1 << 7,
        'nonRepudiation': 0x1 << 6,
        'keyEncipherment': 0x1 << 5,
        'dataEncipherment': 0x1 << 4,
        'keyAgreement': 0x1 << 3,
        'keyCertSign': 0x1 << 2,
        'cRLSign': 0x1 << 1,
        'encipherOnly': 0x1 << 0,
    }
    usage_bits = map(lambda x: usage_map[x], usage_list)
    usage = functools.reduce(lambda x, y: x | y, usage_bits, 0)
    key_usage = (usage.to_bytes(1, byteorder='big'), 8)
    key_usage_der = asn.encode('KeyUsage', key_usage)
    return {
        'extnID': oid_map['keyUsage'],
        'critical': True,
        'extnValue': key_usage_der
    }


def ext_key_usage(usage_list, asn):
    ext_key_usage = [oid_map[usage] for usage in usage_list]
    ext_key_usage_der = asn.encode('ExtKeyUsageSyntax', ext_key_usage)
    return {
        'extnID': oid_map['extKeyUsage'],
        'critical': True,
        'extnValue': ext_key_usage_der
    }


def basic_constraints(is_ca, asn, max_path_len=None):
    bc = {
        'cA': is_ca,
    }
    if max_path_len is not None:
        bc['pathLenConstraint'] = max_path_len

    bc_der = asn.encode('BasicConstraints', bc)
    return {
        'extnID': oid_map['basicConstraints'],
        'critical': True,
        'extnValue': bc_der
    }


def name_constraints(asn, permitted=None, excluded=None):
    nc = {}
    if permitted is not None:
        nc['permittedSubtrees'] = permitted
    if excluded is not None:
        nc['excludedSubtrees'] = excluded
    nc_der = asn.encode('NameConstraints', nc)
    return {
        'extnID': oid_map['nameConstraints'],
        'critical': True,
        'extnValue': nc_der
    }


def general_subtree(general_name, minimum=0, maximum=None):
    subtree = {
        'base': general_name,
        'minimum': minimum
    }
    if maximum is not None:
        subtree['maximum'] = maximum
    return subtree


def general_ip_address(address):
    addr_bytes = bytes(map(int, address.split('.')))
    return ('iPAddress', addr_bytes)


def general_ip_address_range(address, prefix):
    addr_bytes = bytes(map(int, address.split('.')))
    prefix_bytes = (pow(2, prefix) - 1).to_bytes(4, 'big')
    return ('iPAddress', addr_bytes + prefix_bytes)


def subject_alt_name(general_names, asn):
    san_der = asn.encode('SubjectAltName', general_names)
    return {
        'extnID': oid_map['subjectAltName'],
        'critical': True,
        'extnValue': san_der
    }


def issuer_alt_name(general_names, asn):
    ian_der = asn.encode('IssuerAltName', general_names)
    return {
        'extnID': oid_map['issuerAltName'],
        'critical': True,
        'extnValue': ian_der
    }


def certificate_policies(policy_list, asn):
    policies = [
        {
            'policyIdentifier': oid_map[policy],
        } for policy in policy_list
    ]
    policies_der = asn.encode('CertificatePolicies', policies)
    return {
        'extnID': oid_map['certificatePolicies'],
        'critical': True,
        'extnValue': policies_der
    }


def policy_constraints(asn, require_explicit=None, inhibit_mapping=None):
    pc = {}
    if require_explicit is not None:
        pc['requireExplicitPolicy'] = require_explicit
    if inhibit_mapping is not None:
        pc['inhibitPolicyMapping'] = inhibit_mapping
    pc_der = asn.encode('PolicyConstraints', pc)
    return {
        'extnID': oid_map['policyConstraints'],
        'critical': True,
        'extnValue': pc_der
    }


def inhibit_any_policy(skip_certs, asn):
    iap_der = asn.encode('InhibitAnyPolicy', skip_certs)
    return {
        'extnID': oid_map['inhibitAnyPolicy'],
        'critical': True,
        'extnValue': iap_der
    }


def proxy_cert_info(language, asn, path_len_constraint=None, policy=None):
    proxy_policy = {
        'policyLanguage': oid_map[language]
    }
    if policy is not None:
        proxy_policy['policy'] = policy
    cert_info = {
        'proxyPolicy': proxy_policy
    }
    if path_len_constraint is not None:
        cert_info['pCPathLenConstraint'] = path_len_constraint
    cert_info_der = asn.encode('ProxyCertInfo', cert_info)
    return {
        'extnID': oid_map['id-pe-proxyCertInfo'],
        'critical': True,
        'extnValue': cert_info_der
    }


def crl_distribution_points(uris, asn):
    dp_names = [('fullName', [('uniformResourceIdentifier', uri)])
                for uri in uris]
    dps = [
        {
            'distributionPoint': dp_name
        } for dp_name in dp_names
    ]
    dps_der = asn.encode('CRLDistributionPoints', dps)
    return {
        'extnID': oid_map['cRLDistributionPoints'],
        'critical': False,
        'extnValue': dps_der
    }


def issuing_distribution_point(asn,
                               distribution_point=None,
                               only_contains_user_certs=False, 
                               only_contains_ca_certs=False, 
                               only_some_reasons=None,
                               indirect_crl=False, 
                               only_contains_attribute_certs=False):
    idp = {
        'onlyContainsUserCerts': only_contains_user_certs,
        'onlyContainsCACerts': only_contains_ca_certs,
        'indirectCRL': indirect_crl,
        'onlyContainsAttributeCerts': only_contains_attribute_certs,
    }
    if distribution_point is not None:
        idp['distributionPoint'] = distribution_point
    if only_some_reasons is not None:
        idp['onlySomeReasons'] = only_some_reasons
    idp_der = asn.encode('IssuingDistributionPoint', idp)
    return {
        'extnID': oid_map['issuingDistributionPoint'],
        'critical': True,
        'extnValue': idp_der
    }


def freshest_crl(uris, asn):
    dp_names = [('fullName', [('uniformResourceIdentifier', uri)])
                for uri in uris]
    dps = [
        {
            'distributionPoint': dp_name
        } for dp_name in dp_names
    ]
    dps_der = asn.encode('FreshestCRL', dps)
    return {
        'extnID': oid_map['freshestCRL'],
        'critical': False,
        'extnValue': dps_der
    }


def access_descriptions(uris):
    return [
        {
            'accessMethod': oid_map[method],
            'accessLocation': ('uniformResourceIdentifier', uri)
        } for (uri, method) in uris
    ]


def authority_information_access(uris, asn):
    aia = access_descriptions(uris)
    aia_der = asn.encode('AuthorityInfoAccessSyntax', aia)
    return {
        'extnID': oid_map['authorityInfoAccess'],
        'critical': False,
        'extnValue': aia_der
    }


def subject_information_access(uris, asn):
    sia = access_descriptions(uris)
    sia_der = asn.encode('SubjectInfoAccessSyntax', sia)
    return {
        'extnID': oid_map['subjectInfoAccess'],
        'critical': False,
        'extnValue': sia_der
    }


def revoked_certificate(serial, time, extensions=None):
    revoked = {
        'userCertificate': serial,
        'revocationDate': time,
    }
    if extensions is not None:
        revoked['crlEntryExtensions'] = extensions
    return revoked


def crl_number(number, asn):
    num_der = asn.encode('CRLNumber', number)
    return {
        'extnID': oid_map['cRLNumber'],
        'critical': False,
        'extnValue': num_der
    }


def delta_crl_indicator(number, asn):
    num_der = asn.encode('BaseCRLNumber', number)
    return {
        'extnID': oid_map['deltaCRLIndicator'],
        'critical': False,
        'extnValue': num_der
    }


def certificate(tbs_cert, signature, asn):
    cert = {
        'tbsCertificate': tbs_cert,
        'signatureAlgorithm': tbs_cert['signature'],
        'signatureValue': (signature, len(signature) * 8)
    }
    return asn.encode('Certificate', cert)


def certificate_list(tbs_cert_list, signature, asn):
    crl = {
        'tbsCertList': tbs_cert_list,
        'signatureAlgorithm': tbs_cert_list['signature'],
        'signatureValue': (signature, len(signature) * 8)
    }
    return asn.encode('CertificateList', crl)


def tls_features(features, asn):
    features_map = {
        'status_request': 5,
        'status_request_v2': 17
    }
    features_list = [features_map[feature] for feature in features]
    features_der = asn.encode('Features', features_list)
    return {
        'extnID': oid_map['ext-TLSFeatures'],
        'critical': False,
        'extnValue': features_der
    }


def default_tbs(issuer_public_key,
                subject_public_key,
                issuer_cn,
                subject_cn,
                is_ca,
                additional_extensions,
                asn):
    pub_info = subject_public_key_info(subject_public_key, asn)
    sigalg = algorithm_identifier('sha256WithRSAEncryption')
    issuer_cn = attribute_type_and_value('commonName', issuer_cn)
    issuer = name([issuer_cn])
    subject_cn = attribute_type_and_value('commonName', subject_cn)
    subject = name([subject_cn])
    valid = validity(misc.current_time(),
                     misc.current_time_offset(10 * 365 if is_ca else 365))
    skid = subject_key_identifier(subject_public_key, asn)
    akid = authority_key_identifier(issuer_public_key, asn)
    usage = key_usage(['keyCertSign', 'cRLSign'] if is_ca else
                      ['digitalSignature', 'keyEncipherment'], asn)
    bc = basic_constraints(is_ca, asn)

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


def default_tbs_crl(issuer_public_key,
                    issuer_cn,
                    number,
                    revoked,
                    additional_extensions,
                    asn):
    sigalg = algorithm_identifier('sha256WithRSAEncryption')
    issuer_cn = attribute_type_and_value('commonName', issuer_cn)
    issuer = name([issuer_cn])
    akid = authority_key_identifier(issuer_public_key, asn)
    crlnumber = crl_number(number, asn)

    extensions = [
        akid,
        crlnumber
    ] + additional_extensions

    tbs = {
        'version': 1,
        'signature': sigalg,
        'issuer': issuer,
        'thisUpdate': ('generalTime', misc.current_time()),
        'nextUpdate': ('generalTime', misc.current_time_offset(365)),
        'revokedCertificates': revoked,
        'crlExtensions': extensions
    }
    return tbs
