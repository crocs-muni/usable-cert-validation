import sys

BEGIN_STR = '-----BEGIN CERTIFICATE-----'

with open(sys.argv[1], 'r') as f:
    chain = f.read()

tmp = chain.split(BEGIN_STR)
tmp.pop(0)
certs = list(map(lambda x: BEGIN_STR + x, tmp))

with open(sys.argv[2] + 'endpoint.pem', 'w') as f:
    f.write(certs[0])

for i, cert in enumerate(certs[1:]):
    with open(sys.argv[2] + 'intermediate' + str(i + 1) + '.pem', 'w') as f:
        f.write(cert)
