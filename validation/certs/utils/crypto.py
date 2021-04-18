from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import MD5
from Cryptodome.Hash import SHA1
from Cryptodome.Signature import pkcs1_15


def new_rsa_keypair(size):
    privkey = RSA.generate(size)
    pubkey = privkey.publickey()
    return (privkey, pubkey)


def rsa_sha256_sign(key, data):
    digest = SHA256.new()
    digest.update(data)
    return pkcs1_15.new(key).sign(digest)


def rsa_md5_sign(key, data):
    digest = MD5.new()
    digest.update(data)
    return pkcs1_15.new(key).sign(digest)


def sha1_hash(data):
    digest = SHA1.new(data)
    return digest.digest()
