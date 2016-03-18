'''
Wrapper for PyCA's asymmetric crypto primitives, provides asymmetric 
Keypair generation, signing/verification, encryption/decryption
'''
from typing import Tuple
from collections import namedtuple
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import (
        load_pem_public_key,
        load_pem_private_key
    )
from cryptography.exceptions import InvalidSignature

Keypair = namedtuple('Keypair', ['privkey', 'pubkey'])

def _load_pubkey(pubkey_pem_data: bytes):
    return load_pem_public_key(
            pubkey_pem_data,
            backend=default_backend(),
    )

def _load_privkey(privkey_pem_data: bytes, password=None):
    return load_pem_private_key(
            privkey_pem_data,
            password=password,
            backend=default_backend()
    )

def encrypt(message: bytes, pubkey: bytes) -> bytes:
    public_key = _load_pubkey(pubkey)
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    return ciphertext


def decrypt(message: bytes, privkey: bytes) -> bytes:
    private_key = _load_privkey(privkey)
    plaintext = private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

def sign(message: bytes, privkey: bytes) -> bytes:
    private_key = _load_privkey(privkey)
    signer = private_key.signer(
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signer.update(message)
    signature = signer.finalize()
    return signature

def verify(message: bytes, signature: bytes, pubkey: bytes) -> bool:
    public_key = _load_pubkey(pubkey)
    verifier = public_key.verifier(
        signature,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    verifier.update(message)
    try:
        verifier.verify() # raises exception if fails, supposedly
        return True
    except InvalidSignature:
        return False


def gen_keypair() -> Keypair:
    gen_params = {
            'public_exponent': 65537,
            'key_size': 4096,
            'backend': default_backend(),
    }

    key = rsa.generate_private_key(**gen_params)

    privkey = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pubkey = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return Keypair(privkey, pubkey)
