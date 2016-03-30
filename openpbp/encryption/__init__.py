from typing import List, Tuple, Any
from struct import pack, unpack
from cryptography.fernet import Fernet
from keyring import Keyring

from utils import b64_string_to_bytes, bytes_to_b64_string

import asymmetric

def _symmetric_encrypt(plaintext: bytes) -> Tuple[bytes, bytes]:
    session_key = Fernet.generate_key()
    fernet = Fernet(session_key)
    symmetric_ciphertext = fernet.encrypt(plaintext)
    return symmetric_ciphertext, session_key

def _symmetric_decrypt(ciphertext: bytes, session_key: bytes) -> bytes:
    fernet = Fernet(session_key)
    plaintext = fernet.decrypt(ciphertext)
    return plaintext


def encrypt(plaintext: bytes, ring: Keyring, privkey: bytes) -> str:
    symmetric_ciphertext, symmetric_key = _symmetric_encrypt(plaintext)
    group_keys = ring.encrypt(symmetric_key)

def decrypt(message: str, pubkey: bytes, privkey: bytes) -> bytes:
    pass
