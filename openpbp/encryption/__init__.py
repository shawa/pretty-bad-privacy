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


def pack_keys_and_ciphertext(keys: List[bytes],
                             ciphertext: bytes) -> Tuple[str, bytes]:
    fmt_k = ''.join(['{}s'.format(len(key)) for key in keys])
    fmt_b = '{}s'.format(len(ciphertext))
    fmt = fmt_k + fmt_b
    packed = pack(fmt, ciphertext)
    return fmt, packed

def unpack_keys_and_ciphertext(fmt, packed):
    vals = unpack(fmt, packed)
    keys = vals[:-1]
    ciphertext = vals[-1]
    return keys, ciphertext


def pack_sig_and_block(block_fmt: str,
                       sig: bytes,
                       ciphertext_block: bytes) -> Tuple[str, bytes]:
    pass

def encrypt(plaintext: bytes, ring: Keyring, privkey: bytes) -> str:
    symmetric_ciphertext, symmetric_key = _symmetric_encrypt(plaintext)
    group_keys = ring.encrypt(symmetric_key)

    fmt, key_ciphertext_block = pack_keys_and_ciphertext(group_keys,
                                                         symmetric_ciphertext)
    sig = asymmetric.sign(key_ciphertext_block, privkey)

def decrypt(message: str, pubkey: bytes, privkey: bytes) -> bytes:
    pass
