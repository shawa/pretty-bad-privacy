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
    packed = pack(fmt, *(tuple(keys) + (ciphertext, )))
    return fmt, packed


def unpack_keys_and_ciphertext(fmt, packed):
    vals = unpack(fmt, packed)
    *keys, ciphertext = vals
    return keys, ciphertext


def pack_sig_and_block(block_fmt: str,
                       sig: bytes,
                       ciphertext_block: bytes) -> Tuple[str, bytes]:
    fmt_block_fmt = '{}s'.format(len(block_fmt))
    fmt_sig = '{}s'.format(len(sig))
    fmt_cipher_block = '{}s'.format(len(ciphertext_block))
    fmt = fmt_block_fmt + fmt_sig + fmt_cipher_block
    packed = pack(fmt, block_fmt.encode('utf-8'), sig, ciphertext_block)
    return fmt, packed


def unpack_sig_and_block(fmt: str, packed: bytes):
    block_fmt, sig, ciphertext_block = unpack(fmt, packed)
    return block_fmt.decode('utf-8'), sig, ciphertext_block


_SEPARATOR = '|'
def serialize_everything(fmt: str, everything_packed: bytes) -> str:
    serialized = bytes_to_b64_string(everything_packed)
    return '{}{}{}'.format(fmt, _SEPARATOR, serialized)


def deserialize_everything(serialized_everything_packed: str):
    fmt, everything_packed = serialized_everything_packed.split(_SEPARATOR)
    deserialized = b64_string_to_bytes(everything_packed)
    return fmt, everything_packed


def encrypt(plaintext: bytes, ring: Keyring, privkey: bytes) -> str:
    symm_ciphertext, symm_key = _symmetric_encrypt(plaintext)
    group_keys = ring.encrypt(symm_key)
    fmt, ciphertext_block = pack_keys_and_ciphertext(group_keys, symm_ciphertext)
    sig = asymmetric.sign(key_ciphertext_block, privkey)
    fmt, packed = pack_sig_and_block(fmt, sig, ciphertext_block)


def decrypt(message: str, pubkey: bytes, privkey: bytes) -> bytes:
    pass
