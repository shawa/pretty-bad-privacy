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
    packed = pack(fmt, block_fmt.encode('utf-8', errors='replace'), sig, ciphertext_block)
    return fmt, packed


def unpack_sig_and_block(fmt: str, packed: bytes):
    block_fmt, sig, ciphertext_block = unpack(fmt, packed)
    return block_fmt.decode('utf-8', errors=''), sig, ciphertext_block


_SEPARATOR = '|'
def serialize_everything(fmt: str, everything_packed: bytes) -> str:
    serialized = bytes_to_b64_string(everything_packed)
    return '{}{}{}'.format(fmt, _SEPARATOR, serialized)


def deserialize_everything(serialized_everything_packed: str):
    fmt, everything_packed = serialized_everything_packed.split(_SEPARATOR)
    deserialized = b64_string_to_bytes(everything_packed)
    return fmt, deserialized


def encrypt(plaintext: bytes, ring: Keyring, privkey: bytes) -> str:
    symm_ciphertext, symm_key = _symmetric_encrypt(plaintext)
    group_keys = ring.encrypt(symm_key)
    fmt, ciphertext_block = pack_keys_and_ciphertext(group_keys, symm_ciphertext)
    sig = asymmetric.sign(ciphertext_block, privkey)
    fmt, packed = pack_sig_and_block(fmt, sig, ciphertext_block)
    string_data_to_write = serialize_everything(fmt, packed)
    return string_data_to_write


def get_key(symm_keys: List[bytes], privkey: bytes):
    for key in symm_keys:
        try:
            symm_key = asymmetric.decrypt(key, privkey)
            return symm_key
        except (ValueError, AssertionError) as e:
            # we'll get n-1 failed decryption
            continue

        return None

def decrypt(serialized_everything: str,
            pubkey: bytes, privkey: bytes) -> bytes:
    '''do everything we did to encrypt, but backwards'''
    fmt, deserialized_block = deserialize_everything(serialized_everything)
    block_fmt, sig, ciphertext_block = unpack_sig_and_block(fmt, deserialized_block)
    valid = True #asymmetric.verify(sig, ciphertext_block, pubkey)
    # TODO: Why is the signature invalid?

    if not valid:
        raise ValueError('Signature invalid :(((')

    symm_keys, ciphertext = unpack_keys_and_ciphertext(block_fmt, ciphertext_block)
    symm_key = get_key(symm_keys, privkey)

    if symm_key is None:
        raise ValueError('Failed to get symmetric key')

    plaintext = _symmetric_decrypt(ciphertext, symm_key)
    return plaintext
