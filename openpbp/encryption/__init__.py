from typing import List, Tuple, Any
from struct import pack, unpack
from cryptography.fernet import Fernet
from keyring import Keyring

from utils import b64_string_to_bytes, bytes_to_b64_string

import asymmetric

MAGIC_MARKER = '|#|buckfast|@|'
MAGIC_CRAYON = '|#|clubmate|@|'

def pack_group_block(message: bytes, keys: List[bytes]) -> Tuple[str, bytes]:
    fmt = ('{}s'.format(len(message)) +
           ''.join(['{}s'.format(len(k)) for k in keys]))
    block = pack(fmt, message, *keys)
    return fmt, block


def unpack_group_block(fmt: str, block: bytes) -> Tuple[Any, List[Any]]:
    message, *keys = unpack(fmt, block)
    return message, list(keys)


def serialize_group_block(fmt: str, block: bytes) -> str:
    block_serial = bytes_to_b64_string(block)
    return ('{fmt}{marker}{block}'
            .format(fmt=fmt, marker=MAGIC_MARKER, block=block_serial))


def deserialize_group_block(serialized: str) -> Tuple[str, bytes]:
    if MAGIC_MARKER not in serialized:
        raise ValueError('bad serialized block given')

    fmt, block_serial = serialized.split(MAGIC_MARKER)
    block = b64_string_to_bytes(block_serial)
    return fmt, block


def serialize_message(sig_serial: str, serialized_group_block: str) -> str:
    return '{}{}{}'.format(sig_serial, MAGIC_CRAYON, serialized_group_block)


def deserialize_message(serialized_message: str)  -> Tuple[str, str]:
    if MAGIC_CRAYON not in serialized_message:
        raise ValueError('bad serialized message given')

    sig, serialized_group_block = serialized_message.split(MAGIC_CRAYON)
    return sig, serialized_group_block


def encrypt_message(ring: Keyring, privkey: bytes,
            message: bytes) -> Tuple[str, str]:
    if not ring.complete():
        raise ValueError('Invalid keyring given')

    # L I T E R A T E   P R O G R A M M I N G
    # I
    # T
    # E
    # R
    # A
    # T
    # E
    #
    # p
    # R
    # O
    # G
    # R
    # A
    # M
    # M
    # I
    # N
    # G
    # To encrypt a plaintext file P to be shared to group members, Alice
    # first generates a session key Ks with which to encrypt P.
    session_key = Fernet.generate_key()
    fern = Fernet(session_key)
    # She then symmetrically encrypts P with Ks to produce Cs, the
    # symmetrically encrypted cipher text. Note that the session key will be
    # common to all group members.
    message = fern.encrypt(message)
    # For each public key Ki in keyring, she asymmetrically encrypts Ks
    # to produce Ksi . Thus with any member’s private key, the session key may
    # be decrypted.
    # She then groups these keys together, to form the Key Block KB,
    # which is a list containing each Ksi .
    keys = ring.encrypt(session_key)
    # She places KB and Cs together, to form the Group Ciphertext Cg.
    # Cg, and thus the original file P may now be only be decrypted by a member
    # of the group.
    fmt, group_block = pack_group_block(message, keys)
    serialized_group_block = serialize_group_block(fmt, group_block)
    serialized_group_block_bin = serialized_group_block.encode('utf-8')
    # Finally, she signs Gg with her private key, producing Sg so that
    # each member may verify the file’s integrity, and that the sender is
    # indeed Alice.
    sig = asymmetric.sign(serialized_group_block_bin, privkey) # type: bytes
    sig_serial = bytes_to_b64_string(sig)
    # She bundles Cg with her signature Sg to produce CG. CG may now be
    # shared via an insecure channel.
    return sig_serial, serialized_group_block


def decrypt_message(privkey: bytes,
                    origin_pubkey: bytes,
                    sig_serial: str,
                    serialized_group_block: str) -> bytes:
    sig = b64_string_to_bytes(sig_serial)
    serialized_group_block_bin = serialized_group_block.encode('utf-8')
    if not asymmetric.verify(serialized_group_block_bin, sig, origin_pubkey):
        raise ValueError('Bad signature on message')

    fmt, group_block = deserialize_group_block(serialized_group_block)
    message, keys = unpack_group_block(fmt, group_block)

    session_key = None
    for key in keys:
        try:
            session_key = asymmetric.decrypt(key, privkey)
            break
        except ValueError:
            # There'll be n-1 failed decryptions. We can avoid this by giving
            # each key a key id within the ring, but this is good enough
            # for the moment
            continue

    if session_key is None:
        raise RuntimeError('Failed to find a session key. Sorry.')


    fern = Fernet(session_key)
    plaintext = fern.decrypt(message)
    return plaintext
