from typing import List, Tuple, Any
from struct import pack, unpack
from cryptography.fernet import Fernet
from keyring import Keyring

from utils import b64_string_to_bytes, bytes_to_b64_string

import asymmetric

MAGIC_MARKER = '|#|buckfast|@|'

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
            .format(fmt=fmt, marker=MAGIC_MARKER, block=block))

def deserialize_group_block(serialized: str) -> Tuple[str, bytes]:
    if MAGIC_MARKER not in serialized:
        raise ValueError('bad serialized block given')

    fmt, block_serial = serialized.split(MAGIC_MARKER)
    block = b64_string_to_bytes(block_serial)
    return fmt, block


def encrypt(ring: Keyring, privkey: bytes,
            message: bytes) -> Tuple[bytes, List[bytes]]:
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

    # TODO:  She places KB and Cs together, to form the Group Ciphertext Cg.
    # Cg, and thus the original file P may now be only be decrypted by a member
    # of the group.
    fmt, group_block = pack_group_block(message, keys)

    # TODO:  Finally, she signs Gg with her private key, producing Sg so that
    # each member may verify the file’s integrity, and that the sender is
    # indeed Alice.
    sig = asymmetric.sign(group_block, privkey)
    # TODO:  She bundles Cg with her signature Sg to produce CG. CG may now be
    # shared via an insecure channel.
    keys = ring.encrypt(session_key)
    return (sig, group_block)
