from typing import List, Tuple
from struct import pack, unpack
from cryptography.fernet import Fernet
from keyring import Keyring

import asymmetric


def pack_group_block(message: bytes, keys: List[bytes]) -> Tuple[str, bytes]:
    fmt = ('c' * len(message) + ''.join('c' * len(key) for key in keys))
    block = pack(fmt, message, *keys)
    return fmt, block


def unpack_group_block(fmt: str, block: bytes) -> Tuple[bytes, List[bytes]]:
    message, keys = struct.unpack(fmt, block)
    return message, keys


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
    group_block = message + ''b''.join(k for k in keys)

    # TODO:  Finally, she signs Gg with her private key, producing Sg so that
    # each member may verify the file’s integrity, and that the sender is
    # indeed Alice.
    sig = asymmetric.sign(group_block, privkey)
    # TODO:  She bundles Cg with her signature Sg to produce CG. CG may now be
    # shared via an insecure channel.
    keys = ring.encrypt(session_key)
    return (sig, group_block)
