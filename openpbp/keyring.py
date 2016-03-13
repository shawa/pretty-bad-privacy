from typing import Tuple, List
import axolotl_curve25519 as curve
import os

from utils import b64_string_to_bytes, bytes_to_b64_string

def generate_keypair() -> Tuple[bytes, bytes]:
    '''generate a new keypair from the given curve'''
    private_key = curve.generatePrivateKey(os.urandom(32))
    public_key = curve.generatePublicKey(private_key)
    return private_key, public_key


def keyring(*keys: List[str]) -> dict:
    '''generate a keyring dict with the given keys'''
    ring = {
        'keys': [bytes_to_b64_string(k) for k in keys],
        'signatures': [],
    }

    return ring


def keyring_keystring(ring: dict) -> bytes:
    '''return a bytes of the keyring values'''
    return b''.join(b64_string_to_bytes(key)
                    for key in ring['keys'])


def keyring_sign(ring: dict, private_key: bytes) -> str:
    '''generate a signature for the given keyring'''
    nonce = os.urandom(64)
    keystring = keyring_keystring(ring)
    sig = curve.calculateSignature(nonce, private_key, keystring)
    return bytes_to_b64_string(sig)


def keyring_verify_signature(ring:dict , public_key: str, signature: str):
    return 0 is curve.verifySignature(b64_string_to_bytes(public_key),
                                      keyring_keystring(ring),
                                      b64_string_to_bytes(signature))


def keyring_verify(ring: dict) -> bool:
    keys = ring['keys']
    sigs = ring['signatures']
    verifications = (keyring_verify_signature(ring, key, signature)
                     for key, signature in zip(keys, sigs))

    return all(verifications)
