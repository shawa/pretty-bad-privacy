import axolotl_curve25519 as curve
import os
import base64

from utils import b64_string_to_bytes, bytes_to_b64_string

def generate_keypair():
    private_key = curve.generatePrivateKey(os.urandom(32))
    public_key = curve.generatePublicKey(private_key)
    return private_key, public_key


def keyring(*keys):
    '''generate a keyring dict with the given keys'''
    ring = {
        'keys': [bytes_to_b64_string(k) for k in keys],
        'signatures': [],
    }

    return ring


def keyring_keystring(ring):
    return ''.join(ring['keys']).encode('utf-8')


def keyring_sign(ring, private_key):
    '''generate a signature for the given keyring'''
    nonce = os.urandom(64)
    keystring = keyring_keystring(ring)
    sig = curve.calculateSignature(nonce, private_key, keystring)
    return bytes_to_b64_string(sig)


def keyring_verify_signature(ring, public_key_string, signature_string):
    return 0 is curve.verifySignature(b64_string_to_bytes(public_key_string),
                                      keyring_keystring(ring),
                                      b64_string_to_bytes(signature_string))


def keyring_verify(ring):
    keys = ring['keys']
    sigs = ring['signatures']
    verifications = (keyring_verify_signature(ring, k, s)
                     for k, s in zip(keys, sigs))
    return all(verifications)
