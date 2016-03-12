import axolotl_curve25519 as curve
import os
import base64


def str2b64str(string):
    return base64.b64encode(string).decode('utf-8')


def b64str2str(string):
    return base64.b64decode(string).decode('utf-8')


def generate_keypair():
    private_key = curve.generatePrivateKey(os.urandom(32))
    public_key = curve.generatePublicKey(private_key)
    return private_key, public_key


def keyring(*keys):
    '''generate a keyring dict with the given keys'''
    ring = {
        'keys': [str2b64str(k) for k in keys],
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
    return str2b64str(sig)


def keyring_verify_signature(ring, public_key, signature):
    sig = base64.b64decode(signature)
    pubkey = base64.b64decode(public_key)
    return 0 is curve.verifySignature(public_key,
                                      keyring_keystring(ring),
                                      sig)


def keyring_verify(ring):
    keys = ring['keys']
    sigs = ring['signatures']
    verifications = (keyring_verify_signature(ring, k, s)
                     for k, s in zip(keys, sigs))
    return all(verifications)
