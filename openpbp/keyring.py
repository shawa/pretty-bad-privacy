from typing import Tuple, List
import axolotl_curve25519 as curve
import os

from utils import b64_string_to_bytes, bytes_to_b64_string

def generate_keypair() -> Tuple[bytes, bytes]:
    '''generate a new keypair from the given curve'''
    private_key = curve.generatePrivateKey(os.urandom(32))
    pubkey = curve.generatePublicKey(private_key)
    return private_key, pubkey


class Keyring(object):
    def __init__(self, keys: List[bytes]) -> None:
        '''generate a keyring dict with the given keys'''

        self.keys = [bytes_to_b64_string(k) for k in keys]
        self.sigs = []  # type: List[str]

    def _keystring(self) -> bytes:
        '''return a bytes of the keyring values'''
        return b''.join(b64_string_to_bytes(key)
                        for key in self.keys)


    def signature(self, private_key: bytes) -> str:
        '''generate a signature for the given keyring'''
        nonce = os.urandom(64)
        sig = curve.calculateSignature(nonce, private_key, self._keystring())
        return bytes_to_b64_string(sig)


    def _verify_sig(self, signature: str) -> bool:
        '''
        verify that a signature is valid under one of the keys in the public
        key list
        '''

        verifications = (curve.verifySignature(b64_string_to_bytes(pubkey),
                                               self._keystring(),
                                               b64_string_to_bytes(signature))
                         for pubkey in self.keys)
        valid_sigs = (verification is 0 for verification in verifications)
        return any(valid_sigs)


    def complete(self) -> bool:
        '''a complete keyring is a list of public keys, and a list of
        signatures of that list of public keys, one per public key'''
        assert(len(self.sigs) is len(self.keys))
        return all(self._verify_sig(sig) for sig in self.sigs)
