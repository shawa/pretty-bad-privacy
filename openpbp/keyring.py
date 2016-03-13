from typing import Tuple, List
import axolotl_curve25519 as curve
import os

from utils import b64_string_to_bytes, bytes_to_b64_string

def generate_keypair() -> Tuple[bytes, bytes]:
    '''generate a new keypair from the given curve'''
    private_key = curve.generatePrivateKey(os.urandom(32))
    public_key = curve.generatePublicKey(private_key)
    return private_key, public_key


class Keyring(object):
    def __init__(self, keys: List[bytes]) -> None:
        '''generate a keyring dict with the given keys'''

        self.keys = [bytes_to_b64_string(k) for k in keys]
        self.signatures = []  # type: List[str]

    def _keystring(self) -> bytes:
        '''return a bytes of the keyring values'''
        return b''.join(b64_string_to_bytes(key)
                        for key in self.keys)


    def signature(self, private_key: bytes) -> str:
        '''generate a signature for the given keyring'''
        nonce = os.urandom(64)
        sig = curve.calculateSignature(nonce, private_key, self._keystring())
        return bytes_to_b64_string(sig)


    def _verify_sig(self, public_key: str, signature: str):
        verification = curve.verifySignature(b64_string_to_bytes(public_key),
                                            self._keystring(),
                                            b64_string_to_bytes(signature))
        return verification is 0


    def complete(self, ring: dict) -> bool:
        key_signatures = zip(self.keys, self.signatures)
        verifications = (self._verify_sig(public_key, signature)
                         for public_key, signature in key_signatures)

        return all(verifications)

    def add_signature(self, signature):
        assert(_verify_sig(s
