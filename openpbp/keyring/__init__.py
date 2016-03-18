from typing import Tuple, List, Union
import asymmetric
import os


from utils import b64_string_to_bytes, bytes_to_b64_string

class Keyring(object):
    def __init__(self, keys: List[bytes]) -> None:
        '''generate a keyring dict with the given keys'''

        self.keys = keys
        self.sigs = []  # type: List[str]


    def _keystring(self) -> bytes:
        '''return a bytes of the concatenated keyring PEM data values'''
        return b''.join(self.keys)


    def signature(self, private_key: bytes, fmt=bytes) -> Union[str, bytes]:
        '''generate a signature for the given keyring'''
        assert fmt in [str, bytes]

        nonce = os.urandom(64)
        sig = asymmetric.sign(self._keystring(), private_key)

        if fmt is str:
            return bytes_to_b64_string(sig)
        else:
            return sig


    def _verify_sig(self, signature: str) -> bool:
        ''' verify that a signature is valid under one of the keys in the public key list '''
        sig = b64_string_to_bytes(signature) # type: bytes
        concat = self._keystring()
        return any(asymmetric.verify(concat, sig, pubkey)
                   for pubkey in self.keys)

    def encrypt(self, message: bytes) -> List[bytes]:
        '''encrypt a given message for each recipient in the key list'''
        assert self.complete()
        return [asymmetric.encrypt(message, key) for key in self.keys]

    def complete(self) -> bool:
        '''a complete keyring is a list of public keys, and a list of
        signatures of that list of public keys, one per public key'''
        assert len(self.sigs) is len(self.keys)
        return all(self._verify_sig(sig) for sig in self.sigs)
