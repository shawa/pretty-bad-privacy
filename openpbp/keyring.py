from typing import Tuple, List, Union
import asymmetric
import os
import json

from utils import b64_string_to_bytes, bytes_to_b64_string

class Keyring(object):
    def __init__(self, keys: List[bytes], sigs: List[str]=None) -> None:
        '''generate a keyring dict with the given keys'''
        if not all(type(key) is bytes for key in keys):
            raise ValueError('keys must be a list of bytes objects')

        self.keys = keys
        # just `if sigs'
        self.sigs = sigs if sigs is not None else [] # type: List[str]

    def to_json(self) -> str:
        # you could just make this a lambda
        def _stringify(l):
            return [member.decode('utf-8') for member in l]
        return json.dumps({'keys': _stringify(self.keys), 'sigs': self.sigs})

    @classmethod
    def from_json(cls, json_data: str):
        ring_dict = json.loads(json_data)
        ring_dict['keys'] = [key.encode('utf-8') for key in ring_dict['keys']]
        # just call 'cls' instead of 'Keyring' here
        return Keyring(**ring_dict)

    # Make this a property
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

    # Make this a property
    def complete(self) -> bool:
        '''a complete keyring is a list of public keys, and a list of
        signatures of that list of public keys, one per public key'''
        if not len(self.sigs) is len(self.keys):
            return False

        return all(self._verify_sig(sig) for sig in self.sigs)

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
