import unittest
import keyring
import os

from utils import b64_string_to_bytes, bytes_to_b64_string


class TestKeyring(unittest.TestCase):
    def test_keyring_signature(self):
        keypairs = [keyring.generate_keypair() for _ in range(4)]
        priv_alice, pub_alice = keypairs[0]
        pub_alice = bytes_to_b64_string(pub_alice)

        pubkeys = (keypair[1] for keypair in keypairs)
        ring = keyring.Keyring(pubkeys)
        sig = ring.signature(priv_alice)

        self.assertTrue(ring._verify_sig(sig))

    def test_keyring_integrity(self):
        keypairs = [keyring.generate_keypair() for _ in range(3)]
        ring = keyring.Keyring([kp[1] for kp in keypairs])
        sigs = [ring.signature(kp[0]) for kp in keypairs]
        ring.sigs = sigs
        self.assertTrue(ring.complete())

if __name__ == '__main__':
    unittest.main()
