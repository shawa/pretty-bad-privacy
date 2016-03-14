import unittest
import keyring
import axolotl_curve25519 as curve
import os

from utils import b64_string_to_bytes, bytes_to_b64_string


class TestKeypair(unittest.TestCase):
    def test_keypair_generates_valid_signatures(self):
        '''keypair should generate valid signatures'''

        priv, pub = keyring.generate_keypair()
        nonce = os.urandom(64)
        message = os.urandom(64)
        sig = curve.calculateSignature(nonce, priv, message)
        verification = curve.verifySignature(pub, message, sig)
        self.assertIs(0, verification)


class TestKeyring(unittest.TestCase):
    def test_keyring_signature(self):
        keypairs = [keyring.generate_keypair() for _ in range(3)]
        priv_alice, pub_alice = keypairs[0]
        pub_alice = bytes_to_b64_string(pub_alice)

        pubkeys = (keypair[1] for keypair in keypairs)
        ring = keyring.Keyring(pubkeys)
        sig = ring.signature(priv_alice)

        self.assertTrue(ring._verify_sig(pub_alice, sig))

    def test_keyring_integrity(self):
        keypairs = [keyring.generate_keypair() for _ in range(3)]
        ring = keyring.Keyring([kp[1] for kp in keypairs])
        sigs = [ring.signature(kp[0]) for kp in keypairs]
        ring.signatures = sigs
        self.assertTrue(ring.complete())

if __name__ == '__main__':
    unittest.main()
