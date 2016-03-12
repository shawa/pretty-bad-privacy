import unittest
import keyring
import axolotl_curve25519 as curve
import os


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
        '''generate a signature for the base65 concat of keys'''
        keypairs = [keyring.generate_keypair() for _ in range(3)]
        priv_alice, pub_alice = keypairs[0]

        pubkeys = (keypair[1] for keypair in keypairs)
        b64pubkeys = (base64.encode(k) for k in pubkeys)

        ring = keyring.keyring(*pubkeys)
        sig = keyring.keyring_sign(ring, priv_alice)

        self.assertTrue(keyring.keyring_verify_signature(ring,
                                                         pub_alice,
                                                         sig))

    def test_keyring_integrity(self):
        keypairs = [keyring.generate_keypair() for _ in range(3)]
        ring = keyring.keyring(*(kp[1] for kp in keypairs))
        sigs = [keyring.keyring_sign(ring, kp[0]) for kp in keypairs]
        ring['signatures'] = sigs
        self.assertTrue(keyring.keyring_verify(ring))

if __name__ == '__main__':
    unittest.main()
