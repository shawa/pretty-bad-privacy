import unittest
import asymmetric
import os
import sys

from hypothesis import given, settings
from hypothesis.strategies import binary

import cryptography.hazmat.backends.openssl

class TestAsymmetric(unittest.TestCase):
    def setUp(self):
        self.kp = asymmetric.gen_keypair()

    def gen_keypair(self):
        self.assertNotNone(self.kp.pubkey)
        self.assertNotNone(self.kp.privkey)

    def test__load_pubkey(self):
        pubkey_pem = self.kp.pubkey
        key = asymmetric._load_pubkey(pubkey_pem)
        self.assertIsNotNone(key)

    def test__load_privkey(self):
        privkey_pem = self.kp.privkey
        key = asymmetric._load_privkey(privkey_pem)
        self.assertIsNotNone(key)

    @given(binary())
    def test_encrypt_decrypt(self, plaintext):
        ciphertext = asymmetric.encrypt(plaintext, self.kp.pubkey)
        self.assertIsNotNone(ciphertext)
        decrypted = asymmetric.decrypt(ciphertext, self.kp.privkey)
        self.assertEqual(plaintext, decrypted)

    @given(binary(min_size=1))
    def test_sign_verify(self, message):
        sig = asymmetric.sign(message, self.kp.privkey)
        valid = asymmetric.verify(message, sig, self.kp.pubkey)
        self.assertTrue(valid)


if __name__ == '__main__':
    unittest.main()
