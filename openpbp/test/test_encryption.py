import unittest
import os
import sys

import encryption
import asymmetric
import keyring
from utils import b64_string_to_bytes

from hypothesis import given
from hypothesis.strategies import binary, lists

class Test__symmetric_encrypt_decrypt(unittest.TestCase):
    @given(binary())
    def test_encrypt_decrypt_inverse(self, plaintext):
        ciphertext, key = encryption._symmetric_encrypt(plaintext)
        self.assertIsNotNone(ciphertext)
        self.assertIsNotNone(key)
        got_plaintext = encryption._symmetric_decrypt(ciphertext, key)
        self.assertEqual(got_plaintext, plaintext)

class Test_encrypt(unittest.TestCase):
    def setUp(self):
        self.alice = asymmetric.gen_keypair()
        self.bob = asymmetric.gen_keypair()
        self.carol = asymmetric.gen_keypair()
        self.derek = asymmetric.gen_keypair()

        keys = [kp.pubkey
                for kp in (self.alice, self.bob, self.carol, self.derek)]

        ring = keyring.Keyring(keys)
        sigs = [ring.signature(kp.privkey, fmt=str)
                for kp in (self.alice, self.bob, self.carol, self.derek)]

        ring.sigs = sigs
        self.assertTrue(ring.complete)

    def test_encrypt(self):
        self.assertTrue(True)
