import unittest
import asymmetric
import os
import sys

from hypothesis import given, settings
from hypothesis.strategies import binary

class TestAsymmetric(unittest.TestCase):
    def test__load_pubkey(self):
        pass

    def test__load_privkey(self):
        pass
    def setUp(self):
        self.kp = asymmetric.gen_keypair()

    @given(binary(min_size=400))
    @settings(max_examples=500)
    def test_encrypt_decrypt(self, plaintext):
        ciphertext = asymmetric.encrypt(plaintext, self.kp.pubkey)
        self.assertIsNotNone(ciphertext)
        decrypted = asymmetric.decrypt(ciphertext, self.kp.privkey)
        self.assertEqual(plaintext, decrypted)


    def test_sign(self):

        pass

    def test_verify(self):
        pass

    def gen_keypair(self):
        pass

if __name__ == '__main__':
    unittest.main()
