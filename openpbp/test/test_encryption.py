import unittest
import os
import sys

import encryption
import asymmetric
import keyring
from utils import b64_string_to_bytes

from hypothesis import given
from hypothesis.strategies import binary, text, lists

class Test__symmetric_encrypt_decrypt(unittest.TestCase):
    @given(binary())
    def test_encrypt_decrypt_inverse(self, plaintext):
        ciphertext, key = encryption._symmetric_encrypt(plaintext)
        self.assertIsNotNone(ciphertext)
        self.assertIsNotNone(key)
        got_plaintext = encryption._symmetric_decrypt(ciphertext, key)
        self.assertEqual(got_plaintext, plaintext)


class Test_pack_keys_and_ciphertext(unittest.TestCase):
    @given(binary(), binary(), binary(), binary())
    def test_pack_unpack_invert(self, a, b, c, ciphertext):
        keys = [a, b, c]
        fmt, packed = encryption.pack_keys_and_ciphertext(keys, ciphertext)
        self.assertIsNotNone(fmt)
        self.assertIsNotNone(packed)
        got_keys, got_ciphertext = encryption.unpack_keys_and_ciphertext(fmt, packed)
        self.assertEqual(keys, got_keys)
        self.assertEqual(ciphertext, got_ciphertext)


class Test_pack_sig_and_block(unittest.TestCase):
    @given(text(min_size=1), binary(min_size=1), binary(min_size=1))
    def test_pack_sig_and_block_invert(self, block_fmt, sig, ciphertext_block):
        fmt, packed = encryption.pack_sig_and_block(block_fmt, sig, ciphertext_block)
        self.assertIsNotNone(fmt)
        self.assertIsNotNone(packed)

        got_block_fmt, got_sig, got_ciphertext_block = encryption.unpack_sig_and_block(fmt, packed)
        self.assertEqual(block_fmt, got_block_fmt)
        self.assertEqual(sig, got_sig)
        self.assertEqual(ciphertext_block, got_ciphertext_block)


class Test_serialize_everything(unittest.TestCase):
    pass

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
