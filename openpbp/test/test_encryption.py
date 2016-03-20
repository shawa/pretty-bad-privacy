import unittest
import os

import encryption
import asymmetric
import keyring
from utils import b64_string_to_bytes

class TestEncryption(unittest.TestCase):
    def test_packing(self):
        msg = os.urandom(64)
        keys = [os.urandom(64) for _ in range(5)]
        fmt, block = encryption.pack_group_block(msg, keys)

        msg_unpacked, keys_unpacked = encryption.unpack_group_block(fmt, block)
        self.assertEqual(msg, msg_unpacked)
        self.assertEqual(keys, keys_unpacked)

    def test_serialization(self):
        msg = os.urandom(64)
        keys = [os.urandom(64) for _ in range(5)]
        fmt, block = encryption.pack_group_block(msg, keys)

        serialized = encryption.serialize_group_block(fmt, block)
        fmt_deser, block_deser = encryption.deserialize_group_block(serialized)
        self.assertEqual(fmt, fmt_deser)
        self.assertEqual(block, block_deser)

    def test_ring_encrypt(self):
        keypairs = [asymmetric.gen_keypair() for _ in range(4)]
        alice = keypairs[0]

        ring = keyring.Keyring([kp.pubkey for kp in keypairs])
        ring.sigs = [ring.signature(kp.privkey, fmt=str) for kp in keypairs]
        message = os.urandom(1024)
        sig_serial, serial = encryption.encrypt_message(ring, alice.privkey,
                                                        message)
        sig = b64_string_to_bytes(sig_serial)
        serial_bin = serial.encode('utf-8')
        self.assertTrue(asymmetric.verify(serial_bin, sig, alice.pubkey))

    def test_ring_decrypt(self):
        keypairs = [asymmetric.gen_keypair() for _ in range(4)]
        alice = keypairs[0]
        ring = keyring.Keyring([kp.pubkey for kp in keypairs])
        ring.sigs = [ring.signature(kp.privkey, fmt=str) for kp in keypairs]
        plaintext = os.urandom(1024)
        sig_serial, serial = encryption.encrypt_message(ring, alice.privkey, plaintext)

        gotten_plaintext = encryption.decrypt_message(alice.privkey,
                                                      alice.pubkey,
                                                      sig_serial,
                                                      serial)

        self.assertEqual(plaintext, gotten_plaintext)
