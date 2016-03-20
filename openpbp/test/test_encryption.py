import unittest
import os

import encryption

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
