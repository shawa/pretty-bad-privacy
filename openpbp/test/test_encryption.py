import unittest
import os

import encryption

class TestEncryption(unittest.TestCase):
    def test_packing(self):
        msg = os.urandom(64)
        keys = [os.urandom(64) for _ in range(5)]
        fmt, block = encryption.pack_group_block(msg, keys)

        msg_unpacked, keys_unpacked = encryption.unpack_group_block(fmt, block)
        self.assertEquals(msg, msg_unpacked)
        self.assertEquals(keys, keys_unpacked)
