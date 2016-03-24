import unittest
import os
import sys

import encryption
import asymmetric
import keyring
from utils import b64_string_to_bytes

from hypothesis import given
from hypothesis.strategies import binary, lists

class Test_pack_unpack_group_block(unittest.TestCase):
    @given(binary(min_size=1), binary(min_size=1), binary(min_size=1), binary(min_size=1))
    def test_gotten_is_given(self, message, k1, k2, k3):
        keys = [k1, k2, k3]
        fmt, block = encryption.pack_group_block(message, keys)
        g_msg, g_keys = encryption.unpack_group_block(fmt, block)
        self.assertEqual(message, g_msg)
        self.assertEqual(keys, g_keys)

class Test_serialize_group_block(unittest.TestCase):
    pass


class Test_deserialize_group_block(unittest.TestCase):
    pass


class Test_serialize_message(unittest.TestCase):
    pass


class Test_deserialize_message(unittest.TestCase):
    pass


class Test_encrypt_message(unittest.TestCase):
    pass


class Test_decrypt_message(unittest.TestCase):
    pass
