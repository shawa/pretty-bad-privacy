import unittest
import utils
import os


class TestEncodeDecode(unittest.TestCase):
    def test_b64_bytes_idempotency(self):
        bs = os.urandom(32)
        b64_bs = utils.bytes_to_b64_string(bs)
        res = utils.b64_string_to_bytes(b64_bs)
        self.assertEqual(bs, res)

if __name__ == '__main__':
    unittest.main()
