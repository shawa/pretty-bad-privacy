import unittest
import keyring
import asymmetric
import os

from utils import b64_string_to_bytes, bytes_to_b64_string


class TestKeyring(unittest.TestCase):
    def test_keyring_signature(self):
        keypairs = [asymmetric.gen_keypair() for _ in range(3)]
        ring = keyring.Keyring([kp.pubkey for kp in keypairs])
        alice = keypairs[0]
        sig = ring.signature(alice.privkey, fmt=str)
        self.assertTrue(ring._verify_sig(sig))

    def test_keyring_complete(self):
        keypairs = [asymmetric.gen_keypair() for _ in range(3)]
        ring = keyring.Keyring([kp.pubkey for kp in keypairs])
        alice = keypairs[0]
        ring.sigs = [ring.signature(kp.privkey, fmt=str) for kp in keypairs]
        self.assertTrue(ring.is_complete)

    def test_encryption(self):
        keypairs = [asymmetric.gen_keypair() for _ in range(3)]
        ring = keyring.Keyring([kp.pubkey for kp in keypairs])
        ring.sigs = [ring.signature(kp.privkey, fmt=str) for kp in keypairs]

        plaintext = os.urandom(64)
        messages = ring.encrypt(plaintext)

        plains = (asymmetric.decrypt(msg, kp.privkey)
                  for kp, msg in zip(keypairs, messages))

        for plain in plains:
            self.assertEqual(plaintext, plain)


if __name__ == '__main__':
    unittest.main()
