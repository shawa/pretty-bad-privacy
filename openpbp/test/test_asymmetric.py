import unittest
import asymmetric
import os

class TestAsymmetric(unittest.TestCase):
    def test__load_pubkey(self):
        pass

    def test__load_privkey(self):
        pass

    def test_encrypt_decrypt(self):
        kp = asymmetric.gen_keypair()
        plaintext = os.urandom(256)
        ciphertext = asymmetric.encrypt(plaintext, kp.pubkey)
        decrypted = asymmetric.decrypt(ciphertext, kp.privkey)
        self.assertEqual(plaintext, decrypted)


    def test_sign(self):
        pass

    def test_verify(self):
        pass

    def gen_keypair(self):
        pass

if __name__ == '__main__':
    unittest.main()
