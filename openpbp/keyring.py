def sym_encrypt(*args):
    pass


def asym_encrypt(*args):
    pass


def asym_sign(*args):
    pass


def asym_verify_signature(*args):
    pass


class Keyring(object):
    def __init__(self, keys=None, signatures=None):
        self.pubkeys = (keys if keys is not None else [])
        self.signatures = (signatures if signatures is not None else [])

    def approve(self, private_key):
        asym_verify_signature(self.signature[0], self.keys)
        signature = asym_sign(private_key, self.keys)
        return signature

    def verify(self):
        pass

    def encrypt(self, data, private_key):
        session_key = 'Random data'
        session_keys_encrypted = (asym_encrypt(session_key, pubkey)
                                  for pubkey in self.pubkeys)

        ciphertext = sym_encrypt(data, session_key)

        prepackage = (list(session_keys_encrypted), ciphertext)
        signature = asym_sign(private_key, prepackage)
        return (prepackage, signature)

    def decrypt(self, package, private_key):
        pass
