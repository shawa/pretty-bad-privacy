from cryptography.fernet import Fernet
from keyring import Keyring

class RingEncryptedMessage(object):
    def __init__(self, ring: Keyring, message: bytes) -> None:
        symmetric_key = Fernet.generate_key()
        f = Fernet(symmetric_key)
        self.symmetric_keys = ring.encrypt(symmetric_key)
