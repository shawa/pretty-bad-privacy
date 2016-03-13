def generatePrivateKey(nonce: bytes) -> bytes:
    pass


def generatePublicKey(private_key: bytes) -> bytes:
    pass


def calculateAgreement(private_key: bytes, public_key: bytes) -> bytes:
    pass


def calculateSignature(nonce: bytes, private_key: bytes, message: bytes) -> bytes:
    pass


def verifySignature(public_key: bytes, message: bytes, signature: bytes) -> int:
    pass


