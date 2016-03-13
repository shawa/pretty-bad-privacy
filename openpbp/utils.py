from base64 import b64encode, b64decode


def b64_string_to_bytes(string: str) -> bytes:
    return b64decode(string.encode('utf-8'))


def bytes_to_b64_string(byte_string: bytes) -> str:
    return b64encode(byte_string).decode('utf-8')
