import hashlib

settings = {} # type: dict

def import_key(pubkey: bytes, nickname: str) -> bool:
    digest = hashlib.sha256(pubkey).hexdigest()
    key_dict = {
            'nickname': nickname,
            'digest': digest,
            'pem_data': pubkey,
    }

    if digest not in (k['digest'] for k in settings['keys']):
        settings['keys'].append(key_dict)

def trust_key(nickname):
    pass
