'''The PBP spec defines a number of keys which are to be used by all parties
these are:
    * Per-group AES-GCM keys
    * Per-member RSA keypairs
    * Per file (session) AES-GCM keys

As these are common to all operations, we define them all here. Should they
need to change, we can simply modify their definitions here.'''

class PublicKey(object):
    def __init__(self):
        pass


class PrivateKey(object):
    def __init__(self):
        pass


class GroupPSK(object):
    def __init__(self):
        pass


class SessionKey(object):
    def __init__(self):
        pass

