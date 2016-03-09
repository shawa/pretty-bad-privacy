'''The PBP spec defines a number of keys which are to be used by all parties
these are:
    * Per-group AES-GCM keys
    * Per-member RSA keypairs
    * Per file (session) AES-GCM keys

As these are common to all operations, we define them all here. Should they
need to change, we can simply modify their definitions here.'''

class Keyring(object):
    def __init__(self, pubkeys):
        '''
        create a new (preliminary) keyring

        the keyring will not be usable until all of the signatures
        have been collected and verified

        pubkeys: a list of public keys, in ascii armored format
        '''
        self.pubkeys = pubkeys
        self.PSK = None
        self.digest = None
        self.signatures = []
