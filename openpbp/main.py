'''
Usage:
    pbp keypair <outfile>
    pbp keyring create <outfile> <keys>...
    pbp keyring sign <outfile> <keyring_file> <privkey_file>
    pbp keyring complete <outfile> <keyring_file> <signature_names>...
    pbp keyring verify <keyring_file>
    pbp encrypt <private_key> <keyring_file> <plaintext>
    pbp decrypt <private_key> <origin_pubkey> <ciphertext>

'''

from docopt import docopt
import sys
import json
import keyring
import encryption
import hashlib

def shadigest(data: str) -> str:
    return hashlib.sha512(data.encode('utf-8')).hexdigest()

_HASH_SEP = '||'
def handle_decrypt(arguments):
    _EXTENSION = '.pbp'
    privkey, pubkey = (open(arguments[key], 'r').read().encode('utf-8')
                       for key in ('<private_key>', '<origin_pubkey>'))
    infile = arguments['<ciphertext>']
    outfile = infile.split(_EXTENSION)[0]
    if '.pbp' not in infile:
        raise ValueError('Sanity check: Filename must end in{}'.format(_EXTENSION))

    digest, ciphertext = open(infile).read().split(_HASH_SEP)
    if digest != shadigest(ciphertext):
        raise ValueError('SHA-2 digest failed, someone may be doing something nasty!')

    plaintext = encryption.decrypt(ciphertext, pubkey, privkey)
    with open(outfile, 'wb') as f:
        f.write(plaintext)

def handle_encrypt(arguments):
    privkey_file = arguments['<private_key>']
    keyring_file = arguments['<keyring_file>']
    infile = arguments['<plaintext>']

    keyring_data = json.load(open(keyring_file, 'r'))
    keyring_data['keys'] = [k.encode('utf-8') for k in keyring_data['keys']]
    ring = keyring.Keyring(**keyring_data)

    if not ring.complete():
        raise ValueError('Incomplete keyring given')

    privkey = open(privkey_file, 'r').read().encode('utf-8')
    plaintext = open(infile, 'rb').read()
    ciphertext = encryption.encrypt(plaintext, ring, privkey)
    digest = shadigest(ciphertext)

    with open(infile + '.pbp', 'w') as f:
        f.write(digest + _HASH_SEP)
        f.write(ciphertext)


def handle_keypair(arguments):
    import asymmetric
    base_name = arguments['<outfile>']
    private_outfile = base_name + '.pem'
    public_outfile = private_outfile + '.pub'

    privkey, pubkey = asymmetric.gen_keypair()
    with open(private_outfile, 'w') as f:
        f.write(privkey.decode('utf-8'))

    with open(public_outfile, 'w') as f:
        f.write(pubkey.decode('utf-8'))


def handle_keyring(arguments):
    def create():
        key_names = arguments['<keys>']
        outfile = arguments['<outfile>']
        keys = [open(key_name, 'r').read()
                for key_name in key_names]

        partial_ring = {'keys' : keys, 'sigs': []}
        with open(outfile, 'w') as f:
            json.dump(partial_ring, f, indent=4, sort_keys=True)

    def sign():
        keyring_file = arguments['<keyring_file>']
        privkey_file = arguments['<privkey_file>']
        outfile = arguments['<outfile>']

        keyring_data = open(keyring_file, 'r').read()
        privkey_pem = open(privkey_file).read().encode('utf-8')

        ring = keyring.Keyring.from_json(keyring_data)
        sig = ring.signature(privkey_pem, fmt=str)

        with open(outfile, 'w') as f:
            f.write(sig)

    def complete():
        keyring_file = arguments['<keyring_file>']
        sig_names = arguments['<signature_names>']
        outfile = arguments['<outfile>']
        keyring_data = {
            'keys': [key.encode('utf-8') for key in
                     json.load(open(keyring_file, 'r'))['keys']],
            'sigs': [open(sig_name, 'r').read()
                     for sig_name in sig_names],
        }

        ring = keyring.Keyring(**keyring_data)
        if not ring.complete():
            raise ValueError('Invalid Keyring')

        with open(outfile, 'w') as f:
            out = json.loads(ring.to_json())
            json.dump(out, f, indent=4, sort_keys=True)

    def verify():
        keyring_file = arguments['<keyring_file>']
        outfile = arguments['<outfile>']
        with open(keyring_file, 'r') as f:
            ring = json.load(f)
            ring_data = {
                'keys': [key.encode('utf-8') for key in ring['keys']],
                'sigs': ring['sigs'],
            }

            ring = keyring.Keyring(**ring_data)

        print('{}alid keyring given'
               .format('V' if ring.complete() else 'Inv'))

    if arguments['create']:
        create()
    elif arguments['complete']:
        complete()
    elif arguments['sign']:
        sign()
    elif arguments['verify']:
        verify()


HANDLER = {
       'decrypt': handle_decrypt,
       'encrypt': handle_encrypt,
       'keypair': handle_keypair,
       'keyring': handle_keyring,
}

if __name__ == '__main__':
    arguments = docopt(__doc__, version='Naval Fate 2.0')
    for action in ('decrypt', 'encrypt', 'keypair', 'keyring'):
        if arguments[action]:
            HANDLER[action](arguments)
