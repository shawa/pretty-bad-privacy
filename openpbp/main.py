'''
Usage:
    pbp keypair <outfile>
    pbp keyring create <keys>...
    pbp keyring sign <keyring_file> <privkey_file>
    pbp keyring complete <keyring_file> <signature_names>...
    pbp encrypt <private_key> <keyring_file> <plaintext>
    pbp decrypt <private_key> <ciphertext>

'''

from docopt import docopt
import sys
import json
import keyring
import encryption

def handle_decrypt(arguments):
    pass


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
    plaintext = open(infile, 'r').read().encode('utf-8')
    sig, ciphertext = encryption.encrypt_message(ring, privkey, plaintext)
    output = '{}{}{}'.format(sig, encryption.MAGIC_MARKER, ciphertext)
    print(output)

def handle_keypair(arguments):
    import asymmetric
    private_outfile = arguments['<outfile>']
    public_outfile = private_outfile + '.pub'

    privkey, pubkey = asymmetric.gen_keypair()
    with open(private_outfile, 'w') as f:
        f.write(privkey.decode('utf-8'))

    with open(public_outfile, 'w') as f:
        f.write(pubkey.decode('utf-8'))


def handle_keyring(arguments):
    def create():
        key_names = arguments['<keys>']
        pubkey_names = [key_name + '.pub' for key_name in key_names]
        signature_names = [key_name + '.sig' for key_name in key_names]

        keys = [open(pubkey_name, 'r').read()
                for pubkey_name in pubkey_names]

        partial_ring = {'keys' : keys, 'sigs': []}
        json.dump(partial_ring, sys.stdout)

    def sign():
        keyring_file = arguments['<keyring_file>']
        privkey_file = arguments['<privkey_file>']
        keyring_data = open(keyring_file, 'r').read()
        privkey_pem = open(privkey_file).read().encode('utf-8')
        ring = keyring.Keyring.from_json(keyring_data)
        sig = ring.signature(privkey_pem, fmt=str)
        with open(privkey_file + '.sig', 'w') as f:
            f.write(sig)

    def complete():
        keyring_file = arguments['<keyring_file>']
        sig_names = arguments['<signature_names>']
        keyring_data = {
            'keys': [key.encode('utf-8') for key in
                     json.load(open(keyring_file, 'r'))['keys']],
            'sigs': [open(sig_name + '.sig', 'r').read()
                     for sig_name in sig_names],
        }

        ring = keyring.Keyring(**keyring_data)
        if not ring.complete():
            raise ValueError('Invalid signature/key data')

        print(ring.to_json())

    if arguments['create']:
        create()
    if arguments['complete']:
        complete()
    elif arguments['sign']:
        sign()


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
