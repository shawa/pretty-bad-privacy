'''
Usage:
    pbp keypair <outfile>
    pbp keyring <keys>...
    pbp verify <keyring_file>
    pbp encrypt <keyring_file> <plaintext>
    pbp decrypt <private_key> <ciphertext>
'''

from docopt import docopt
import sys

def handle_decrypt(arguments):
    pass


def handle_encrypt(arguments):
    pass


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
    import json
    key_names = arguments['<keys>']
    pubkey_names = [key_name + '.pub' for key_name in key_names]
    signature_names = [key_name + '.sig' for key_name in key_names]

    keys = [open(pubkey_name, 'r').read()
            for pubkey_name in pubkey_names]

    partial_ring = {'keys' : keys, 'sigs': []}
    outfile_name = arguments['--outfile']
    if outfile_name:
        with open(arguments['outfile'], 'w') as f:
            json.dump(partial_ring, sys.stdout)
    else:
        print(json.dumps(partial_ring))

def handle_verify(arguments):
    pass


HANDLER = {
       'decrypt': handle_decrypt,
       'encrypt': handle_encrypt,
       'keypair': handle_keypair,
       'keyring': handle_keyring,
       'verify': handle_verify,
}

if __name__ == '__main__':
    arguments = docopt(__doc__, version='Naval Fate 2.0')
    for action in ('decrypt', 'encrypt', 'keypair', 'keyring', 'verify'):
        if arguments[action]:
            HANDLER[action](arguments)
