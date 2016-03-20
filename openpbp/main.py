import argparse

'''
pbp keypair
pbp keyring create <keys>
pbp verify <keyring file>
pbp encrypt <keyring file> <plaintext>
pbp decrypt <private key> <ciphertext>
'''
def main():
    actions = [
            'gen_keypair',
            'create_keyring',
            'verify_keyring',
            'encrypt',
            'decrypt',
    ]
    p = argparse.ArgumentParser()
    p.add_argument('action', type=str, choices=actions)

