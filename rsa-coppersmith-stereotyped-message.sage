# Coppersmith Stereotyped Message Recovery
# Using Sage Math

# Copyright 2021-2022 Maxim Masiutin
# This file may be distributed on conditions of the
# GNU General Public License v3.0

# it implements the following function: stereotyped_message_attack
# to decrypt a "secret" from the message (m) consisting of "prefix | secret | suffix"
# if we only know "prefix" and "suffix" but not the "secret"
# inputs: prefix, length of the secret in bytes, suffix, enc, n, e
# where "n" and "e" are parts of RSA public key, and "enc" is the ciphertext
# output: secret

# to install rerequisites, run
# sage -pip install pycryptodome pycrypto

from Crypto.Util.number import getPrime, inverse, long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto import Random
import secrets


def stereotyped_message_attack(prefix, secret_len_bytes, suffix, enc, n, e):
    ZmodN = Zmod(n)
    P.<x> = PolynomialRing(ZmodN)
    prefix_len_bytes = len(prefix)
    suffix_len_bytes = len(suffix)
    known = ZmodN((bytes_to_long(prefix) * (2**((secret_len_bytes+suffix_len_bytes)*8))) + bytes_to_long(suffix))
    xmultiplier = ZmodN(Integer(2**(suffix_len_bytes*8)))
    enc = ZmodN(enc)
    f = (known+xmultiplier*x)^e - enc
    f = f.monic()
    roots = f.small_roots(epsilon=1/20)
    rc = len(roots)
    if rc == 0:
        return None
    elif rc == 1:
        decrypted = known + xmultiplier * (roots[0])
        return decrypted
    else:
        print("Don't know how to handle situation when multiple roots are returned:", rc)
        sys.exit(1)

def encrypt(m, pubkey):
    n, e = pubkey.n, pubkey.e
    m = bytes_to_long(m)
    return pow(m, e, n)

def test():
    print('Generating primes..')
    public_key = RSA.generate(4096, secrets.token_bytes, e=5)
    e = public_key.e
    n = public_key.n
    suffix = bytearray([0x0a])+"The quick brown fox jumped over ???".encode()
    prefix = "Alice was beginning to get very tired of sitting by her sister on the bank, and of having nothing to do once or twice she had peeped into sister was reading, but it had no pictures or conversations in it, and what is the use of a book thought Alice without".encode() + \
        bytearray([0xe8, 0x01])

    secret_len = 51
    test_secret = ((bytearray([0xff]))*int(secret_len))  # You can also fill this with pseudorandom bytes rather than fixed bytes
    plaintext = prefix+test_secret+suffix
    enc = encrypt(plaintext, public_key)

    e = Integer(e)
    n = Integer(n)
    enc = Integer(enc)
    max_secret_len = max(n.nbits(), enc.nbits())//8 - len(prefix) - len(suffix)
    if secret_len > max_secret_len:
        print("Error: The secret length of", secret_len, "byte(s) is larger then the maximum of",
              max_secret_len, "bytes(s) for the given prefix, suffix, encrypted message and the public exponent!")
        sys.exit(1)

    print("Will recover the secret with the length of up to a maximum",
          max_secret_len, "byte(s).")

    # Attack
    while True:
        print("Trying to recover the secret", secret_len, "byte(s) long...")
        root = stereotyped_message_attack(
            prefix, secret_len, suffix, enc, n, e)
        if root is not None:
            dec = long_to_bytes(root)
            with open("decrypted-message.bin", "wb") as file:
                file.write(dec)
                file.close()
            break
        else:
            if secret_len > max_secret_len:
                print('Could not recover the secret, sorry!')
                sys.exit(1)
        secret_len += 1

    # Result
    print('Decrypted message:', dec)
    print('plaintext=dec', plaintext == dec)

if __name__ == '__main__':
    test()
