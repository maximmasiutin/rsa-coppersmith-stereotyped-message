# Coppersmith Stereotyped Message Recovery
## Using Sage Math

Copyright 2021-2022 Maxim Masiutin

This file may be distributed on conditions of the
GNU General Public License v3.0

It implements the following function: `stereotyped_message_attack`
to decrypt a `secret` from the message `m` consisting of `prefix | secret | suffix`
if we only know `prefix` and `suffix` but not the `secret`.

Inputs: `prefix`, length of the secret in bytes, `suffix`, `enc`, `n`, `e`

Where `n` and `e` are parts of RSA public key, and `enc` is the ciphertext

Output: `secret`

To install rerequisites, run
`sage -pip install pycryptodome pycrypto`


