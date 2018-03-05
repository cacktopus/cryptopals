import base64
import random

import s2c11
from s2c10 import cbc_encrypt, cbc_decrypt
from pkcs7_padding import pkcs7_padding_valid, pkcs7_padding
from s2c13 import get_all_blocks

KEY = s2c11.random_AES_key()

strings = b"""
MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
""".split()

strings = [base64.b64decode(s) for s in strings]
s = random.choice(strings)


def get_cookie():
    padded = pkcs7_padding(s, 16)
    iv = s2c11.random_bytes(16)
    em = cbc_encrypt(KEY, padded, iv=iv)
    return em, iv


def check_token(ct: bytes, iv: bytes) -> bool:
    padded = cbc_decrypt(KEY, ct, iv)
    return pkcs7_padding_valid(padded, 16)


def main():
    ct, iv = get_cookie()
    print(ct)
    print(iv)

    print(check_token(ct, iv))

    blocks = get_all_blocks(ct)
    n = len(blocks)
    prefix = b"".join(blocks[:n - 1])

    last = list(blocks[-1])

    for i in range(256):
        trial = prefix + bytes(last[:15] + [i])
        assert len(trial) % 16 == 0

        a = check_token(trial, iv)
        b = trial == ct

        if a or b:
            print(i, a, b)


if __name__ == '__main__':
    main()
