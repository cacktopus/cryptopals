import base64
import random
from typing import List

import s2c11
from s1c2 import xor2
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


def get_cookie(key: bytes = KEY):
    padded = pkcs7_padding(s, 16)
    iv = s2c11.random_bytes(16)
    em = cbc_encrypt(key, padded, iv=iv)
    return em, iv


def check_token(ct: bytes, iv: bytes, key: bytes = KEY) -> bool:
    padded = cbc_decrypt(key, ct, iv)
    return pkcs7_padding_valid(padded, 16)


def padding_oracle_attack(
        block: List[int],
        iv: List[int],
        internal_state: List[int],
        key: bytes = KEY,
) -> bytes:
    # I believe there is a rare failure case this doesn't handle

    if len(internal_state) == len(block):
        return xor2(internal_state, iv)

    pad_length = len(block) - len(internal_state) - 1
    pad = [0] * pad_length

    target = len(internal_state) + 1

    augmented = [c ^ target for c in internal_state]

    for i in range(256):

        trial = pad + [i] + augmented
        assert len(trial) % 16 == 0

        a = check_token(bytes(block), bytes(trial), key=key)

        if a:
            internal_char = i ^ target
            return padding_oracle_attack(block, iv, [internal_char] + internal_state, key)

    assert 0, "not supposed to be here"


def main():
    ct, iv = get_cookie()
    blocks = get_all_blocks(ct)

    answer = padding_oracle_attack(list(blocks[0]), iv, [])
    print(answer)


if __name__ == '__main__':
    main()
