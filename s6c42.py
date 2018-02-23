import binascii
import itertools
import math
import os
import sys
from hashlib import sha256

from Crypto.PublicKey import RSA

from pkcs15 import i2osp, SHA256_HEADER, os2ip
from util import modexp


def hexdump(s):
    return binascii.hexlify(s)


def next_perfect_cube(n):
    for i in itertools.count():
        if i ** 3 > n:
            return i


def icbrt(n: int, lo: int = 1, hi: int = None):
    """integer cube root"""
    hi = hi or n

    while hi - lo != 1:
        trial = lo + (hi - lo) // 2
        r = trial ** 3

        if r > n:
            hi = trial

        else:
            lo = trial

    return lo


def round_up_power_2(n):
    m = int(math.floor(math.log2(n))) + 1
    return 2 ** m


def main():
    priv_key = os.environ.get('RSA_KEY', 'mykey')
    key = RSA.importKey(open(priv_key).read())

    key_byte_len = round_up_power_2(key.size()) // 8

    print(key_byte_len)

    content = b'hi mom'
    digest = sha256(content).digest()

    ff_len = 6

    msg = b'\x00' + b'\x01' + b'\xff' * ff_len + b'\x00' + SHA256_HEADER + digest

    pad_len = key_byte_len - len(msg)
    padded = (msg + b'\x00' * pad_len)

    n = os2ip(padded)
    nxt = icbrt(n) + 1

    print(n, end="\n\n")

    res = modexp(nxt, key.n, key.e)
    # res = nxt ** 3

    assert res < key.n

    print(res, end="\n\n")

    print(nxt, end="\n\n")

    forgery = i2osp(res)

    print(binascii.hexlify(i2osp(n)), end="\n\n")
    print(binascii.hexlify(forgery), end="\n\n")


if __name__ == '__main__':
    main()
