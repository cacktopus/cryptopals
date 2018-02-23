import os

import binascii

import sys

import itertools

import math
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

    key_sz = round_up_power_2(key.size())

    print(key_sz)

    msg = b'\x00' + b'\x01' + b'\xff' * (16 - 3) + b'\x00' + SHA256_HEADER + b'\x00' * 128
    n = os2ip(msg)
    nxt = icbrt(n) + 1

    res = modexp(nxt, key.n, key.e)

    sys.stdout.buffer.write(i2osp(n, 64*8))
    sys.stdout.buffer.write(i2osp(res, 64*8))
    sys.stdout.buffer.write(i2osp(nxt, 64*8))


if __name__ == '__main__':
    main()
