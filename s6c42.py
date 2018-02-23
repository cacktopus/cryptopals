import os

import binascii

import sys

import itertools
from Crypto.PublicKey import RSA

from pkcs15 import i2osp
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


def main():
    # print(icbrt(16000))
    # print(icbrt((999999999999999111321312310287398127**3**3+1298310923)**3))

    priv_key = os.environ.get('RSA_KEY', 'mykey')
    key = RSA.importKey(open(priv_key).read())

    res = modexp(2, key.n, key.e)
    # print(key.size())

    msg = key.n << 8
    nxt = icbrt(msg)
    # print(nxt)

    res = modexp(nxt, key.n, key.e)

    sys.stdout.buffer.write(i2osp(msg, 32))
    sys.stdout.buffer.write(i2osp(res, 32))
    sys.stdout.buffer.write(i2osp(nxt, 32))


if __name__ == '__main__':
    main()
