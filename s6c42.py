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

    if hi - lo == 1:
        return lo  # TODO: try perfect cubes

    trial = lo + (hi - lo) // 2
    r = trial ** 3

    print(lo, hi, trial, r)

    if r > n:
        return icbrt(n, lo, trial)

    else:
        return icbrt(n, trial, hi)


def main():
    print(icbrt((999999999999999111321312310287398127**2+1298310923)**3))

    # priv_key = os.environ.get('RSA_KEY', 'mykey')
    # key = RSA.importKey(open(priv_key).read())
    #
    # res = modexp(2, key.n, key.e)
    # # print(key.size())
    #
    # msg = 0x1ffffff00000ff00
    # # print(msg)
    #
    # i = next_perfect_cube(msg)
    # nxt = (i - 1) ** 3
    # # print(nxt)
    #
    # em = i2osp(msg, 16)
    # # sys.stdout.buffer.write(em)
    #
    # sys.stdout.buffer.write(i2osp(nxt, 16))


if __name__ == '__main__':
    main()
