import binascii
import itertools
import math
import os
from hashlib import sha256

from Crypto.PublicKey import RSA

from pkcs15 import i2osp, SHA256_HEADER, os2ip
from util import modexp

DEBUG = False
debug = print if DEBUG else lambda *args, **kwargs: None


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
    priv_key = os.environ.get('RSA_KEY', 'test/fixtures/e3_test_key')

    with open(priv_key) as f:
        key = RSA.importKey(f.read())

    key_byte_len = round_up_power_2(key.size()) // 8

    debug(key_byte_len)

    content = b'hi mom'
    digest = sha256(content).digest()

    ff_len = 6

    msg = b'\x00' + b'\x01' + b'\xff' * ff_len + b'\x00' + SHA256_HEADER + digest

    pad_len = key_byte_len - len(msg)
    padded = (msg + b'\x00' * pad_len)

    n = os2ip(padded)
    nxt = icbrt(n) + 1

    debug(n, end="\n\n")

    res = modexp(nxt, key.n, key.e)
    # res = nxt ** 3

    assert res < key.n

    debug(res, end="\n\n")

    debug(nxt, end="\n\n")

    forgery = i2osp(res)

    debug(binascii.hexlify(i2osp(n)), end="\n\n")
    debug(binascii.hexlify(forgery), end="\n\n")


if __name__ == '__main__':
    main()
