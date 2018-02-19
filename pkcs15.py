#!/usr/bin/env python

import binascii
import os
import sys
from hashlib import sha256

from Crypto.PublicKey import RSA

from util import modexp


def emsa_pcks1_v1_5_encode(m, em_len, hashfunc=sha256):
    a = "30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20".replace(" ", "")
    b = binascii.unhexlify(a)

    digest = sha256(m).digest()
    # output = binascii.hexlify(digest)

    t = b + digest

    ps_len = em_len - len(t) - 3
    ps = b'\xff' * ps_len

    em = b'\x00' + b'\x01' + ps + b'\x00' + t

    return em


def os2ip(bin):
    return int(binascii.hexlify(bin), 16)


def i2osp(n, x_len: int):
    n_ = hex(n)[2:]
    pad_len = 2 * x_len - len(n_)
    padding = "0" * pad_len

    return binascii.unhexlify(padding + n_)


def rsasp1(n, d, m):
    return modexp(m, n, d)


def main():
    path = os.path.expanduser("~/.ssh")
    testkey = os.path.join(path, "testkey")

    key = RSA.importKey(open(testkey).read())

    h = hex(key.n)
    n = binascii.unhexlify(h.lstrip("0x"))  # TODO: should be better way to do this

    em_len = len(n)

    def sign():
        data = open("decode_single_char_xor.py", "rb").read()
        em = emsa_pcks1_v1_5_encode(data, em_len)

        n = os2ip(em)

        s = rsasp1(key.n, key.d, n)
        s_ = i2osp(s, em_len)

        sys.stdout.buffer.write(s_)

    def verify():
        data = open("sig", "rb").read()
        s = os2ip(data)
        m = modexp(s, key.n, key.e)
        d = i2osp(m, em_len)
        sys.stdout.buffer.write(d)

    cmd = sys.argv[0]
    cmd = os.path.basename(cmd)

    if cmd == "sign":
        return sign()

    if cmd == "verify":
        return verify()

    raise RuntimeError("Unknown command")


if __name__ == '__main__':
    main()
