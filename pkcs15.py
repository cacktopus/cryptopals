#!/usr/bin/env python

import binascii
import os
import sys
from hashlib import sha256

from Crypto.PublicKey import RSA

from util import modexp

SHA256_HEADER = binascii.unhexlify("3031300d060960864801650304020105000420")


def emsa_pcks1_v1_5_encode(m, em_len, hashfunc=sha256):
    digest = sha256(m).digest()

    t = SHA256_HEADER + digest

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


def sign(key, em_len: int) -> bytes:
    fn = sys.argv.pop(0)
    data = open(fn, "rb").read()
    em = emsa_pcks1_v1_5_encode(data, em_len)
    n = os2ip(em)
    s = rsasp1(key.n, key.d, n)
    o = i2osp(s, em_len)
    return o


def decode(key, em_len: int) -> bytes:
    fn = sys.argv.pop(0)
    data = open(fn, "rb").read()
    s = os2ip(data)
    m = modexp(s, key.n, key.e)
    d = i2osp(m, em_len)
    return d


def decode_pkcs_padding_unsafe(d):
    c, d = d[0], d[1:]
    assert c == 0x00

    c, d = d[0], d[1:]
    assert c == 0x01

    while True:
        c, d = d[0], d[1:]
        if c == 0xff:
            continue

        elif c == 0x00:
            break

        else:
            assert 0, "Invalid padding"

    return d


def check_sha256_header(d):
    ln = len(SHA256_HEADER)
    c, d = d[:ln], d[ln:]

    if len(c) != ln:
        assert 0, "Invalid header"

    for i in range(ln):
        if SHA256_HEADER[i] != c[i]:
            assert 0, "Invalid header"

    return d[:32]


def verify_unsafe(key, em_len):
    sig_fn = sys.argv.pop(0)
    data = open(sig_fn, "rb").read()
    s = os2ip(data)
    m = modexp(s, key.n, key.e)
    d = i2osp(m, em_len)

    d = decode_pkcs_padding_unsafe(d)
    d = check_sha256_header(d)

    data_fn = sys.argv.pop(0)
    data = open(data_fn, "rb").read()
    sig1 = sha256(data).hexdigest()
    sig2 = binascii.hexlify(d).decode()

    assert sig1 == sig2, "Signature mismatch: " + str(sig1) + " != " + str(sig2)

    return b'Verified OK\n'


def unknown_command(*args):
    raise RuntimeError("Unknown command")


def main():
    path = os.path.expanduser("~/.ssh")
    testkey = os.path.join(path, "testkey")

    key = RSA.importKey(open(testkey).read())

    h = hex(key.n)
    n = binascii.unhexlify(h.lstrip("0x"))  # TODO: should be better way to do this
    em_len = len(n)

    cmd = sys.argv.pop(0)
    cmd = os.path.basename(cmd)

    fn = {
        "sign": sign,
        "verify-unsafe": verify_unsafe,
        "decode": decode,
    }.get(cmd, unknown_command)

    o = fn(key, em_len)
    sys.stdout.buffer.write(o)


if __name__ == '__main__':
    main()
