#!/usr/bin/env python

import os

import binascii

import sys
from Crypto.PublicKey import RSA

import pkcs15
import util


def sign_cmd(key, em_len: int) -> bytes:
    fn = sys.argv.pop(0)
    data = open(fn, "rb").read()
    return pkcs15.sign(key, em_len, data)


def decode_cmd(key, em_len: int) -> bytes:
    fn = sys.argv.pop(0)
    data = open(fn, "rb").read()
    s = pkcs15.os2ip(data)
    m = util.modexp(s, key.n, key.e)
    d = pkcs15.i2osp(m, em_len)
    return d


def verify_unsafe_cmd(key, em_len):
    sig_fn = sys.argv.pop(0)
    sig = open(sig_fn, "rb").read()

    data_fn = sys.argv.pop(0)
    data = open(data_fn, "rb").read()

    verified, info = pkcs15.verify_unsafe(key, em_len, sig, data)

    assert verified, "Signature mismatch: " + str(info["sig1"]) + " != " + str(info["sig2"])

    return b'Verified OK\n'


def unknown_command(*args):
    raise RuntimeError("Unknown command")


def main():
    priv_key = os.environ['RSA_KEY']
    key = RSA.importKey(open(priv_key).read())

    h = hex(key.n)
    n = binascii.unhexlify(h.lstrip("0x"))  # TODO: should be better way to do this
    em_len = len(n)

    sys.argv.pop(0)
    cmd = sys.argv.pop(0)
    cmd = os.path.basename(cmd)

    fn = {
        "sign": sign_cmd,
        "verify-unsafe": verify_unsafe_cmd,
        "decode": decode_cmd,
    }.get(cmd, unknown_command)

    o = fn(key, em_len)
    sys.stdout.buffer.write(o)


if __name__ == '__main__':
    main()
