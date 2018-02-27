import binascii
from hashlib import sha256
from typing import Tuple, Dict

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


def i2osp(n, x_len: int = 0):
    n_ = hex(n)[2:]

    if x_len:
        pad_len = 2 * x_len - len(n_)
        assert pad_len >= 0
        padding = "0" * pad_len
    else:
        padding = "0" if len(n_) % 2 == 1 else ""

    return binascii.unhexlify(padding + n_)


def rsasp1(n, d, m):
    return modexp(m, n, d)


def sign(key, em_len: int, msg: bytes) -> bytes:
    em = emsa_pcks1_v1_5_encode(msg, em_len)
    n = os2ip(em)
    s = rsasp1(key.n, key.d, n)
    o = i2osp(s, em_len)
    return o


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


def verify_unsafe(key, em_len: int, sig: bytes, msg: bytes) -> Tuple[bool, Dict]:
    """Returns true if signature is correctly verified"""
    s = os2ip(sig)
    m = modexp(s, key.n, key.e)
    d = i2osp(m, em_len)

    d = decode_pkcs_padding_unsafe(d)
    d = check_sha256_header(d)

    sig1 = sha256(msg).hexdigest()
    sig2 = binascii.hexlify(d).decode()

    return sig1 == sig2, dict(
        sig1=sig1,
        sig2=sig2,
    )
