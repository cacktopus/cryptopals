import binascii
import math
from hashlib import sha256

from pkcs15 import i2osp, SHA256_HEADER, os2ip
from util import modexp

DEBUG = False
debug = print if DEBUG else lambda *args, **kwargs: None


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


def forge_signature(key, content: bytes, ff_len: int = 6):
    assert getattr(key, 'd', None) is None
    assert key.e == 3

    key_byte_len = round_up_power_2(key.size()) // 8

    debug(key_byte_len)

    digest = sha256(content).digest()

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

    forgery = binascii.hexlify(i2osp(res, key_byte_len))

    desired = binascii.hexlify(i2osp(n, key_byte_len))
    debug(desired, end="\n\n")
    debug(forgery, end="\n\n")

    msg_len_hex = len(msg) * 2
    assert desired[:msg_len_hex] == forgery[:msg_len_hex]

    return forgery
