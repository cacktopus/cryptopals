import hashlib
from functools import partial
from typing import Callable

from s1c2 import xor2


def digest(hashfunc: Callable) -> Callable:
    def _hash(msg: bytes) -> bytes:
        h = hashfunc()
        h.update(msg)
        return h.digest()

    return _hash


def hexdigest(hashfunc: Callable) -> Callable:
    def _hash(msg: bytes) -> str:
        h = hashfunc()
        h.update(msg)
        return h.hexdigest()

    return _hash


def hmac(hashfunc: Callable, blocksize: int, key: bytes, message: bytes) -> str:
    if len(key) > blocksize:
        key = hashfunc().update(key).digest()

    if len(key) < blocksize:
        key += b"\x00" * (blocksize - len(key))

    o_key_pad = xor2(key, b"\x5c" * blocksize)
    i_key_pad = xor2(key, b"\x36" * blocksize)

    return hexdigest(hashfunc)(o_key_pad + digest(hashfunc)(i_key_pad + message))


hmac_sha1 = partial(hmac, hashlib.sha1, 64)
hmac_md5 = partial(hmac, hashlib.md5, 64)
hmac_sha256 = partial(hmac, hashlib.sha256, 64)