from typing import Dict

import binascii

import s2c11
import util
from s2c10 import ecb_encrypt, ecb_decrypt
from s2c9 import pkcs7_padding

# KEY = s2c11.random_AES_key()
KEY = b"a" * 16
debug = util.debug_print(False)


def parse_kv(s: str) -> Dict:
    pairs = (p.split("=", 1) for p in s.split("&"))
    return dict(pairs)


def encode_pair(k: bytes, v: bytes) -> bytes:
    return b"".join([k, b"=", v.replace(b"&", b"").replace(b"=", b"")])


def profile_for(email: bytes, uid: bytes, role: bytes) -> bytes:
    return b"&".join([
        encode_pair(b"email", email),
        encode_pair(b"uid", uid),
        encode_pair(b"role", role),
    ])


def encrypt_profile(email: bytes) -> bytes:
    data = profile_for(email, b"10", b"user")
    padded = pkcs7_padding(data, 16)
    return ecb_encrypt(KEY, padded)


def pkcs7_unpad(data: bytes) -> bytes:
    # TODO: needs its own unit tests
    # This kind of padding just seems like a bad idea
    assert len(data) % 16 == 0
    n = len(data)
    head = data[:n - 16]
    last_block = data[n - 16:n]
    assert len(last_block) == 16
    last_char = last_block[-1]
    if last_char < 16:
        target = bytes([last_char]) * last_char
        end = last_block[16 - last_char:16]
        if target == end:
            trimmed = last_block[:16 - last_char]
            return head + trimmed
    return data


def decrypt(data: bytes) -> Dict:
    s = ecb_decrypt(KEY, data)
    debug(binascii.hexlify(s))
    unpadded = pkcs7_unpad(s)
    return parse_kv(unpadded.decode())


def main():
    """

123456789012345612345678901234561234567890123456
1               2               3
email=          admin           &uid=10&role=user


    """

    p = encrypt_profile(b" " * 9 + b"admin" + b" " * (16 - 5))
    print(len(p), binascii.hexlify(p))


if __name__ == '__main__':
    main()
