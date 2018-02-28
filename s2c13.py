from typing import Dict

import binascii

import s2c11
import util
from s2c10 import ecb_encrypt, ecb_decrypt
from s2c9 import pkcs7_padding

KEY = s2c11.random_AES_key()
debug = util.debug_print(False)


def parse_kv(s: str) -> Dict:
    pairs = (p.split("=", 1) for p in s.split("&"))
    return dict(pairs)


def encode_pair(k: str, v: str) -> str:
    return "{}={}".format(k, v.replace("&", "").replace("=", ""))


def profile_for(email: str, uid: str, role: str) -> str:
    return "&".join([
        encode_pair("email", email),
        encode_pair("uid", uid),
        encode_pair("role", role),
    ])


def encrypt_profile(email: str) -> bytes:
    data = profile_for(email, "10", "user").encode()
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
