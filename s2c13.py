from typing import Dict

import s2c11
from s2c10 import ecb_encrypt, ecb_decrypt
from pkcs7_padding import pkcs7_padding, pkcs7_unpad

KEY = s2c11.random_AES_key()


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


def decrypt(data: bytes) -> Dict:
    s = ecb_decrypt(KEY, data)
    unpadded = pkcs7_unpad(s, 16)
    return parse_kv(unpadded.decode())


def get_block(data, block_num):
    assert len(data) % 16 == 0
    return data[block_num * 16: (block_num + 1) * 16]


def get_blocks(data, *block_numbers):
    assert len(data) % 16 == 0
    blocks = list(sorted(set(block_numbers)))
    return b"".join(get_block(data, b) for b in blocks)


def main():
    """
        123456789012345612345678901234561234567890123456
        1               2               3
        email=          admin           &uid=10&role=user

        123456789012345612345678901234561234567890123456
        1               2               3
        email=aaaaaaa@b.com&uid=10&role=user
    """

    p = encrypt_profile(b" " * 10 + pkcs7_padding(b"admin", 16))
    admin = get_blocks(p, 1)

    p2 = encrypt_profile(b"aaaaaaa@b.com")
    start = get_blocks(p2, 0, 1)

    forged = start + admin

    # Check solution
    decoded = decrypt(forged)
    assert decoded['role'] == 'admin'


if __name__ == '__main__':
    main()  # pragma nocover
