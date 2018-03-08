import struct
from typing import Generator
from collections import Counter

import random

from s2c10 import cbc_encrypt, ecb_encrypt
from pkcs7_padding import pkcs7_padding


def chunk(size: int, data: bytes) -> Generator[bytes, None, None]:
    assert len(data) % size == 0
    while data:
        ch = data[:size]
        data = data[size:]
        yield ch


def random_bytes(n: int):
    with open("/dev/urandom", "rb") as f:
        return f.read(n)


def random_AES_key() -> bytes:
    return random_bytes(16)


def random_nonce() -> int:
    data = random_bytes(8)
    return struct.unpack("Q", data)[0]


def encryption_oracle(plaintext: bytes):
    key = random_AES_key()

    pre = random_bytes(random.randint(5, 10))
    post = random_bytes(random.randint(5, 10))

    text = pre + plaintext + post
    padded = pkcs7_padding(text, 16)

    if random.random() < 0.5:
        return cbc_encrypt(key, padded)
    else:
        return ecb_encrypt(key, padded)


def detect_block_mode(s: bytes):
    chunks = list(chunk(16, s))
    return 'cbc' if len(chunks) == len(set(chunks)) else 'ecb'


def main():
    c = Counter()
    for _ in range(100):
        res = detect_block_mode(encryption_oracle(b"\x00" * 100))
        c.update([res])
    print(c.most_common(10))


if __name__ == '__main__':
    main()
