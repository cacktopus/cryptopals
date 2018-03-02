import codecs

import util
from s2c10 import ecb_encrypt
from s2c11 import random_AES_key
from pkcs7_padding import pkcs7_padding
from s6c42 import debug

KEY = random_AES_key()

UNKNOWN = b''.join(b'''
Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
'''.split())

UNKNOWN = codecs.decode(UNKNOWN, 'base64')

debug = util.debug_print(False)


def oracle(key: bytes, unknown_string: bytes, your_string: bytes) -> bytes:
    padded = pkcs7_padding(your_string + unknown_string, 16)
    return ecb_encrypt(key, padded)


def find_length(f):
    # There's probably a bug here if the message is exactly the length of a block, or similar
    prev = None
    for i in range(1000):
        sz = len(f(b'A' * i))
        if prev:
            if sz != prev:
                block_size = sz - prev
                msg_length = prev - i + 1
                return block_size, msg_length
        prev = sz
    else:
        raise Exception("Unknown block size")  # pragma nocover


def main():
    def f(s: bytes) -> bytes:
        return oracle(KEY, UNKNOWN, s)

    found = b""

    block_size, unknown_length = find_length(f)

    block = -1
    while len(found) < unknown_length:
        block += 1
        for position in range(block_size):
            debug(block, position, len(found), unknown_length)
            if len(found) == unknown_length:
                break
            padding = b"A" * (block_size - position - 1)
            target_ct = f(padding)[block * block_size: (block + 1) * block_size]

            prefix = found[-(block_size - 1):]
            delta = block_size - 1 - len(found)
            prefix = delta * b'A' + prefix

            for i in range(256):
                trial = prefix + bytes([i])
                assert len(trial) == block_size
                ct = f(trial)[0:block_size]

                if ct == target_ct:
                    found += bytes([i])
                    debug(found)
                    break
            else:
                assert False, "not found"  # pragma nocover

    return found


if __name__ == '__main__':
    main()  # pragma nocover
