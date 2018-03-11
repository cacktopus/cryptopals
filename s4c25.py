import codecs

import s2c11
from s2c10 import ecb_decrypt
from s2c13 import get_blocks, get_block_range
from s3c18 import ctr_encrypt, ctr_decrypt

KEY = s2c11.random_AES_key()
NONCE = s2c11.random_nonce()


def edit(ct: bytes, offset: int, newtext: bytes) -> bytes:
    # generate the keystream
    bgn = offset
    end = bgn + len(newtext)

    bgn_block = bgn // 16
    end_block = end // 16

    blocks = get_block_range(ct, bgn_block, end_block)
    pt = ctr_decrypt(KEY, NONCE, b"".join(blocks), bgn_block)
    print(pt)


def main():
    pt = get_plaintext()
    ct = ctr_encrypt(KEY, NONCE, pt)

    edit(ct, 0, b"x" * 32)


def get_plaintext():
    with open("set4/25.txt", "rb") as f:
        raw = f.read()
    ct = codecs.decode(raw, "base64")
    pt = ecb_decrypt(b"YELLOW SUBMARINE", ct)
    return pt


if __name__ == '__main__':
    main()
