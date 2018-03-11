import codecs

import s2c11
from s1c2 import xor2
from s2c10 import ecb_decrypt
from s2c13 import get_block_range
from s3c18 import ctr_encrypt, ctr_decrypt

KEY = s2c11.random_AES_key()
NONCE = s2c11.random_nonce()


def _decrpt(ct: bytes) -> bytes:
    return ctr_decrypt(KEY, NONCE, ct)


def edit(ct: bytes, offset: int, newtext: bytes) -> bytes:
    # generate the keystream
    bgn = offset
    splice_len = len(newtext)
    end = bgn + splice_len

    bgn_block = bgn // 16
    end_block = end // 16
    last_block = len(ct) // 16

    blocks = get_block_range(ct, bgn_block, end_block + 1)
    section = b"".join(blocks)
    section_len = len(section)
    keystream = ctr_decrypt(KEY, NONCE, b"\x00" * section_len, bgn_block)
    assert len(keystream) > splice_len

    prefix_len = bgn - bgn_block * 16
    assert 0 <= prefix_len < 16

    postfix_len = section_len - prefix_len - splice_len
    assert 0 <= postfix_len < 16
    assert prefix_len + splice_len + postfix_len == section_len

    aligned_keystream = keystream[prefix_len: prefix_len + splice_len]
    assert len(aligned_keystream) == splice_len

    replaced = xor2(aligned_keystream, newtext)
    assert len(replaced) == splice_len

    postfix_offset = prefix_len + splice_len

    prefix = section[:prefix_len]
    postfix = section[postfix_offset: postfix_offset + postfix_len]

    new_ct = prefix + replaced + postfix
    assert len(new_ct) == section_len

    a = b"".join(get_block_range(ct, 0, bgn_block))
    b = new_ct
    c = b"".join(get_block_range(ct, end_block + 1, last_block + 1))

    result = b"".join((a, b, c))
    assert len(result) == len(ct)

    return result


def main():
    pt = get_plaintext()

    ct = ctr_encrypt(KEY, NONCE, pt)

    new_ct = edit(ct, 2 + 16, b"_" * 100)

    print(_decrpt(new_ct))


def get_plaintext():
    with open("set4/25.txt", "rb") as f:
        raw = f.read()
    ct = codecs.decode(raw, "base64")
    pt = ecb_decrypt(b"YELLOW SUBMARINE", ct)
    return pt


if __name__ == '__main__':
    main()
