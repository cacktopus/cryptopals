import s2c11
import util
from s2c13 import get_all_blocks
from s2c16 import userdata
from s3c18 import ctr_encrypt, ctr_decrypt

KEY = s2c11.random_AES_key()
NONCE = s2c11.random_nonce()

debug = util.debug_print(False)


def encrypted_userdata(s: bytes) -> bytes:
    data = userdata(s)
    em = ctr_encrypt(KEY, NONCE, data)
    return em


def decrypt(em: bytes, count: int = 0) -> bytes:
    return ctr_decrypt(KEY, NONCE, em, counter=count)


def is_admin(em: bytes) -> bool:
    msg = decrypt(em)
    return b";admin=true;" in msg


def main():
    p = encrypted_userdata(b":admin?true:    ")

    blocks = get_all_blocks(p)

    buf = list(blocks[2])
    buf[0] ^= 0b1
    buf[6] ^= 0b10
    buf[11] ^= 0b1

    blocks[2] = bytes(buf)

    p_ = b"".join(blocks)

    debug(decrypt(p))
    assert not is_admin(p)

    debug(decrypt(p_))
    assert is_admin(p_)


if __name__ == '__main__':
    main()  # pragma nocover
