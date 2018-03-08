import s2c11
import util
from s2c16 import userdata
from s3c18 import ctr_encrypt, ctr_decrypt

KEY = s2c11.random_AES_key()
NONCE = s2c11.random_nonce()

debug = util.debug_print(False)


def encrypted_userdata(s: bytes) -> bytes:
    data = userdata(s)
    em = ctr_encrypt(KEY, NONCE, data)
    return em


def decrypt(em: bytes) -> bytes:
    return ctr_decrypt(KEY, NONCE, em)


def is_admin(em: bytes) -> bool:
    msg = decrypt(em)
    return b";admin=true;" in msg


def main():
    p = encrypted_userdata(b"admin?true")
    print(p)
    print(decrypt(p))


if __name__ == '__main__':
    main()
