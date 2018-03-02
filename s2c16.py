import s2c11
from s2c10 import cbc_encrypt, cbc_decrypt
from s2c13 import pkcs7_unpad
from s2c9 import pkcs7_padding

KEY = s2c11.random_AES_key()


def escape(s: bytes) -> bytes:
    return s.replace(b";", b"%59").replace(b"=", b"%61")


def userdata(s: bytes) -> bytes:
    return (
            b"comment1=cooking%20MCs;userdata="
            + escape(s)
            + b";comment2=%20like%20a%20pound%20of%20bacon"
    )


def encrypted_userdata(s: bytes) -> bytes:
    data = userdata(s)
    padded = pkcs7_padding(data, 16)
    em = cbc_encrypt(KEY, padded)
    return em


def decrypt(em: bytes) -> bytes:
    unpadded = cbc_decrypt(KEY, em)
    msg = pkcs7_unpad(unpadded)
    return msg


def is_admin(em: bytes) -> bool:
    msg = decrypt(em)
    return b";admin=true;" in msg


def main():
    pass


if __name__ == '__main__':
    main()
