import s2c11
from s2c10 import cbc_encrypt, cbc_decrypt
from s2c13 import get_block
from pkcs7_padding import pkcs7_padding, pkcs7_unpad

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
    """
        # Try to flip
            : -> ;      ^ 0b1
            ? -> =      ^ 0b01

        123456789012345612345678901234561234567890123456123456789012345612345678901234561234567890123456
        1               2               3               4               5               6
        comment1=cooking%20MCs;userdata=:admin?true:    ;comment2=%20like%20a%20pound%20of%20bacon
    """

    p = encrypted_userdata(
        b":admin?true:    ")

    b0 = get_block(p, 0)
    b1 = get_block(p, 1)
    b2 = get_block(p, 2)
    b3 = get_block(p, 3)
    b4 = get_block(p, 4)
    b5 = get_block(p, 5)

    buf = list(b1)
    buf[0] ^= 0b1  # first ;
    buf[6] ^= 0b10  # =
    buf[11] ^= 0b1  # second ;

    flipped = bytes(buf)

    p_ = b0 + flipped + b2 + b3 + b4 + b5

    print(decrypt(p))
    assert not is_admin(p)

    print(decrypt(p_))
    assert is_admin(p_)


if __name__ == '__main__':
    main()  # pragma nocover
