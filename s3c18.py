import base64
import struct

from Crypto.Cipher import AES

from s1c2 import xor2


def ctr_encrypt(key: bytes, nonce: int, data: bytes) -> bytes:
    result = []
    counter = 0
    encrypter = AES.new(key, mode=AES.MODE_ECB)

    while data:
        block = data[:16]
        data = data[16:]

        i = struct.pack("<QQ", nonce, counter)
        j = encrypter.encrypt(i)

        mask = j[:len(block)]

        ct = xor2(block, mask)
        result.append(ct)

        counter += 1

    return b"".join(result)


def ctr_decrypt(key: bytes, nonce: int, data: bytes) -> bytes:
    return ctr_encrypt(key, nonce, data)


def main():
    test = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    given_ct = base64.b64decode(test)

    result = ctr_encrypt(b"YELLOW SUBMARINE", 0, given_ct)
    assert result == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


if __name__ == '__main__':
    main()  # pragma nocover
