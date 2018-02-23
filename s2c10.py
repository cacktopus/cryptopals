import codecs
from Crypto.Cipher import AES

from s1c2 import xor2


def ecb_encrypt(key: bytes, data: bytes):
    assert len(data) % 16 == 0
    result = []
    while data:
        block = data[:16]
        data = data[16:]
        encrypter = AES.new(key, mode=AES.MODE_ECB)
        ct = encrypter.encrypt(block)
        result.append(ct)
    return b"".join(result)


def cbc_encrypt(key: bytes, data: bytes, iv: bytes = b"\x00" * 16):
    assert len(data) % 16 == 0
    result = []

    prev_ct = iv
    while data:
        block = data[:16]
        data = data[16:]

        inp = xor2(block, prev_ct)
        encrypter = AES.new(key, mode=AES.MODE_ECB)
        ct = encrypter.encrypt(inp)
        prev_ct = ct

        result.append(ct)

    return b"".join(result)


def cbc_decrypt(key: bytes, data: bytes, iv: bytes = b"\x00" * 16):
    assert len(data) % 16 == 0
    result = []

    prev_block = iv
    while data:
        block = data[:16]
        data = data[16:]
        decrypter = AES.new(key, mode=AES.MODE_ECB, IV=iv)
        ct = decrypter.decrypt(block)
        pt = xor2(prev_block, ct)
        prev_block = block
        result.append(pt)

    return b"".join(result)


def main():
    key = b'YELLOW SUBMARINE'
    iv = b"\x00" * 16

    b64 = open("set2/10.txt", "rb").read()
    data = codecs.decode(b64, "base64")

    res0 = cbc_decrypt(key, data, iv)
    res1 = cbc_encrypt(key, res0, iv)
    res2 = cbc_decrypt(key, res1, iv)

    print(res2.decode())

    assert res0 == res2


if __name__ == '__main__':
    main()
