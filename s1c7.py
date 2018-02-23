import codecs

from Crypto.Cipher import AES

from s1c2 import xor2


def basics():
    key = "YELLOW SUBMARINE"
    IV = '\x00' * 16
    mode = AES.MODE_ECB

    encryptor = AES.new(key, mode, IV=IV)
    decryptper = AES.new(key, mode, IV=IV)

    text = b'j' * 16 + b'j' * 16
    ciphertext = encryptor.encrypt(text)

    print(codecs.encode(ciphertext, 'hex'))

    plaintext = decryptper.decrypt(ciphertext)

    print(text)
    print(plaintext)

    c = xor2(text, ciphertext)
    print(codecs.encode(c, 'hex'))

    pt = xor2(ciphertext, c)
    print(pt)

    assert plaintext == text


def main():
    raw = open("set1/7.txt", "rb").read()
    ciphertext = codecs.decode(raw, "base64")
    print(len(ciphertext))

    key = "YELLOW SUBMARINE"
    IV = '\x00' * 16
    mode = AES.MODE_ECB

    decryptper = AES.new(key, mode, IV=IV)

    print(decryptper.decrypt(ciphertext).decode())


if __name__ == '__main__':
    basics()
