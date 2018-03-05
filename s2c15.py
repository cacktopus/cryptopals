from pkcs7_padding import pkcs7_padding_valid


def main():
    assert pkcs7_padding_valid(b"a" * 15 + bytes([1]), 16)
    assert not pkcs7_padding_valid(b"a" * 15 + bytes([2]), 16)
    assert not pkcs7_padding_valid(b"a" * 16, 16)


if __name__ == '__main__':
    main()  # pragma nocover
