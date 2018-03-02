from pkcs7_padding import pkcs7_padding


def main():
    result = pkcs7_padding(b"YELLOW SUBMARINE", 20)
    assert len(result) % 20 == 0
    assert result == b"YELLOW SUBMARINE" + b"\x04" * 4, result

    result = pkcs7_padding(b"YELLOW SUBMARINE!", 20)
    assert len(result) % 20 == 0
    assert result == b"YELLOW SUBMARINE!" + b"\x03" * 5, result

    result = pkcs7_padding(b"YELLOW SUBMARINE" * 2, 20)
    assert len(result) % 20 == 0
    assert result == b"YELLOW SUBMARINE" * 2 + b"\x08" * 8, result


if __name__ == '__main__':
    main()
