def pkcs7_padding(s: bytes, length: int):
    remainder = len(s) % length
    if remainder == 0:
        return s
    pad_length = length - remainder

    pad_char = bytes([pad_length])
    return s + pad_char * pad_length


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
