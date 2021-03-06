def pkcs7_padding(s: bytes, length: int):
    # TODO: this needs its own unit tests

    if len(s) % length == 0:
        return s + bytes([length] * length)

    remainder = len(s) % length
    pad_length = length - remainder

    pad_char = bytes([pad_length])
    return s + pad_char * pad_length


class PaddingError(Exception):
    pass


class BlockSizeError(Exception):
    pass


def pkcs7_unpad(data: bytes, length: int) -> bytes:
    n = len(data)
    if n == 0:
        raise PaddingError
    if n % length != 0:
        raise BlockSizeError
    head = data[:n - length]
    last_block = data[n - length:n]
    assert len(last_block) == length
    last_char = last_block[-1]

    if last_char == 0:
        raise PaddingError

    if last_char <= length:
        target = bytes([last_char]) * last_char
        end = last_block[length - last_char:length]
        if target == end:
            trimmed = last_block[:length - last_char]
            return head + trimmed
    raise PaddingError  # danger, this can lead to padding oracle attacks


def pkcs7_padding_valid(data: bytes, length: int) -> bool:
    try:
        pkcs7_unpad(data, length)
    except PaddingError:
        return False
    return True
