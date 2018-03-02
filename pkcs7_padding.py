def pkcs7_padding(s: bytes, length: int):
    # TODO: this needs its own unit tests

    if len(s) % length == 0:
        return s + bytes([16] * 16)

    remainder = len(s) % length
    if remainder == 0:
        return s
    pad_length = length - remainder

    pad_char = bytes([pad_length])
    return s + pad_char * pad_length


def pkcs7_unpad(data: bytes) -> bytes:
    # TODO: needs its own unit tests
    # TODO: need to handle the full block of 16's case
    # This kind of padding just seems like a bad idea
    # Seems like some blocks can't be represented
    assert len(data) % 16 == 0
    n = len(data)
    head = data[:n - 16]
    last_block = data[n - 16:n]
    assert len(last_block) == 16
    last_char = last_block[-1]
    if last_char < 16:
        target = bytes([last_char]) * last_char
        end = last_block[16 - last_char:16]
        if target == end:
            trimmed = last_block[:16 - last_char]
            return head + trimmed
    return data
