t0 = b"1c0111001f010100061a024b53535009181c"
t1 = b"686974207468652062756c6c277320657965"
expected = b"746865206b696420646f6e277420706c6179"


def xor2(b0, b1):
    assert len(b0) == len(b1)
    r = [bytes([c0 ^ c1]) for (c0, c1) in zip(b0, b1)]
    return b"".join(r)
