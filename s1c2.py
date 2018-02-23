import codecs

t0 = b"1c0111001f010100061a024b53535009181c"
t1 = b"686974207468652062756c6c277320657965"
expected = b"746865206b696420646f6e277420706c6179"


def xor2(b0, b1):
    assert len(b0) == len(b1)
    r = [bytes([c0 ^ c1]) for (c0, c1) in zip(b0, b1)]
    return b"".join(r)


def main():
    i0 = codecs.decode(t0, "hex")
    i1 = codecs.decode(t1, "hex")

    r = xor2(i0, i1)

    assert codecs.encode(r, "hex") == expected


if __name__ == '__main__':
    main()
