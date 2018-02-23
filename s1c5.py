import itertools
from functools import partial
import codecs

from util import Chain

t = b"""
Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
""".strip()

expected = (
    b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
    b"a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
)


def repeating_key_xor(key: bytes, s: bytes):
    gen = itertools.cycle(key)
    result = []
    for ch in s:
        code = next(gen)
        outch = bytes([code ^ ch])
        result.append(outch)
    return b"".join(result)


def main():
    f = Chain(
        partial(repeating_key_xor, b"ICE"),
        lambda x: codecs.encode(x, "hex"),
    )

    res = f(t)
    assert res == expected


if __name__ == '__main__':
    main()
