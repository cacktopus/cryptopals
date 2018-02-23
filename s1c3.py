from typing import Iterator, Tuple

import codecs

t = b"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"


def single_char_xor(ch: int, s: bytes) -> bytes:
    return bytes(c0 ^ ch for c0 in s)


def pairwise(it) -> Iterator[Tuple[str, str]]:
    it = iter(it)
    while True:
        yield next(it), next(it)


table = """
E	12.02
T	9.10
A	8.12
O	7.68
I	7.31
N	6.95
S	6.28
R	6.02
H	5.92
D	4.32
L	3.98
U	2.88
C	2.71
M	2.61
F	2.30
Y	2.11
W	2.09
G	2.03
P	1.82
B	1.49
V	1.11
K	0.69
X	0.17
Q	0.11
J	0.10
Z	0.07
""".split()

freq = dict()
freq[' '] = 0

for letter, percentage in pairwise(table):
    f = float(percentage)
    freq[letter] = f
    freq[letter.lower()] = f


def score(s):
    return sum(freq.get(chr(ch), -12.0) for ch in s)


def decode_single_char_xor_with_score(s: bytes) -> Tuple[bytes, float]:
    choices = range(256)

    m0 = ((single_char_xor(i, s), i) for i in choices)
    m1 = ((score(s[0]), s[0], s[1]) for s in m0)

    return max(m1)


def decode_single_char_xor(s: bytes) -> bytes:
    return decode_single_char_xor_with_score(s)[1]


def main():
    input = codecs.decode(b"0528346d2f38292934616d3a252c396a3e6d2a2224232a6d222347", "hex")
    plaintext = decode_single_char_xor(input)

    print(plaintext.decode())


if __name__ == '__main__':
    main()
