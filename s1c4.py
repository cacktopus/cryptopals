import codecs
from s1c3 import decode_single_char_xor_with_score

from util import Chain


def main():
    lines = open("set1/4.txt").read().split()

    f = Chain(
        lambda x: codecs.decode(x, "hex"),
        decode_single_char_xor_with_score,
    )

    print(max(map(f, lines))[1].decode())


if __name__ == '__main__':
    main()
