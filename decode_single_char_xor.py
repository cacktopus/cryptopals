import codecs
import sys

from c3 import decode_single_char_xor
from util import Chain


def main():
    msg = sys.stdin.read()

    f = Chain(
        lambda x: x.strip(),
        lambda x: codecs.decode(x, "hex"),
        decode_single_char_xor,
        lambda x: x.decode(),
    )

    print(f(msg))


if __name__ == '__main__':
    main()
