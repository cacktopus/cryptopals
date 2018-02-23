import codecs
import sys

from c3 import single_char_xor
from functools import partial
from util import Chain


def main():
    key = int(sys.argv[1])
    msg = sys.stdin.read()

    f = Chain(
        lambda s: s.encode(),
        partial(single_char_xor, key),
        lambda s: codecs.encode(s, 'hex'),
        lambda x: x.decode(),
    )

    print(f(msg))


if __name__ == '__main__':
    main()
