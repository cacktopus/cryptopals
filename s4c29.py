from typing import Tuple

import sha1
import util
from s4c28 import keyed_mac

debug = util.debug_print(False)


def to_registers(hexdigest) -> Tuple:
    n = int(hexdigest, 16)

    result = []
    for i in range(5):
        r = n & 0xFFFFFFFF
        result.append(r)
        n >>= 32

    return tuple(reversed(result))


def main():
    key = b"abc123"
    msg = b"green cup soup chef"

    correct = keyed_mac(key, msg)
    assert correct == "4860e61b1152e72910ab41f776df5c38940931a7"

    registers = to_registers(correct)
    debug(list(map(hex, registers)))

    assert registers == (0x4860e61b, 0x1152e729, 0x10ab41f7, 0x76df5c38, 0x940931a7)

    assert keyed_mac(b"abc124", msg) != correct
    assert keyed_mac(key, b"green cup soup chefs") != correct

    guessed_length = 6
    message_byte_length = len(msg) + guessed_length

    processed_byte_length = message_byte_length // 64

    unprocessed_length = processed_byte_length % 64
    glue_padding = sha1.pad_message(unprocessed_length, 0)

    assert (processed_byte_length + len(glue_padding)) % 64 == 0


if __name__ == '__main__':
    main()  # pragma nocover
