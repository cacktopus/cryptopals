import random
from typing import Tuple

import sha1
import util
from s4c28 import keyed_mac

debug = util.debug_print(False)

with open("/usr/share/dict/words", "rb") as f:
    KEY = random.choice(f.read().split())


def to_registers(hexdigest) -> Tuple:
    # TODO: needs tests
    n = int(hexdigest, 16)

    result = []
    for i in range(5):
        r = n & 0xFFFFFFFF
        result.append(r)
        n >>= 32

    return tuple(reversed(result))


def length_extension_attack(original_message: bytes, existing_hash: str, guessed_length: int):
    extra = b";admin=true"
    glue_padding = compute_glue_padding(original_message, guessed_length)
    new_msg = original_message + glue_padding + extra

    prefix_length = guessed_length + len(original_message) + len(glue_padding)
    assert prefix_length % 64 == 0

    registers = to_registers(existing_hash)
    h = sha1.Sha1Hash(initial=registers)
    h._message_byte_length = prefix_length
    forged = h.update(extra).hexdigest()

    return forged, new_msg


def compute_glue_padding(msg, guessed_length):
    message_byte_length = len(msg) + guessed_length
    processed_byte_length = 64 * (message_byte_length // 64)
    unprocessed_length = message_byte_length % 64
    glue_padding = sha1.pad_message(unprocessed_length, processed_byte_length)
    assert (message_byte_length + len(glue_padding)) % 64 == 0
    return glue_padding


def verify_keyed_mac(new_msg: bytes, mac: bytes):
    result = keyed_mac(KEY, new_msg)
    return result == mac


def main():
    msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    msg_hash = keyed_mac(KEY, msg)

    for i in range(100):
        forged, new_msg = length_extension_attack(msg, msg_hash, i)
        if verify_keyed_mac(new_msg, forged):
            break
    else:
        assert 0, "couldn't produce length-extended hash"  # pragma nocover

    assert b"comment1" in new_msg
    assert b";admin=true" in new_msg

    debug("Found valid hash with key length {}; key was '{}'".format(i, KEY))


if __name__ == '__main__':
    main()  # pragma nocover
