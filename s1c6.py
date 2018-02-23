from typing import Iterable

import codecs
from s1c3 import decode_single_char_xor_with_score
from s1c5 import repeating_key_xor


def split(key_length: int, data: bytes):
    while len(data) > 0:
        chunk = data[:key_length]
        yield chunk
        data = data[key_length:]


def to_columns(chunks: Iterable[bytes]):
    chunks = list(chunks)

    for i in range(len(chunks[0])):
        result = []
        for c in chunks:
            if i < len(c):
                result.append(c[i])
        yield bytes(result)


def score_batch(data: bytes, i: int):
    chunks = split(i, data)
    scores = (decode_single_char_xor_with_score(c) for c in to_columns(chunks))
    score = sum(s[0] for s in scores)
    return score


def main():
    b64 = open("set1/6.txt").read().encode()
    data = codecs.decode(b64, "base64")

    domain = range(2, 40)
    mapped = ((score_batch(data, i), i) for i in domain)
    key_length = max(mapped)[1]

    key = []
    for c in to_columns(split(key_length, data)):
        res = decode_single_char_xor_with_score(c)
        # print(res)
        key.append(res[2])

    print(bytes(key))
    print("")
    print(repeating_key_xor(key, data).decode())


if __name__ == '__main__':
    main()
