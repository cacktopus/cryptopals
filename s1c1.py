t = b"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"


def fromhex(s: bytes):
    result = 0
    for idx, ch in enumerate(reversed(s)):
        result |= int(chr(ch), 16) << (idx * 4)
    return result


def b64encode_character(i: int) -> chr:
    if i <= 25:
        return chr(i + ord('A'))

    if i <= 51:
        return chr(i-26 + ord('a'))

    if i <= 61:
        return chr(i-52 + ord('0'))

    if i == 62:
        return '+'

    if i == 63:
        return '/'

    raise ValueError("Unexpected value for i")


def base64encode(i: int):
    mask = 0b111111
    result = ""

    while i:
        digit = i & mask
        ch = b64encode_character(digit)
        result += ch
        i >>= 6

    return ''.join(reversed(result))


def main():
    print(base64encode(fromhex(t)))


if __name__ == '__main__':
    main()
