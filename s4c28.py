import sha1
import hashlib


def keyed_mac(key: bytes, msg: bytes) -> str:
    h0 = sha1.Sha1Hash()
    h0.update(key + msg)

    h1 = hashlib.sha1()
    h1.update(key + msg)

    d0 = h0.hexdigest()
    d1 = h1.hexdigest()

    assert d0 == d1

    return d0


def main():
    sha1.Sha1Hash().update(b"a"*(64*2-1)).hexdigest()

    key = b"abc123"
    msg = b"green cup soup chef"

    correct = keyed_mac(key, msg)
    assert correct == "4860e61b1152e72910ab41f776df5c38940931a7"

    assert keyed_mac(b"abc124", msg) != correct
    assert keyed_mac(key, b"green cup sous chef") != correct


if __name__ == '__main__':
    main()  # pragma nocover
