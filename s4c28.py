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
    key = b"abc123"
    msg = b"green cup soup chef"

    correct = keyed_mac(key, msg)
    print(correct)

    assert keyed_mac(b"abc124", msg) != correct
    assert keyed_mac(key, b"green cup sous chef") != correct


if __name__ == '__main__':
    main()  # pragma nocover
