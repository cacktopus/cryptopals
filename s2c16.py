import s2c11

KEY = s2c11.random_AES_key()


def escape(s: bytes) -> bytes:
    return s.replace(b";", b"%59").replace(b"=", b"%61")


def userdata(s: bytes) -> bytes:
    return (
            b"comment1=cooking%20MCs;userdata="
            + escape(s)
            + b";comment2=%20like%20a%20pound%20of%20bacon"
    )


def main():
    pass


if __name__ == '__main__':
    main()
