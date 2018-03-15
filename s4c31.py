from hmac import hmac_sha1


def main():
    mac = hmac_sha1(b"", b"")
    print(mac)
    assert mac == "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"


if __name__ == '__main__':
    main()
