import binascii
import hashlib

import actors
from hmac import hmac_sha256
from s4c36 import host
from util import int_to_bytes


def user():
    start = yield []
    assert start is actors.Start

    A = 0

    print("user: sending email")
    salt, B = yield [b"joe@abc.com", A]

    S = 0

    print("user: S:", S)

    key = hashlib.sha256(int_to_bytes(S)).digest()
    print("user: key:", binascii.hexlify(key))

    response, *_ = yield [hmac_sha256(key, salt)]
    print("server says password was", response)

    assert response == "OK"


def main():
    actor_list = {
        "user": (user, "host"),
        "host": (host, "user"),
    }

    actors.run(actor_list, "user")


if __name__ == '__main__':
    main()  # pragma nocover
