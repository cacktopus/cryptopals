import binascii
import hashlib

import actors
from hmac import hmac_sha256
from s4c33 import dh_secret
from s4c36 import USERS, hash_to_int, mod, G, P
from util import random_bytes, int_to_bytes, bytes_to_int, random_int_from_n_bytes


def host():
    email, A = yield []
    password = USERS[email]

    salt = random_bytes(16)
    x = hash_to_int(salt + password)
    v = mod(G, x)

    b = dh_secret(P)
    B = mod(G, b)
    u = random_int_from_n_bytes(128 // 8)

    user_mac, *_ = yield [salt, B, u]

    S = mod(A * mod(v, u), b)
    key = hashlib.sha256(int_to_bytes(S)).digest()
    host_mac = hmac_sha256(key, salt)

    print("=" * 80)
    print("{} trying to log in".format(email.decode()))
    print("host: A:", A)
    print("host: B:", B)
    print("host: salt:", bytes_to_int(salt))
    print("host: u", u)
    print("host: x:", x)
    print("host: S:", S)
    print("host: key:", binascii.hexlify(key))

    yield ["OK" if user_mac == host_mac else "NO"]


def user():
    start = yield []
    assert start is actors.Start

    a = dh_secret(P)
    A = mod(G, a)

    salt, B, u = yield [b"joe@abc.com", A]
    x = hash_to_int(salt + b"pass")
    S = mod(B, a + u * x)
    key = hashlib.sha256(int_to_bytes(S)).digest()

    response, *_ = yield [hmac_sha256(key, salt)]

    print("=" * 80)
    print("user: A:", A)
    print("user: B:", B)
    print("user: salt:", bytes_to_int(salt))
    print("user: u", u)
    print("user: x:", x)
    print("user: S:", S)
    print("user: key:", binascii.hexlify(key))
    print("user: server says password was", response)

    assert response == "OK"


def main():
    actors_list = {
        "user": (user, "host"),
        "host": (host, "user"),
    }

    actors.run(actors_list, "user")


if __name__ == '__main__':
    main()  # pragma nocover
