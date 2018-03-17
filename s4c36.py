import hashlib

import binascii

from s4c33 import p_nist, dh_secret
from s4c34 import run, Start
from util import random_bytes, modexp, bytes_to_int, int_to_bytes

EMAIL = b"joe@abc.com"
PASSWORD = b"pass"
P = p_nist and 107670934010135287054261758880117521203403554085594247991095416943566194277953  # TODO
G = 2
K = 3


def mod(base: int, exponent: int) -> int:
    return modexp(base, P, exponent)


def hash_to_int(data: bytes) -> int:
    xH = hashlib.sha256(data).digest()
    return bytes_to_int(xH)


def host():
    salt = random_bytes(16)
    x = hash_to_int(salt + PASSWORD)
    print("s: x:", x)
    v = mod(G, x)

    b = dh_secret(P)
    B = K * v + mod(G, b)

    email, A = yield []
    print("{} trying to log in".format(email.decode()))
    u = hash_to_int(int_to_bytes(A) + int_to_bytes(B))

    print("host: A:", A)
    print("host: B:", B)
    print("host: salt:", bytes_to_int(salt))
    print("host: u", u)
    print("host: x:", x)

    yield [salt, B]

    t0 = A * mod(v, u)
    S = mod(t0, b)

    print("host: S:", S)

    key = hashlib.sha256(int_to_bytes(S)).digest()
    print("host: key:", binascii.hexlify(key))


def user():
    start = yield []
    assert start is Start

    a = dh_secret(P)
    A = mod(G, a)

    print("user: sending email")
    salt, B = yield [EMAIL, A]
    u = hash_to_int(int_to_bytes(A) + int_to_bytes(B))

    print("user: A:", A)
    print("user: B:", B)
    print("user: salt:", bytes_to_int(salt))
    print("user: u", u)

    x = hash_to_int(salt + PASSWORD)
    print("user: x:", x)

    t1 = B - K * mod(G, x)
    assert t1 > 0

    S = mod(t1, a + u * x)

    print("user: S:", S)

    key = hashlib.sha256(int_to_bytes(S)).digest()
    print("user: key:", binascii.hexlify(key))

    yield []


def main():
    actors = {
        "user": (user, "host"),
        "host": (host, "user"),
    }

    run(actors, "user")


if __name__ == '__main__':
    main()
