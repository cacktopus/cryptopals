import binascii
import hashlib

from actors import Start, run
from hmac import hmac_sha256
from s4c33 import p_nist, dh_secret
from util import random_bytes, modexp, bytes_to_int, int_to_bytes

USERS = {
    b"joe@abc.com": b"pass"
}

P = p_nist
# P = 322987745571404816193832791771236452571894539012739
G = 2
K = 3


def mod(base: int, exponent: int) -> int:
    return modexp(base, P, exponent)


def hash_to_int(data: bytes) -> int:
    xH = hashlib.sha256(data).digest()
    return bytes_to_int(xH)


def host():
    email, A = yield []

    password = USERS[email]

    salt = random_bytes(16)
    x = hash_to_int(salt + password)
    print("s: x:", x)
    v = mod(G, x)

    b = dh_secret(P)
    B = K * v + mod(G, b)

    print("{} trying to log in".format(email.decode()))
    u = hash_to_int(int_to_bytes(A) + int_to_bytes(B))

    print("host: A:", A)
    print("host: B:", B)
    print("host: salt:", bytes_to_int(salt))
    print("host: u", u)
    print("host: x:", x)

    user_mac, *_ = yield [salt, B]

    t0 = A * mod(v, u)
    S = mod(t0, b)

    print("host: S:", S)

    key = hashlib.sha256(int_to_bytes(S)).digest()
    print("host: key:", binascii.hexlify(key))

    host_mac = hmac_sha256(key, salt)
    yield ["OK" if user_mac == host_mac else "NO"]


def user():
    start = yield []
    assert start is Start

    a = dh_secret(P)
    A = mod(G, a)

    print("user: sending email")
    salt, B = yield [b"joe@abc.com", A]
    u = hash_to_int(int_to_bytes(A) + int_to_bytes(B))

    print("user: A:", A)
    print("user: B:", B)
    print("user: salt:", bytes_to_int(salt))
    print("user: u", u)

    x = hash_to_int(salt + b"pass")
    print("user: x:", x)

    t1 = B - K * mod(G, x)
    assert t1 > 0

    S = mod(t1, a + u * x)

    print("user: S:", S)

    key = hashlib.sha256(int_to_bytes(S)).digest()
    print("user: key:", binascii.hexlify(key))

    response, *_ = yield [hmac_sha256(key, salt)]
    print("server says password was", response)

    assert response == "OK"


def main():
    actors = {
        "user": (user, "host"),
        "host": (host, "user"),
    }

    run(actors, "user")


if __name__ == '__main__':
    main()  # pragma nocover
