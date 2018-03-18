import binascii
import hashlib

from hmac import hmac_sha256
from s4c36 import mod, P, G, K, hash_to_int, host
import actors
from s4c33 import dh_secret
from util import int_to_bytes, bytes_to_int


def user():
    start = yield []
    assert start is actors.Start

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
    actor_list = {
        "user": (user, "host"),
        "host": (host, "user"),
    }

    actors.run(actor_list, "user")
    actors.run(actor_list, "user")


if __name__ == '__main__':
    main()  # pragma nocover
