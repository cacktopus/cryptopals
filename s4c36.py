import hashlib

from s4c33 import p_nist, dh_secret
from s4c34 import run, Start
from util import random_bytes, modexp

EMAIL = b"joe@abc.com"
PASSWORD = b"pass"
P = p_nist
G = 2
K = 3


def s():
    salt = random_bytes(16)
    xH = hashlib.sha256(salt + PASSWORD).hexdigest()
    x = int(xH, 16)
    v = modexp(G, P, x)

    private = dh_secret(P)
    B = K * v + modexp(G, P, private)

    email, client_public_key = yield []
    print("{} trying to log in".format(email.decode()))

    yield [salt, B]


def c():
    start = yield []
    assert start is Start

    private = dh_secret(P)
    public = modexp(G, P, private)

    print("c: sending email")
    salt, B = yield [EMAIL, public]
    print("c: salt, B:", salt, B)


def main():
    actors = {
        "c": (c, "s"),
        "s": (s, "c"),
    }

    run(actors, "c")


if __name__ == '__main__':
    main()
