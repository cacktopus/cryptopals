import hashlib
import types
from typing import Callable, Tuple

from pkcs7_padding import pkcs7_padding, pkcs7_unpad
from s2c10 import cbc_encrypt, cbc_decrypt
from s4c33 import dh_secret
from util import modexp, gen_prime, int_to_bytes, random_bytes


def derive_key(secret: int):
    return hashlib.sha1(int_to_bytes(secret)).digest()[:16]


def decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    reply_padded = cbc_decrypt(key, data, iv)
    reply_pt = pkcs7_unpad(reply_padded, 16)
    return reply_pt


def encrypt(key: bytes, msg: bytes) -> Tuple[bytes, bytes]:
    iv = random_bytes(16)
    padded = pkcs7_padding(msg, 16)
    ct = cbc_encrypt(key, padded, iv)
    return ct, iv


def a():
    print("a: started")
    yield []
    p = gen_prime(256)
    g = 37
    private = dh_secret(p)
    public = modexp(g, p, private)

    other_public, *_ = yield [p, g, public]
    secret = modexp(other_public, p, private)

    key = derive_key(secret)

    msg = b"abc"
    ct, iv = encrypt(key, msg)
    reply_data, reply_iv = yield [ct, iv]

    reply_pt = decrypt(key, reply_iv, reply_data)
    assert reply_pt == msg

    print("a: reply", reply_pt)


def b():
    print("b: started")
    p, g, other_public = yield []
    private = dh_secret(p)
    public = modexp(g, p, private)

    secret = modexp(other_public, p, private)
    key = derive_key(secret)

    ct, iv = yield [public]

    pt = decrypt(key, iv, ct)
    print("b: got pt", pt)

    new_ct, new_iv = encrypt(key, pt)
    yield [new_ct, new_iv]


class PInjector:
    def __init__(self):
        self.p = None

    def mitm_ba(self):
        pub_b, *_ = yield []
        print("ba: ", pub_b)
        ct, iv = yield [self.p]

        key = derive_key(0)

        print("ba: ", ct, iv)
        yield [ct, iv]

    def mitm_ab(self):
        p, g, pub_a = yield []
        self.p = p
        print("ab:", p, g, pub_a)
        ct, iv = yield [p, g, self.p]
        print("ab:", ct, iv)
        yield [ct, iv]


def start(g: Callable):
    gen = g()
    next(gen)
    return gen


def run(actors, starting_actor):
    actors = {k: (start(gen), dst) for k, (gen, dst) in actors.items()}

    target, args = starting_actor, []
    while True:
        t, target = actors[target]
        assert isinstance(t, types.GeneratorType)
        try:
            args = t.send(args)
            assert isinstance(args, list)
        except StopIteration:
            break


def main():
    pi = PInjector()

    actors = {
        "a": (a, "m0"),
        "b": (b, "m1"),
        "m0": (pi.mitm_ab, "b"),
        "m1": (pi.mitm_ba, "a"),

    }

    run(actors, "a")


if __name__ == '__main__':
    main()  # pragma nocoverr
