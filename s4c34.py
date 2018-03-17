import hashlib
import types
from typing import Callable

from pkcs7_padding import pkcs7_padding, pkcs7_unpad
from s2c10 import cbc_encrypt, cbc_decrypt
from s4c33 import dh_secret
from util import modexp, gen_prime, int_to_bytes, random_bytes


def a():
    print("a started")
    yield []
    p = gen_prime(256)
    g = 37
    private = dh_secret(p)
    public = modexp(g, p, private)

    other_public, *_ = yield [p, g, public]
    print("gen_a got B", other_public)

    s = modexp(other_public, p, private)
    print("gen_a secret", s)

    key = hashlib.sha1(int_to_bytes(s)).digest()[:16]
    iv = random_bytes(16)

    msg = b"abc"
    padded = pkcs7_padding(msg, 16)

    ct = cbc_encrypt(key, padded, iv)
    reply_data, reply_iv = yield [ct, iv]

    print("echo:", reply_data, reply_iv)
    reply_padded = cbc_decrypt(key, reply_data, reply_iv)

    reply_pt = pkcs7_unpad(reply_padded, 16)
    assert reply_pt == msg

    print("reply:", reply_pt)


def b():
    print("b started")
    p, g, other_public = yield []
    private = dh_secret(p)
    public = modexp(g, p, private)

    print("b got", other_public)
    s = modexp(other_public, p, private)
    key = hashlib.sha1(int_to_bytes(s)).digest()[:16]

    print("gen_b secret", s)
    ct, iv = yield [public]
    print("got msg", ct, iv)

    padded = cbc_decrypt(key, ct, iv=iv)

    pt = pkcs7_unpad(padded, 16)
    print("got pt", pt)

    new_iv = random_bytes(16)
    new_padded = pkcs7_padding(pt, 16)
    new_ct = cbc_encrypt(key, new_padded, new_iv)

    yield [new_ct, new_iv]


def mitm_ba():
    pub_b, *_ = yield []
    print("ba: ", pub_b)
    ct, iv = yield [pub_b]
    print("ba: ", ct, iv)
    yield [ct, iv]


def mitm_ab():
    p, g, pub_a = yield []
    print("ab:", p, g, pub_a)
    ct, iv = yield [p, g, pub_a]
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
    actors = {
        "a": (a, "m0"),
        "b": (b, "m1"),
        "m0": (mitm_ab, "b"),
        "m1": (mitm_ba, "a"),

    }

    run(actors, "a")


if __name__ == '__main__':
    main()  # pragma nocoverr
