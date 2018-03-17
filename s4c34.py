import hashlib
import types
from typing import Callable

from pkcs7_padding import pkcs7_padding, pkcs7_unpad
from s2c10 import cbc_encrypt, cbc_decrypt
from s4c33 import dh_secret
from util import modexp, gen_prime, int_to_bytes, random_bytes


def a(target: str):
    print("a started")
    yield target, []
    p = gen_prime(256)
    g = 37
    private = dh_secret(p)
    public = modexp(g, p, private)

    other_public, *_ = yield target, [p, g, public]
    print("gen_a got B", other_public)

    s = modexp(other_public, p, private)
    print("gen_a secret", s)

    key = hashlib.sha1(int_to_bytes(s)).digest()[:16]
    iv = random_bytes(16)

    msg = b"abc"
    padded = pkcs7_padding(msg, 16)

    ct = cbc_encrypt(key, padded, iv)
    reply_data, reply_iv = yield target, [ct, iv]

    print("echo:", reply_data, reply_iv)
    reply_padded = cbc_decrypt(key, reply_data, reply_iv)

    reply_pt = pkcs7_unpad(reply_padded, 16)
    assert reply_pt == msg

    print("reply:", reply_pt)


def b(target: str):
    print("b started")
    p, g, other_public = yield target, []
    private = dh_secret(p)
    public = modexp(g, p, private)

    print("b got", other_public)
    s = modexp(other_public, p, private)
    key = hashlib.sha1(int_to_bytes(s)).digest()[:16]

    print("gen_b secret", s)
    ct, iv = yield target, [public]
    print("got msg", ct, iv)

    padded = cbc_decrypt(key, ct, iv=iv)

    pt = pkcs7_unpad(padded, 16)
    print("got pt", pt)

    new_iv = random_bytes(16)
    new_padded = pkcs7_padding(pt, 16)
    new_ct = cbc_encrypt(key, new_padded, new_iv)

    yield target, [new_ct, new_iv]


def mitm(target: str):
    args = []
    while True:
        args = yield target, args
        print("saw", args)


def start(g: Callable, destination: str):
    gen = g(destination)
    next(gen)
    return gen


def run(actors, starting_actor):
    actors = {k: start(*v) for k, v in actors.items()}

    target, args = starting_actor, []
    while True:
        t = actors[target]
        assert isinstance(t, types.GeneratorType)
        try:
            target, args = t.send(args)
            assert isinstance(args, list)
        except StopIteration:
            break


def main():
    actors = {
        "a": (a, "m0"),
        "b": (b, "m1"),
        "m0": (mitm, "b"),
        "m1": (mitm, "a"),

    }

    run(actors, "a")


if __name__ == '__main__':
    main()
