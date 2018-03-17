import hashlib
import types
from typing import Callable, Tuple

import binascii

from pkcs7_padding import pkcs7_padding, pkcs7_unpad
from s2c10 import cbc_encrypt, cbc_decrypt
from s4c33 import dh_secret
from util import modexp, gen_prime, int_to_bytes, random_bytes

MSG = b"abc"


def derive_key(secret: int):
    return hashlib.sha1(int_to_bytes(secret)).digest()[:16]


def decrypt(who: bytes, key: bytes, iv: bytes, ct: bytes) -> bytes:
    print(b" ".join([
        who + b":",
        b"decrypting using",
        binascii.hexlify(key),
        b"=>",
        binascii.hexlify(ct),
        b",",
        binascii.hexlify(iv),
    ]).decode())
    reply_padded = cbc_decrypt(key, ct, iv)
    reply_pt = pkcs7_unpad(reply_padded, 16)
    return reply_pt


def encrypt(who: bytes, key: bytes, msg: bytes) -> Tuple[bytes, bytes]:
    iv = random_bytes(16)
    padded = pkcs7_padding(msg, 16)
    ct = cbc_encrypt(key, padded, iv)
    print(b" ".join([
        who + b":",
        b"encrypting",
        msg,
        b"using",
        binascii.hexlify(key),
        b"=>",
        binascii.hexlify(ct),
        b",",
        binascii.hexlify(iv),
    ]).decode())
    return ct, iv


def a():
    print("a: started")
    start = yield []
    assert start is Start
    p = gen_prime(256)
    g = 37
    private = dh_secret(p)
    public = modexp(g, p, private)

    other_public, *_ = yield [p, g, public]
    secret = modexp(other_public, p, private)

    key = derive_key(secret)
    print("a: key", binascii.hexlify(key))

    ct, iv = encrypt(b"a", key, MSG)
    reply_data, reply_iv = yield [ct, iv]

    reply_pt = decrypt(b"a", key, reply_iv, reply_data)
    assert reply_pt == MSG + b" echo"

    print("a: reply", reply_pt)


def b():
    print("b: started")
    p, g, other_public = yield []
    private = dh_secret(p)
    public = modexp(g, p, private)

    secret = modexp(other_public, p, private)
    key = derive_key(secret)
    print("b: key", binascii.hexlify(key))

    ct, iv = yield [public]

    pt = decrypt(b"b", key, iv, ct)
    print("b: got pt", pt)

    new_ct, new_iv = encrypt(b"b", key, pt + b" echo")
    yield [new_ct, new_iv]


class PInjector:
    def __init__(self):
        self.p = None

    def mitm_ba(self):
        pub_b, *_ = yield []
        print("ba: ", pub_b)
        ct, iv = yield [self.p]

        key = derive_key(0)
        pt = decrypt(b"ba", key, iv, ct)
        print(pt)
        target = MSG
        assert pt == target + b" echo"

        print("ba: ", pt)
        yield [ct, iv]

    def mitm_ab(self):
        p, g, pub_a = yield []
        self.p = p
        print("ab:", p, g, pub_a)
        ct, iv = yield [p, g, self.p]

        key = derive_key(0)
        pt = decrypt(b"ab", key, iv, ct)
        assert pt == MSG

        print("ab:", pt)
        yield [ct, iv]


class BasicMITM:
    def __init__(self):
        pass

    def mitm_ba(self):
        pub_b, *_ = yield []
        ct, iv = yield [pub_b]
        yield [ct, iv]

    def mitm_ab(self):
        p, g, pub_a = yield []
        ct, iv = yield [p, g, pub_a]
        yield [ct, iv]


class DoubleDH:
    def __init__(self):
        self.p, self.g = None, None
        self.public, self.private = None, None
        self.key_b, self.key_a = None, None

    def mitm_ab(self):
        p, g, pub_a = yield []

        self.p = p
        self.g = g
        self.private = dh_secret(self.p)
        self.public = modexp(self.g, self.p, self.private)

        ct, iv = yield [p, g, self.public]
        secret = modexp(pub_a, self.p, self.private)
        self.key_a = derive_key(secret)
        print("ab: key_a", binascii.hexlify(self.key_a))

        pt = decrypt(b"ab", self.key_a, iv, ct)
        new_ct, new_iv = encrypt(b"ab", self.key_b, pt)

        yield [new_ct, new_iv]

    def mitm_ba(self):
        pub_b, *_ = yield []
        secret = modexp(pub_b, self.p, self.private)
        self.key_b = derive_key(secret)
        print("ba: key", binascii.hexlify(self.key_b))

        ct, iv = yield [self.public]
        pt = decrypt(b"ba'", self.key_b, iv, ct)
        new_ct, new_iv = encrypt(b"ba", self.key_a, pt)
        yield [new_ct, new_iv]


def start(g: Callable):
    gen = g()
    next(gen)
    return gen


class Start:
    pass


def run(actors, starting_actor):
    actors = {k: (start(gen), dst) for k, (gen, dst) in actors.items()}

    target, args = starting_actor, Start
    while True:
        t, target = actors[target]
        assert isinstance(t, types.GeneratorType)
        try:
            args = t.send(args)
            assert isinstance(args, list)
        except StopIteration:
            break


def main():
    proxies = [
        BasicMITM(),
        PInjector(),
        DoubleDH(),
    ]

    for p in proxies:
        print(("Run " + p.__class__.__name__).center(80, "="))

        actors = {
            "a": (a, "m0"),
            "b": (b, "m1"),
            "m0": (p.mitm_ab, "b"),
            "m1": (p.mitm_ba, "a"),

        }
        run(actors, "a")


if __name__ == '__main__':
    main()  # pragma nocover
