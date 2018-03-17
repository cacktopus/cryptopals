import hashlib

from pkcs7_padding import pkcs7_padding, pkcs7_unpad
from s2c10 import cbc_encrypt, cbc_decrypt
from s4c33 import dh_secret
from util import modexp, gen_prime, int_to_bytes, random_bytes


def gen_a():
    print("a started")
    p = gen_prime(256)
    g = 37
    private = dh_secret(p)
    public = modexp(g, p, private)

    other_public = yield p, g, public
    print("gen_a got B", other_public)

    s = modexp(other_public, p, private)
    print("gen_a secret", s)

    key = hashlib.sha1(int_to_bytes(s)).digest()[:16]
    iv = random_bytes(16)

    msg = b"abc"
    padded = pkcs7_padding(msg, 16)

    ct = cbc_encrypt(key, padded, iv)
    reply_data, reply_iv = yield ct, iv

    print("echo:", reply_data, reply_iv)
    reply_padded = cbc_decrypt(key, reply_data, reply_iv)

    reply_pt = pkcs7_unpad(reply_padded, 16)
    assert reply_pt == msg

    print("reply:", reply_pt)


def gen_b():
    print("b started")
    p, g, other_public = yield None
    private = dh_secret(p)
    public = modexp(g, p, private)

    print("b got", other_public)
    s = modexp(other_public, p, private)
    key = hashlib.sha1(int_to_bytes(s)).digest()[:16]

    print("gen_b secret", s)
    ct, iv = yield public
    print("got msg", ct, iv)

    padded = cbc_decrypt(key, ct, iv=iv)

    pt = pkcs7_unpad(padded, 16)
    print("got pt", pt)

    new_iv = random_bytes(16)
    new_padded = pkcs7_padding(pt, 16)
    new_ct = cbc_encrypt(key, new_padded, new_iv)

    yield new_ct, new_iv


def main():
    a = gen_a()
    b = gen_b()

    next(b)
    ret_a = next(a)

    done = set()
    while len(done) < 2:
        try:
            ret_b = b.send(ret_a)
        except StopIteration:
            done.add('a')

        try:
            ret_a = a.send(ret_b)
        except StopIteration:
            done.add('b')


if __name__ == '__main__':
    main()
