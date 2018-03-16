from s4c33 import p_nist, dh_secret
from util import modexp, gen_prime


def gen_a():
    print("a started")
    p = gen_prime(256)
    g = 37
    a = dh_secret(p)
    A = modexp(g, p, a)

    B = yield p, g, A
    print("gen_a got B", B)

    s = modexp(B, p, a)
    print("gen_a secret", s)
    yield None


def gen_b():
    print("b started")
    p, g, A = yield None
    b = dh_secret(p)
    B = modexp(g, p, b)

    print("b got", A)
    s = modexp(A, p, b)
    print("gen_b secret", s)
    yield B
    yield None


def main():
    a = gen_a()
    b = gen_b()

    next(b)
    ret_a = next(a)

    ret_b = b.send(ret_a)
    ret_a = a.send(ret_b)
    ret_b = b.send(ret_a)


if __name__ == '__main__':
    main()
