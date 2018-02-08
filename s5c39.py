# further research:
# - gcd/lcm
# - coprime check
# - modular multiplicative inverse
# - primality testing
import math
import subprocess as sp

from util import modexp


def gen_prime(bits: int) -> int:
    cmd = "openssl prime -generate -bits {}".format(bits)
    output = sp.check_output(cmd.split())
    return int(output)


def multiplicative_inverse(a, m):
    # totally naive
    for i in range(m):
        if a * i % m == 1:
            return i

    raise ValueError("No multiplicative inverse for {} (mod {})".format(a, m))


def fast_multiplicative_inverse(a, m):
    _, _, t = egcd(a, m)
    # print(t)
    return (t + m) % m


def egcd(a, b):
    # TODO: only works when a and b are coprime
    # needs tests, need to think about this
    if b > a:
        return egcd(b, a)

    if b == 1:
        return a, 0, 1

    q = a // b
    r = a % b

    # print("{}, {}".format(a, b))
    # one = "{} = {}*{} + {}".format(a, q, b, r)
    # print(one)

    d, s_next, t_next = egcd(b, r)

    t = s_next - t_next * q
    s = t_next

    two = "{} == {} - {} * {}".format(r, a, q, b)
    tre = "{} == {} * {} + {} * {}".format(1, s, a, t, b)
    check = s * a + t * b

    # print("{}  //  {}, {}".format(two, tre, check == 1))
    # print("")

    return d, s, t


def gcd(a, b):
    if b > a:
        return gcd(b, a)

    if b == 0:
        return a

    return gcd(b, a % b)


def lcm(a, b):
    return a * b // gcd(a, b)


def totient(p, q):
    return lcm(p - 1, q - 1)


def rsa(m: int):
    p = gen_prime(200)
    q = gen_prime(200)

    n = p * q
    t = totient(p, q)

    t_bits = int(math.floor(math.log2(t)))
    print("t_bits", t_bits)

    e = gen_prime(t_bits - 10)
    # TODO: we should loop until this is true
    assert gcd(t, e) == 1

    d = fast_multiplicative_inverse(e, t)

    assert d * e % t == 1

    print('t', t)
    print('e', e)
    print('d', d)

    encrypted = modexp(m, n, e)
    print('enc', encrypted)

    decrypted = modexp(encrypted, n, d)
    print('dec', decrypted)


def main():
    rsa(65)


if __name__ == '__main__':
    main()
