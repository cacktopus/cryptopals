# further research:
# - gcd/lcm
# - coprime check
# - modular multiplicative inverse
# - primality testing
import math
import subprocess as sp


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
    return int(a * b / gcd(a, b))


def totient(p, q):
    return lcm(p - 1, q - 1)


def rsa():
    m = 65

    p = 61
    q = 53

    n = p * q
    t = totient(p, q)

    e = 17  # TODO e should be random

    # TODO: check e is prime
    # TODO: check e is coprime to t

    d = fast_multiplicative_inverse(e, t)

    print(t)
    print(d)

    encrypted = m ** e % n  # TODO: use modular exponentiation algo
    print(encrypted)

    decrypted = encrypted ** d % n  # TODO: use modular exponentiation algo
    print(decrypted)


def main():
    rsa()


if __name__ == '__main__':
    main()
