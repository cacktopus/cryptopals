import math

import util

p_nist_text = """
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff
"""

p_nist = int("".join(p_nist_text.split()), 16)

g_nist = 2


def dh_example(p: int, g: int):
    bit_sz = math.log2(p)
    byte_sz = int(math.ceil(bit_sz / 8))

    priv_a = util.random_int_from_n_bytes(byte_sz) % p
    pub_a = util.modexp(g, p, priv_a)

    priv_b = util.random_int_from_n_bytes(byte_sz) % p
    pub_b = util.modexp(g, p, priv_b)

    secret_a = util.modexp(pub_b, p, priv_a)
    secret_b = util.modexp(pub_a, p, priv_b)

    assert secret_a == secret_b


def main():
    dh_example(37, 5)
    dh_example(p_nist, g_nist)


if __name__ == '__main__':
    main()  # pragma nocover
