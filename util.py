import math
import random
import subprocess as sp

from Crypto.PublicKey import RSA


class Chain:
    def __init__(self, *functions):
        self.functions = functions

    def __call__(self, x):
        # TODO: reduce()?
        res = self.functions[0](x)
        for f in self.functions[1:]:
            res = f(res)
        return res


def modexp(base, modulus, exponent):
    result = 1
    curPow = base % modulus
    while exponent:
        bit = exponent % 2
        if bit:
            result *= curPow
            result %= modulus
        curPow *= curPow
        curPow %= modulus
        exponent >>= 1

    return result


def round_up_power_2(n):
    m = int(math.floor(math.log2(n))) + 1
    return 2 ** m


def get_key_length_in_bytes(key) -> int:
    return round_up_power_2(key.size()) // 8


def get_keys(key_name: str):
    with open(key_name) as f:
        priv_key = RSA.importKey(f.read())

    with open(key_name + ".pub") as f:
        pub_key = RSA.importKey(f.read())

    key_len = get_key_length_in_bytes(priv_key)

    return priv_key, pub_key, key_len


def debug_print(enabled):
    return print if enabled else lambda *args, **kwargs: None


def random_word() -> bytes:
    with open("/usr/share/dict/words", "rb") as f:
        return random.choice(f.read().split())


def random_int_from_n_bytes(n: int):
    data = random_bytes(n)
    return int.from_bytes(data, "little")


def int_to_bytes(n: int) -> bytes:
    if n == 0:
        return b"\x00"
    bitlen = math.log2(n)
    byte_len = int(math.ceil(bitlen / 8))

    return n.to_bytes(byte_len, "little")


def random_bytes(n: int):
    with open("/dev/urandom", "rb") as f:
        return f.read(n)


def gen_prime(bits: int) -> int:
    cmd = "openssl prime -generate -bits {}".format(bits)
    output = sp.check_output(cmd.split())
    return int(output)
