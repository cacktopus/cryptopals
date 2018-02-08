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
