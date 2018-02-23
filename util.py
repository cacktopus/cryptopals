class Chain:
    def __init__(self, *functions):
        self.functions = functions

    def __call__(self, x):
        # TODO: reduce()?
        res = self.functions[0](x)
        for f in self.functions[1:]:
            res = f(res)
        return res
