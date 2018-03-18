import types
from typing import Callable


def start(g: Callable):
    gen = g()
    next(gen)
    return gen


class Start:
    pass


def run(actors, starting_actor):
    generators = {k: (start(gen), dst) for k, (gen, dst) in actors.items()}

    target, args = starting_actor, Start
    while True:
        t, target = generators[target]
        assert isinstance(t, types.GeneratorType)
        try:
            args = t.send(args)
            assert isinstance(args, list)
        except StopIteration:
            break
