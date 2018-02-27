from typing import Optional

import util
import random

from s5c39 import fast_multiplicative_inverse


class Server:
    def __init__(self, key_name):
        self._priv_key, self._pub_key, _ = util.get_keys(key_name)
        self.data = set()

    def decrypt(self, msg: int) -> Optional[int]:
        if msg in self.data:
            return None

        self.data.add(msg)
        return util.modexp(msg, self._priv_key.n, self._priv_key.d)

    @property
    def pub_key(self):
        return self._pub_key


class Client:
    def __init__(self, server):
        self._pub_key = server.pub_key
        self._msg = random.randint(2, 1000000)
        self.em = self.encrypt(self._msg)
        orig = server.decrypt(self.em)
        assert orig == self._msg
        second_try = server.decrypt(self.em)
        assert second_try is None

    def encrypt(self, msg: int) -> int:
        return util.modexp(msg, self._pub_key.n, self._pub_key.e)


def main():
    server = Server("test/fixtures/server_key")
    client = Client(server)

    assert server.decrypt(client.em) is None

    s = random.randint(2, server.pub_key.n)
    t = util.modexp(s, server.pub_key.n, server.pub_key.e)
    c_prime = t * client.em % server.pub_key.n
    p_prime = server.decrypt(c_prime)
    inv = fast_multiplicative_inverse(s, server.pub_key.n)
    msg = p_prime * inv % server.pub_key.n

    assert msg == client._msg
    assert msg < 1000000


if __name__ == '__main__':
    main()  # pragma: no cover
