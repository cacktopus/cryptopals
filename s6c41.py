from typing import Optional

import util


class Server:
    def __init__(self, key_name):
        self.priv_key, self.pub_key, self.key_len = util.get_keys(key_name)
        self.data = set()

    def decrypt(self, msg: int) -> Optional[int]:
        if msg in self.data:
            return None

        self.data.add(msg)
        return util.modexp(msg, self.priv_key.n, self.priv_key.d)


def main():
    s = Server("test/fixtures/server_key")
    print(s.decrypt(2))
    print(s.decrypt(2))


if __name__ == '__main__':
    main()
