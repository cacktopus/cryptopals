from os.path import expanduser

import os
from Crypto.PublicKey import RSA


def main():
    path = expanduser("~/.ssh")
    testkey = os.path.join(path, "testkey")

    key = RSA.importKey(open(testkey).read())
    print(key)

    print(hex(key.n))


if __name__ == '__main__':
    main()
