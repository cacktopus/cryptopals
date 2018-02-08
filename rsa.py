from os.path import expanduser

import os
from Crypto.PublicKey import RSA


def testkey():
    path = expanduser("~/.ssh")
    testkey = os.path.join(path, "testkey")

    key = RSA.importKey(open(testkey).read())
    print(key)

    print(hex(key.n))


def pub():
    key = RSA.importKey(open("mykey.pub").read())
    print(key.n)
    print(key.e)


if __name__ == '__main__':
    pub()
