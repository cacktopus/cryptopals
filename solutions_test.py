import codecs
import unittest

import os

from Crypto.PublicKey import RSA

import s1c1 as c1
import s1c2 as c2
import s6c42 as c42


class TestSolutions(unittest.TestCase):
    def test_s1c1(self):
        h = c1.fromhex(c1.t)
        r = c1.base64encode(h)

        self.assertEqual(h,
                         11259432467145572969189485457381052543241507215288737798329079056359121649591228422793827173000297562297701340508013)
        self.assertEqual(r, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

    def test_s1c2(self):
        i0 = codecs.decode(c2.t0, "hex")
        i1 = codecs.decode(c2.t1, "hex")

        r = c2.xor2(i0, i1)

        assert codecs.encode(r, "hex") == c2.expected

    def test_s6c42(self):
        pub_key = os.environ.get('RSA_KEY', 'test/fixtures/e3_test_key.pub')

        with open(pub_key) as f:
            key = RSA.importKey(f.read())

        content = b'hi mom'
        c42.forge_signature(key, content)

        # TODO: check that the broken implementation parses this

    def test_pkcs(self):
        pass


if __name__ == '__main__':
    unittest.main()
