import codecs
import unittest

from Crypto.PublicKey import RSA

import pkcs15
import s1c1 as c1
import s1c2 as c2
import s6c42 as c42


class TestSolutions(unittest.TestCase):
    def get_keys(self, key_name: str):
        with open(key_name) as f:
            priv_key = RSA.importKey(f.read())

        with open(key_name + ".pub") as f:
            pub_key = RSA.importKey(f.read())

        key_len = c42.get_key_length_in_bytes(priv_key)

        return priv_key, pub_key, key_len

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
        _, pub_key, _ = self.get_keys('test/fixtures/e3_test_key')

        content = b'hi mom'
        c42.forge_signature(pub_key, content)

        # TODO: check that the broken implementation parses this

    def test_pkcs(self):
        priv_key, pub_key, key_len_bytes = self.get_keys('test/fixtures/e3_test_key')

        msg = b'test string'
        sig = pkcs15.sign(priv_key, key_len_bytes, msg)

        pkcs15.verify_unsafe(pub_key, key_len_bytes, sig, msg)


if __name__ == '__main__':
    unittest.main()
