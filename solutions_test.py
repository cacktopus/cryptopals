import codecs
import unittest

import pkcs15
import rsa
import s1c1 as c1
import s1c2 as c2
import s2c12 as c12
import s2c13 as c13
import s6c41 as c41
import s6c42 as c42
import util


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

    def test_s2c12(self):
        self.skipTest("slow")
        found = c12.main()
        self.assertEqual(found, c12.UNKNOWN)

    def test_s2c13(self):
        res = c13.parse_kv('foo=bar&baz=qux&zap=zazzle')
        self.assertEqual(res, {
            "foo": "bar",
            "baz": "qux",
            "zap": "zazzle",
        })

        self.assertEqual(
            c13.profile_for("foo@bar.com", "10", "user"),
            "email=foo@bar.com&uid=10&role=user",
        )

        self.assertEqual(
            c13.profile_for("foo@bar.com&role=admin", "10", "user"),
            "email=foo@bar.comroleadmin&uid=10&role=user",
        )

        e = c13.encrypt_profile("foo@bar.com")
        p = c13.decrypt(e)

        self.assertEqual(p, {
            "email": "foo@bar.com",
            "uid": "10",
            "role": "user",
        })

    def test_s6c41(self):
        c41.main()

    def test_s6c42(self):
        priv_key, pub_key, key_len_bytes = util.get_keys('test/fixtures/e3_test_key')

        msg = b'hi mom'
        fake_sig = c42.forge_signature(pub_key, msg)
        real_sig = pkcs15.sign(priv_key, key_len_bytes, msg)

        self.assertNotEqual(fake_sig, real_sig)

        real, _ = pkcs15.verify_unsafe(pub_key, key_len_bytes, real_sig, msg)
        self.assertTrue(real)

        fake, _ = pkcs15.verify_unsafe(pub_key, key_len_bytes, fake_sig, msg)
        self.assertTrue(fake)

        # TODO: create a verify routine that rejects the fake

    def test_pkcs(self):
        priv_key, pub_key, key_len_bytes = util.get_keys('test/fixtures/e3_test_key')

        msg = b'test string'
        sig = pkcs15.sign(priv_key, key_len_bytes, msg)

        pkcs15.verify_unsafe(pub_key, key_len_bytes, sig, msg)

    def test_rca_command_line(self):
        assert rsa.main


if __name__ == '__main__':
    unittest.main()
