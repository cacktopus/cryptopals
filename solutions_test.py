import codecs
import unittest

import pkcs15
import rsa
import s1c1 as c1
import s1c2 as c2
import s2c13 as c13
import s2c15 as c15
import s2c16 as c16
import s3c17 as c17
import s3c18 as c18
import s4c25 as c25
import s4c26 as c26
import s4c28 as c28
import s4c29 as c29
import s4c31 as c31
import s6c41 as c41
import s6c42 as c42
import util
from s2c10 import cbc_encrypt
from pkcs7_padding import pkcs7_padding
from webserver import insecure_compare


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

    def test_s2c13(self):
        res = c13.parse_kv('foo=bar&baz=qux&zap=zazzle')
        self.assertEqual(res, {
            "foo": "bar",
            "baz": "qux",
            "zap": "zazzle",
        })

        self.assertEqual(
            c13.profile_for(b"foo@bar.com", b"10", b"user"),
            b"email=foo@bar.com&uid=10&role=user",
        )

        self.assertEqual(
            c13.profile_for(b"foo@bar.com&role=admin", b"10", b"user"),
            b"email=foo@bar.comroleadmin&uid=10&role=user",
        )

        e = c13.encrypt_profile(b"foo@bar.com")
        p = c13.decrypt(e)

        self.assertEqual(p, {
            "email": "foo@bar.com",
            "uid": "10",
            "role": "user",
        })

        c13.main()

    def test_s2c15(self):
        c15.main()

    def test_s2c16(self):
        result = c16.userdata(b";admin=true")
        self.assertEqual(result,
                         b"comment1=cooking%20MCs;userdata=%59admin%61true;comment2=%20like%20a%20pound%20of%20bacon")

        def encrypt(m: bytes) -> bytes:
            padded = pkcs7_padding(m, 16)
            return cbc_encrypt(c16.KEY, padded)

        self.assertTrue(
            c16.is_admin(encrypt(b"abc=123;admin=true;def=456"))
        )

        self.assertFalse(
            c16.is_admin(encrypt(b"abc=123;admin%61true;def=456"))
        )

        payload = c16.encrypted_userdata(b";admin=true")

        self.assertEqual(c16.decrypt(payload),
                         b"comment1=cooking%20MCs;userdata=%59admin%61true;comment2=%20like%20a%20pound%20of%20bacon")

        self.assertFalse(
            c16.is_admin(payload)
        )

        c16.main()

    def test_s3c17(self):
        result = c17.padding_oracle_attack()
        self.assertEqual(result, c17.s)

    def test_s3c18(self):
        c18.main()

    def test_s4c25(self):
        c25.main()

    def test_s4c26(self):
        c26.main()

    def test_s4c28(self):
        c28.main()

    def test_s4c29(self):
        c29.main()

    def test_s4c31(self):
        eq = self.assertEqual
        eq(
            c31.hmac_md5(b"", b""),
            "74e6f7298a9c2d168935f58c001bad88",
        )

        eq(
            c31.hmac_sha1(b"", b""),
            "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d",
        )

        eq(
            c31.hmac_sha256(b"", b""),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad",
        )

        eq(
            c31.hmac_md5(b"key", b"The quick brown fox jumps over the lazy dog"),
            "80070713463e7749b90c2dc24911e275",
        )

        eq(
            c31.hmac_sha1(b"key", b"The quick brown fox jumps over the lazy dog"),
            "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9",
        )

        eq(
            c31.hmac_sha256(b"key", b"The quick brown fox jumps over the lazy dog"),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        )

        self.assertTrue(insecure_compare(0.0, "abcd", "abcd"))
        self.assertFalse(insecure_compare(0.0, "abcd", "abce"))
        self.assertFalse(insecure_compare(0.0, "aBcd", "abcd"))
        self.assertFalse(insecure_compare(0.0, "abc", "abcd"))
        self.assertFalse(insecure_compare(0.0, "abcd", "abc"))

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
