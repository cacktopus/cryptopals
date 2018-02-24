import codecs
import unittest

import s1c1 as c1
import s1c2 as c2


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


if __name__ == '__main__':
    unittest.main()
