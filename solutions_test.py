import unittest

import s1c1 as c1


class TestSolutions(unittest.TestCase):
    def test_s1c1(self):
        h = c1.fromhex(c1.t)
        r = c1.base64encode(h)

        self.assertEqual(h, 11259432467145572969189485457381052543241507215288737798329079056359121649591228422793827173000297562297701340508013)
        self.assertEqual(r, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")


if __name__ == '__main__':
    unittest.main()
