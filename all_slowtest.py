import unittest

import s2c12 as c12
import webserver


class AllTests(unittest.TestCase):
    def test_s2c12(self):
        found = c12.main()
        self.assertEqual(found, c12.UNKNOWN)

    def test_s4c31(self):
        webserver.main()


if __name__ == '__main__':
    unittest.main()
