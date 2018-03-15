import unittest

import s2c12 as c12
import s4c31 as c31
import s4c31 as c32


class AllTests(unittest.TestCase):
    def test_s2c12(self):
        found = c12.main()
        self.assertEqual(found, c12.UNKNOWN)

    def test_s4c31(self):
        c31.main()

    def test_s4c32(self):
        c32.main()


if __name__ == '__main__':
    unittest.main()
