import unittest

from pkcs7_padding import pkcs7_padding, pkcs7_unpad, PaddingError, BlockSizeError, pkcs7_padding_valid


class TestPadding(unittest.TestCase):
    def test_padding(self):
        eq = self.assertEqual

        eq(
            pkcs7_padding(b"abcde", 16),
            b"abcde" + bytes([11] * 11),
        )

        eq(
            pkcs7_unpad(pkcs7_padding(b"abcde", 16), 16),
            b"abcde",
        )

        eq(
            pkcs7_padding(b"", 16),
            b"" + bytes([16] * 16),
        )

        eq(
            pkcs7_padding(b"a" * 16, 16),
            b"a" * 16 + bytes([16] * 16),
        )

        eq(
            pkcs7_padding(b"a" * 32, 16),
            b"a" * 32 + bytes([16] * 16),
        )

        eq(
            pkcs7_unpad(pkcs7_padding(b"", 16), 16),
            b"",
        )

        eq(
            pkcs7_unpad(pkcs7_padding(b"a" * 16, 16), 16),
            b"a" * 16,
        )

        eq(
            pkcs7_unpad(pkcs7_padding(b"a" * 32, 16), 16),
            b"a" * 32,
        )

        self.assertRaises(BlockSizeError, pkcs7_unpad, b"abcde", 16)
        self.assertRaises(PaddingError, pkcs7_unpad, b"a" * 16, 16)
        self.assertRaises(PaddingError, pkcs7_unpad, b"a" * 15 + bytes([0x02]), 16)

        self.assertFalse(pkcs7_padding_valid(b"a" * 16, 16))
        self.assertFalse(pkcs7_padding_valid(b"", 16))
        self.assertTrue(pkcs7_padding_valid(bytes([16] * 16), 16))
        self.assertTrue(pkcs7_padding_valid(b"a" * 15 + bytes([1]), 16))
        self.assertFalse(pkcs7_padding_valid(b"a" * 15 + bytes([2]), 16))

        self.assertFalse(pkcs7_padding_valid(b"a" * 15 + b"\x00", 16))


if __name__ == '__main__':
    unittest.main()
