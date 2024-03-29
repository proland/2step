import unittest

from twostep import secret, scratch

class TestSecretFunctions(unittest.TestCase):
    
    key = "AAAABBBBCCCCDDDD"

    def setUp(self):
        self.sec = secret.Secret(self.key)

    def dummy_time(self):
        return 1234567890

    def test_get_key(self):
        self.assertEqual(self.key, self.sec.get_key())

    def test_get_qrcode(self):
        url = "https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth://totp/user@example.com%3Fsecret%3DAAAABBBBCCCCDDDD"
        self.assertEqual(url, self.sec.get_qrcode("user", "example.com"))

    def test_auth_fail(self):
        self.assertFalse(self.sec.auth("000000"))

    def test_auth_pass(self):
        secret.time.time = self.dummy_time
        self.assertTrue(self.sec.auth("158814"))
