import unittest
import os
import random
import string
from lab4.AES_CBC import AES_CBC


class AES_CBCTest(unittest.TestCase):
    block_size = 16

    def testScenarioAES(self):
        aes = AES_CBC()
        key = os.urandom(self.block_size)
        iv = os.urandom(self.block_size)
        msg = ''.join(random.choice(string.ascii_lowercase) for i in range(1024))

        ciphertext = aes.encrypt(key, iv, msg)
        plaintext = aes.decrypt(key, iv, ciphertext)

        self.assertEqual(msg, plaintext)

if __name__ == '__main__':
    unittest.main()