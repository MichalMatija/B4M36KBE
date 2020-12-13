import unittest
from lab4.RSA import RSA
import conversion


class RSATest(unittest.TestCase):

    def testRSA_int(self):
        p = 13604067676942311473880378997445560402287533018336255431768131877166265134668090936142489291434933287603794968158158703560092550835351613469384724860663783
        q = 20711176938531842977036011179660439609300527493811127966259264079533873844612186164429520631818559067891139294434808806132282696875534951083307822997248459
        e = 3

        alice = RSA(p, q, e)
        bob = RSA()

        # Bob send message to alice
        message = 12345678
        ciphertext = bob.encrypt_int(message, alice.n, alice.encryption_exponent)
        plaintext = alice.decrypt_int(ciphertext)

        self.assertEqual(message, plaintext)

    def testRSA_bytes(self):
        p = 13604067676942311473880378997445560402287533018336255431768131877166265134668090936142489291434933287603794968158158703560092550835351613469384724860663783
        q = 20711176938531842977036011179660439609300527493811127966259264079533873844612186164429520631818559067891139294434808806132282696875534951083307822997248459
        e = 3

        alice = RSA(p, q, e)
        bob = RSA()

        # Bob send message to alice
        message_int = 12345678
        message = conversion.int2bytes(message_int)
        ciphertext = bob.encrypt(message, conversion.int2bytes(alice.n),
                                 conversion.int2bytes(alice.encryption_exponent))
        plaintext = alice.decrypt(ciphertext)

        self.assertEqual(message, plaintext)
        self.assertEqual(message_int, conversion.bytes2int(plaintext))

    def testInvmod(self):
        a = 19
        m = 1212393831
        expected_inv_mod = 701912218

        inv_mod = RSA().invmod(a, m)

        self.assertEqual(inv_mod, expected_inv_mod)

    def testInvmodException(self):
        a = 13
        m = 91

        with self.assertRaises(Exception) as context:
            RSA().invmod(a, m)

        self.assertTrue('Inverse does not exist!' in str(context.exception))

if __name__ == '__main__':
    unittest.main()