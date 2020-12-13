import unittest
from parameterized import parameterized
from lab4.DiffieHellman import DiffieHellman


class DiffieHellmanTest(unittest.TestCase):

    @parameterized.expand([
        [37, 5, 4, 3, 10],
        [
            0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF,
            2, 4, 3, 4096]
    ])
    def testKeyExchange(self, p, g, a, b, shared_key):
        alice = DiffieHellman(p, g, a)
        bob = DiffieHellman(p, g, b)

        alice.key_exchange(bob.my_public_key)
        bob.key_exchange(alice.my_public_key)

        self.assertEqual(alice.shared_key, shared_key)
        self.assertEqual(bob.shared_key, shared_key)

    def testHashFromSharedSecret(self):
        p = 37
        g = 5
        a = 4
        b = 3
        expected_hash = b'\xb1\xd5x\x11\x11\xd8O{?\xe4Z\x08R\xe5\x97X'

        alice = DiffieHellman(p, g, a)
        bob = DiffieHellman(p, g, b)

        alice.key_exchange(bob.my_public_key)
        bob.key_exchange(alice.my_public_key)
        print(alice.get_key())
        self.assertEqual(alice.get_key(), expected_hash)
        self.assertEqual(bob.get_key(), expected_hash)



if __name__ == '__main__':
    unittest.main()
