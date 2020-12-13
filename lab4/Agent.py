from lab4.DiffieHellman import DiffieHellman
from lab4.AES_CBC import AES_CBC
import os


class Agent:
    msg = None

    def __init__(self, message=None):
        if message is not None:
            self.msg = message
            p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
            g = 2
            self.diffieHellman = DiffieHellman(p, g)
        else:
            self.diffieHellman = None
        self.aes = AES_CBC()

    def receive_public_data(self, p, g):
        self.diffieHellman = DiffieHellman(p, g)

    def send_public_data(self):
        if self.diffieHellman is not None:
            return self.diffieHellman.p, self.diffieHellman.g
        else:
            raise Exception('DiffieHellman is not initialized yet!')

    def receive_public_key(self, public_key):
        self.diffieHellman.key_exchange(public_key)

    def send_public_key(self):
        if self.diffieHellman is not None:
            return self.diffieHellman.my_public_key
        else:
            raise Exception('DiffieHellman is not initialized yet!')

    def receive_message(self, message):
        self.msg = self.aes.decrypt(self.diffieHellman.get_key(), None, message)

    def send_message(self):
        block_size = 16
        iv = os.urandom(block_size)
        return self.aes.encrypt(self.diffieHellman.get_key(), iv, self.msg)
