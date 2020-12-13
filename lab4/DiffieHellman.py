import random
import hashlib


class DiffieHellman:
    p = None  # public key1
    g = None  # public key2
    private_key = None
    my_public_key = None
    shared_key = None

    def __init__(self, p, g, private_key=None):
        self.p = p
        self.g = g
        if private_key is None:
            self.private_key = random.randint(3, self.p - 1)
        else:
            self.private_key = private_key
        self.my_public_key = pow(g, self.private_key, p)

    def key_exchange(self, shared_key):
        self.shared_key = pow(shared_key, self.private_key, self.p)

    def get_key(self):
        block_size = 16
        str_shared_key = str(self.shared_key)
        sha1_ = hashlib.sha1()
        for chunk in range(0, len(str_shared_key), block_size):
            sha1_.update(str_shared_key[chunk : chunk + block_size].encode('UTF-8'))
        return sha1_.digest()[:-4]
