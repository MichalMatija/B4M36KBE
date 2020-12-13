import random
import string
import os
from lab4.BulkCipher import encrypt
from lab4.BulkCipher import decrypt

BLOCK_SIZE = 16

key = os.urandom(BLOCK_SIZE)
iv = os.urandom(BLOCK_SIZE)
key = b'C\xf9\x12\xe3\xbbo\xd0\x99\xd6{\x99\x02\xaeq\xef\x8c'
iv = b'\x1a3p^=\x84\xd0\x94\xb8\xfb\xf2\x8f\x06\x84\x00s'
print(key)
print(iv)
msg = ''.join(random.choice(string.ascii_lowercase) for i in range(1024))
assert decrypt(key, iv, encrypt(key, iv, msg)) == msg

