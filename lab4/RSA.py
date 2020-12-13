import conversion


class RSA:
    p = None
    q = None
    n = None
    eulerFunction = None
    encryption_exponent = None
    decryption_exponent = None

    # (n, encryption_exponent) - public key
    # (n, decryption_exponent) - privat key
    def __init__(self, p=None, q=None, e=None):
        # p, q, e is for alice, Bob know only public key for encryption
        if p is not None and q is not None and e is not None:
            # Set first prime number
            self.p = p
            # Set second prime number
            self.q = q
            # compute n
            self.n = self.p * self.q
            # compute euler function
            self.eulerFunction = (self.p - 1) * (self.q - 1)
            # set e, thus that gcd(e, eulerFunction(n)) == 1
            self.encryption_exponent = e
            # compute decryption exponent, where d = e^(-1) % eulerFunction(n)
            self.decryption_exponent = self.invmod(self.encryption_exponent, self.eulerFunction)

    def encrypt(self, plaintext: bytes, n: bytes, encryption_exponent: bytes):
        ciphertext_int = self.encrypt_int(conversion.bytes2int(plaintext), conversion.bytes2int(n),
                                          conversion.bytes2int(encryption_exponent))
        # print(ciphertext_int)

        return conversion.int2bytes(ciphertext_int)

    def decrypt(self, ciphertext: bytes):
        plaintext_int = self.decrypt_int(conversion.bytes2int(ciphertext))
        # print(plaintext_int)

        return conversion.int2bytes(plaintext_int)

    def encrypt_int(self, plaintext: int, n: int, encryption_exponent: int):
        return pow(plaintext, encryption_exponent, n)

    def decrypt_int(self, ciphertext):
        return pow(ciphertext, self.decryption_exponent, self.n)

    def generate_key(self, e):
        return None

    def egcd(self, a, b):
        if a == 0:
            return b, 0, 1
        else:
            gcd, x, y = self.egcd(b % a, a)

        return gcd, y - (b // a) * x, x

    def invmod(self, a, m):
        gcd, x, y = self.egcd(a, m)
        if gcd != 1:
            raise Exception('Inverse does not exist!')
        else:
            return x % m
