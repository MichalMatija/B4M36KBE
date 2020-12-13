from Crypto.Cipher import AES
import conversion

block_size = 16


class AES_CBC:

    def encrypt(self, key: bytes, iv: bytes, message):
        assert len(iv) == block_size

        # Pad message with PKCS#7 padding
        pad_message = self.pad(message)

        # Divide message into blocks by block_size(16)
        blocks = self.get_blocks(pad_message)
        previous_block = iv
        encrypted = conversion.bin2hex(iv)
        for block in blocks:
            encrypted_block = self.encrypt_block(key, block, previous_block)
            encrypted += conversion.bin2hex(encrypted_block)
            previous_block = encrypted_block

        return encrypted

    def decrypt(self, key: bytes, iv, encrypted_message):
        encrypted_message_binary = conversion.hex2bin(encrypted_message)

        if iv is None:
            iv = encrypted_message_binary[:block_size]

        encrypted_message_binary = encrypted_message_binary[block_size:]
        assert len(iv) == block_size

        blocks = self.get_blocks(encrypted_message_binary)

        plaintext = ""
        previous_block = iv
        for block in blocks:
            decrypted_block = self.decrypt_block(key, block, previous_block)
            plaintext += conversion.bin2txt(decrypted_block)
            previous_block = block

        return self.unpad(plaintext)

    def get_blocks(self, message):
        assert len(message) % block_size == 0

        blocks = []
        for i in range(0, len(message), block_size):
            blocks.append(message[i: i + block_size])

        return blocks

    def xor(self, x, y):
        return bytes(i ^ j for i, j in zip(x, y))

    def encrypt_block(self, key, block_to_encrypt, iv):
        aes_cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher_block = aes_cipher.encrypt(block_to_encrypt)
        return cipher_block

    def decrypt_block(self, key, block_to_decrypt, iv):
        aes_cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_block = aes_cipher.decrypt(block_to_decrypt)
        return decrypted_block

    def pad(self, x):
        return {
            0: x + "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10",
            1: x + "\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f",
            2: x + "\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e",
            3: x + "\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d",
            4: x + "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
            5: x + "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
            6: x + "\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a",
            7: x + "\x09\x09\x09\x09\x09\x09\x09\x09\x09",
            8: x + "\x08\x08\x08\x08\x08\x08\x08\x08",
            9: x + "\x07\x07\x07\x07\x07\x07\x07",
            10: x + "\x06\x06\x06\x06\x06\x06",
            11: x + "\x05\x05\x05\x05\x05",
            12: x + "\x04\x04\x04\x04",
            13: x + "\x03\x03\x03",
            14: x + "\x02\x02",
            15: x + "\x01",
        }[len(x) % block_size]

    def unpad(self, y):
        last_character = conversion.txt2hex(y[-1])

        if int(last_character, block_size) == 0x10 and int(conversion.txt2hex(y[-16]), block_size) == 0x10:
            return y[:-16]
        elif int(last_character, block_size) == 0x0f and int(conversion.txt2hex(y[-15]), block_size) == 0x0f:
            return y[:-15]
        elif int(last_character, block_size) == 0x0e and int(conversion.txt2hex(y[-14]), block_size) == 0x0e:
            return y[:-14]
        elif int(last_character, block_size) == 0x0d and int(conversion.txt2hex(y[-13]), block_size) == 0x0d:
            return y[:-13]
        elif int(last_character, block_size) == 0x0c and int(conversion.txt2hex(y[-12]), block_size) == 0x0c:
            return y[:-12]
        elif int(last_character, block_size) == 0x0b and int(conversion.txt2hex(y[-11]), block_size) == 0x0b:
            return y[:-11]
        elif int(last_character, block_size) == 0x0a and int(conversion.txt2hex(y[-10]), block_size) == 0x0a:
            return y[:-10]
        elif int(last_character, block_size) == 0x09 and int(conversion.txt2hex(y[-9]), block_size) == 0x09:
            return y[:-9]
        elif int(last_character, block_size) == 0x08 and int(conversion.txt2hex(y[-8]), block_size) == 0x08:
            return y[:-8]
        elif int(last_character, block_size) == 0x07 and int(conversion.txt2hex(y[-7]), block_size) == 0x07:
            return y[:-7]
        elif int(last_character, block_size) == 0x06 and int(conversion.txt2hex(y[-6]), block_size) == 0x06:
            return y[:-6]
        elif int(last_character, block_size) == 0x05 and int(conversion.txt2hex(y[-5]), block_size) == 0x05:
            return y[:-5]
        elif int(last_character, block_size) == 0x04 and int(conversion.txt2hex(y[-4]), block_size) == 0x04:
            return y[:-4]
        elif int(last_character, block_size) == 0x03 and int(conversion.txt2hex(y[-3]), block_size) == 0x03:
            return y[:-3]
        elif int(last_character, block_size) == 0x02 and int(conversion.txt2hex(y[-2]), block_size) == 0x02:
            return y[:-2]
        elif int(last_character, block_size) == 0x01:
            return y[:-1]
        else:
            print("Unexpected error unpad: ", y)
            raise
