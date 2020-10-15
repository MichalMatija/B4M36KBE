from Crypto.Cipher import AES
import conversion
import binascii

sentence = """I, Michal, understand that cryptography is easy to mess up, and
that I will not carelessly combine pieces of cryptographic ciphers to
encrypt my users' data. I will not write crypto code myself, but defer to
high-level libraries written by experts who took the right decisions for me,
like NaCL."""
print("*********************************************")
print("Exercise 1:")
print(sentence)
print("*********************************************")

with open('result21.txt', 'w') as file:
    file.write(sentence)


def encrypt_aes_block(x, key):
    if not len(x.encode('utf-8')) == 16:
        print("Plaintext is not 16 bytes long")
        raise
    if not len(key.encode('utf-8')) == 16:
        print("Key is not 16 bytes long")
        raise

    aes = AES.new(key, AES.MODE_ECB)
    encrypted_data = aes.encrypt(x)

    return conversion.bin2hex(encrypted_data)


data2 = "90 miles an hour"
key2 = "CROSSTOWNTRAFFIC"

ciphertext2 = encrypt_aes_block(data2, key2)
print("*********************************************")
print("Exercise 2:")
print("Ciphertext is: ", ciphertext2)
print("*********************************************")

with open('result22.txt', 'w') as file:
    file.write("Ciphertext is: ")
    file.write(ciphertext2)


def decrypt_aes_block(y, key):
    if not len(y) == 16:
        print("Decrypted text is not 16 bytes long")
        raise
    if not len(key.encode('utf-8')) == 16:
        print("Key is not 16 bytes long")
        raise

    aes = AES.new(key, AES.MODE_ECB)
    decrypted_data = aes.decrypt(y)

    return conversion.bin2txt(decrypted_data)


data3 = "fad2b9a02d4f9c850f3828751e8d1565"
key3 = "VALLEYSOFNEPTUNE"

plaintext3 = decrypt_aes_block(conversion.hex2bin(data3), key3)

print("*********************************************")
print("Exercise 3:")
print("Plaintext is: ", plaintext3)
print("*********************************************")

with open('result23.txt', 'w') as file:
    file.write("Plaintext is: ")
    file.write(plaintext3)


def pad(x):
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
    }[len(x) % 16]


padded_hello4 = pad("hello")

print("*********************************************")
print("Exercise 4:")
print("PKCS#7 pad(\"hello\") is: ", padded_hello4)
print("*********************************************")

with open('result24.txt', 'w') as file:
    file.write("PKCS#7 pad(\"hello\") is: ")
    file.write(padded_hello4)


def unpad(y):
    last_character = conversion.txt2hex(y[-1])

    if int(last_character, 16) == 0x10 and int(conversion.txt2hex(y[-16]), 16) == 0x10:
        return y[:-16]
    elif int(last_character, 16) == 0x0f and int(conversion.txt2hex(y[-15]), 16) == 0x0f:
        return y[:-15]
    elif int(last_character, 16) == 0x0e and int(conversion.txt2hex(y[-14]), 16) == 0x0e:
        return y[:-14]
    elif int(last_character, 16) == 0x0d and int(conversion.txt2hex(y[-13]), 16) == 0x0d:
        return y[:-13]
    elif int(last_character, 16) == 0x0c and int(conversion.txt2hex(y[-12]), 16) == 0x0c:
        return y[:-12]
    elif int(last_character, 16) == 0x0b and int(conversion.txt2hex(y[-11]), 16) == 0x0b:
        return y[:-11]
    elif int(last_character, 16) == 0x0a and int(conversion.txt2hex(y[-10]), 16) == 0x0a:
        return y[:-10]
    elif int(last_character, 16) == 0x09 and int(conversion.txt2hex(y[-9]), 16) == 0x09:
        return y[:-9]
    elif int(last_character, 16) == 0x08 and int(conversion.txt2hex(y[-8]), 16) == 0x08:
        return y[:-8]
    elif int(last_character, 16) == 0x07 and int(conversion.txt2hex(y[-7]), 16) == 0x07:
        return y[:-7]
    elif int(last_character, 16) == 0x06 and int(conversion.txt2hex(y[-6]), 16) == 0x06:
        return y[:-6]
    elif int(last_character, 16) == 0x05 and int(conversion.txt2hex(y[-5]), 16) == 0x05:
        return y[:-5]
    elif int(last_character, 16) == 0x04 and int(conversion.txt2hex(y[-4]), 16) == 0x04:
        return y[:-4]
    elif int(last_character, 16) == 0x03 and int(conversion.txt2hex(y[-3]), 16) == 0x03:
        return y[:-3]
    elif int(last_character, 16) == 0x02 and int(conversion.txt2hex(y[-2]), 16) == 0x02:
        return y[:-2]
    elif int(last_character, 16) == 0x01:
        return y[:-1]
    else:
        print("Unexpected error unpad: ", y)
        raise


unpadded_hello5 = unpad("hello\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b")

print("*********************************************")
print("Exercise 5:")
print("PKCS#7 unpad(\"hello\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\") is: ", unpadded_hello5)
print("*********************************************")

with open('result25.txt', 'w') as file:
    file.write("PKCS#7 unpad(\"hello\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\\x0b\") is: ")
    file.write(unpadded_hello5)


def encrypt_aes_ecb(x, key):
    padded_x = pad(x)

    start = 0
    end = 16
    encrypted_text = ""
    for block_index in range(int(len(padded_x) / 16)):
        block = padded_x[start + (end * block_index):end + (block_index * 16)]
        encrypted_text += encrypt_aes_block(block, key)

    return encrypted_text


data6 = "Well, I stand up next to a mountain and I chop it down with the edge of my hand"
key6 = "vdchldslghtrturn"

encrypted_text6 = encrypt_aes_ecb(data6, key6)

print("*********************************************")
print("Exercise 6:")
print("Encrypted text is: ", encrypted_text6)
print("*********************************************")

with open('result26.txt', 'w') as file:
    file.write("Encrypted text is: ")
    file.write(encrypted_text6)


def decrypt_aes_ecb(y, key):
    start = 0
    end = 16
    y = binascii.unhexlify(y)
    decrypted_text = ""
    for block_index in range(int(len(y) / 16)):
        block = y[start + (end * block_index):end + (block_index * 16)]
        decrypted_text += decrypt_aes_block(block, key)

    return unpad(decrypted_text)


data7 = "792c2e2ec4e18e9d3a82f6724cf53848abb28d529a85790923c94b5c5abc34f50929a03550e678949542035cd669d4c66da25e59a5519689b3b4e11a870e7cea"
key7 = "If the mountains"

decrypted_text7 = decrypt_aes_ecb(data7, key7)

print("*********************************************")
print("Exercise 7:")
print("Decrypted text is: ", decrypted_text7)
print("*********************************************")

with open('result27.txt', 'w') as file:
    file.write("Decrypted text is: ")
    file.write(decrypted_text7)

data8 = ""
key8 = "TLKNGBTMYGNRTION"
with open('text21.hex', 'r') as file:
    data8 = file.read().split('\n')

# Swap process
tmp = data8[0]
data8[0] = data8[2]
data8[2] = tmp

text = ""
for index in range(len(data8)):
    text += data8[index]

decrypted_text8 = decrypt_aes_ecb(text, key8)

print("*********************************************")
print("Exercise 8:")
print("1. Some hex lines have the same hex, and their plaintext is the same")
print("2. It is pad. Plaintext is 1010...10 (size is 16 byte)")
print("4. Decrypted first line is: ", decrypted_text8.partition("\n")[0])
print("*********************************************")

with open('result28.txt', 'w') as file:
    file.write("1. Some hex lines have the same hex, and their plaintext is the same")
    file.write("\n")
    file.write("2. It is pad. Plaintext is 1010...10 (size is 16 byte)")
    file.write("\n")
    file.write("4. Decrypted first line is: ")
    file.write(decrypted_text8.partition('\n')[0])
    file.write("\n")
    file.write("Whole text: ")
    file.write("\n")
    file.write(decrypted_text8)


def welcome(name):
    first_string = "Your name is "
    third_string = " and you are a user"
    key9 = "RIDERSONTHESTORM"
    ciphertext = encrypt_aes_ecb(first_string + name + third_string, key9)

    return ciphertext


# print(welcome("michal"))
jim_encrypted = welcome("Jim")
# print(jim_encrypted)
padded_16_bytes = welcome("")[-32:]
# print(padded_16_bytes)
admin_encrypted = welcome("   you are an admin             ")[32:64]
# print(admin_encrypted)

your_name_is_encrypted = welcome("   Your name is                 ")[32:64]
# print(your_name_is_encrypted)

key9 = "RIDERSONTHESTORM"
# print(decrypt_aes_ecb(jim_encrypted, key9))
# print(decrypt_aes_ecb(padded_16_bytes, key9))
# print(decrypt_aes_ecb(admin_encrypted + padded_16_bytes, key9))
# print(decrypt_aes_ecb(your_name_is_encrypted + admin_encrypted + padded_16_bytes, key9))


print("*********************************************")
print("Exercise 9:")
print("2. Ciphertext of welcome(\"Jim\") is: ", jim_encrypted)
print("3. Ciphertext of 1010..10", padded_16_bytes)
print("4. Ciphertext of plaintext \"you are an admin\" ", admin_encrypted)
print("5. Ciphertext is: ", your_name_is_encrypted + admin_encrypted)
print("6. Jim decprytion: ", decrypt_aes_ecb(jim_encrypted, key9))
print("6. admin decprytion: ", decrypt_aes_ecb(admin_encrypted + padded_16_bytes, key9))
print("6. your_name_is + admin decprytion: ",
      decrypt_aes_ecb(your_name_is_encrypted + admin_encrypted + padded_16_bytes, key9))
print("7. The problem is, I can find out the secret message in function")
print("*********************************************")

with open('result29.txt', 'w') as file:
    file.write("2. Ciphertext of welcome(\"Jim\") is: ")
    file.write(jim_encrypted)
    file.write("\n")
    file.write("3. Ciphertext of 1010..10")
    file.write(padded_16_bytes)
    file.write("\n")
    file.write("4. Ciphertext of plaintext \"you are an admin\" ")
    file.write(admin_encrypted)
    file.write("\n")
    file.write("5. Ciphertext is: ")
    file.write(your_name_is_encrypted + admin_encrypted)
    file.write("\n")
    file.write("6. Jim decprytion: ")
    file.write(decrypt_aes_ecb(jim_encrypted, key9))
    file.write("\n")
    file.write("6. admin decprytion: ")
    file.write(decrypt_aes_ecb(admin_encrypted + padded_16_bytes, key9))
    file.write("\n")
    file.write("6. your_name_is + admin decprytion: ")
    file.write(decrypt_aes_ecb(your_name_is_encrypted + admin_encrypted + padded_16_bytes, key9))
    file.write("\n")
    file.write("7. The problem is, I can find out the secret message in function")


def hide_secret(x):
    SECRET = "this should stay secret"
    x += SECRET
    key10 = "COOL T MAGIC KEY"

    return encrypt_aes_ecb(x, key10)


print(hide_secret("just listen find the magic key"))
print(hide_secret("AAAAAAAAAAAAAAA"))
encrypted_text = hide_secret("AAAAAAAAAAAAAAA")
data10 = "AAAAAAAAAAAAAAA"


def find_secret_length():
    previous_length = len(binascii.unhexlify(hide_secret('')))
    for i in range(20):
        length = len(binascii.unhexlify(hide_secret('A' * i)))
        if length != previous_length:
            return previous_length - i


# print(find_secret_length())


def find_plaintext():
    secret_length = find_secret_length()
    found_secret = ""
    block = int(((secret_length) + (16 - secret_length % 16)) / 16)

    for found_characters in range(secret_length):
        text = "A" * (secret_length + (16 - secret_length % 16) - found_characters - 1)
        encrypted_text = hide_secret(text)

        for i in range(256):
            potential_secret_chr = hide_secret(text + found_secret + chr(i))
            if potential_secret_chr[32 * (block - 1):block * 32] == encrypted_text[32 * (block - 1): block * 32]:
                # print(chr(i))
                found_secret += chr(i)
                break

    return found_secret


# print(find_plaintext())
ciphertext10 = hide_secret("45a306391112e09639cc44fa4d53c79ec90162749b6055bbc3d0811c0da6bd9bdf3dccce5ff98e742ffdc33a1c8e84b9d47e0182d8fa07c9291b25d8dab01199")

print("*********************************************")
print("Exercise 10:")
print("Ciphertext: ", ciphertext10)
print("Last plaintext byte will be first character of SECRET")
print("Secret is: ", find_plaintext())
print("I use function find_secret_length for find out the complete secret length")
print("*********************************************")

with open('result210.txt', 'w') as file:
    file.write("Ciphertext: ")
    file.write(ciphertext10)
    file.write("\n")
    file.write("Last plaintext byte will be first character of SECRET")
    file.write("\n")
    file.write("Secret is: ")
    file.write(find_plaintext())
    file.write("\n")
    file.write("I use function find_secret_length for find out the complete secret length")