import binascii
import re


# Exercise 0: make utilites

def bin2txt(binary: bytes):
    return binary.decode('utf-8')


def bin2hex(binary):
    return binascii.b2a_hex(binary).decode('utf-8')


def txt2bin(txt):
    return txt.encode('utf-8')


def hex2bin(hex_str):
    return bytes.fromhex(hex_str)


def hex2txt(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8', 'ignore')


def txt2hex(txt):
    return txt.encode("utf-8").hex()


# Exercise 1: encrypt xor

def xor(text: str, key: str):
    text_bytes = bytes(txt2bin(text))
    key_bytes = bytes(txt2bin(key))

    hex_ciphertext = ""
    key_bytes_length = len(key)
    key_index = 0
    for index in range(0, len(text_bytes)):
        if key_index >= key_bytes_length:
            key_index = 0
        hex_ciphertext = hex_ciphertext + hex(text_bytes[index] ^ key_bytes[key_index])[2:].zfill(2)
        key_index += 1

    return hex_ciphertext


print("*********************************************")
print("Exercise 1:")
plaintText = "everything remains raw"
key = "word up"
print(xor(plaintText, key))

plaintText1 = "the world is yours"
key1 = "illmatic"
ciphertext1 = xor(plaintText1, key1)
print(ciphertext1)
print("*********************************************")

with open('result1.txt', 'w') as file:
    file.write("Ciphertext is: ")
    file.write(ciphertext1)

# Ciphertext of hex-encoded text1 against the key1 is "1d04094d161b1b0f0d4c051e410d06161b1f"


# Exercise 2: decrypt single-letter xor

def decrypt(data: bytes, key: int):
    return bytes([byte ^ key for byte in data])


ciphertext = "404b48484504404b48484504464d4848045d4b"

print("*********************************************")
print("Exercise 2:")
print(bin2txt(decrypt(hex2bin(ciphertext), 36)))
plaintext2 = hex2txt(xor(hex2txt(ciphertext), chr(36)))
print(plaintext2)
print("*********************************************")

with open('result2.txt', 'w') as file:
    file.write("Answer: We can see that some hex characters are repeated (404b48484504 is same like 404b48484504)")
    file.write("\n")
    file.write("Plaintext is: ")
    file.write(plaintext2)


# We can see that some hex characters are repeated (404b48484504 is same like 404b48484504)
# Plaintext is dolla dolla bill yo

# Exercise 3: hand crack single-letter xor

def hand_crack_single_letter_xor(data):
    for key in range(256):
        # print(key)
        # print(decrypt(hex2bin(data), key))
        decrypt(hex2bin(data), key)


data = ""
with open('text1.hex', 'r') as file:
    data = file.read()

hand_crack_single_letter_xor(data)

plaintText3 = bin2txt(decrypt(hex2bin(data), 77))
with open('result3.txt', 'w') as file:
    file.write(plaintText3)

print("*********************************************")
print("Exercise 3:")
print(plaintText3.partition('\n')[0])
print("*********************************************")

# First line is: Busta Rhymes up in the place, true indeed

# Exercise 4: automate cracking single-letter xor
character_frequencies = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074, ' ': .13000, 'A': .08167,
    'B': .01492, 'C': .02782, 'D': .04253,
    'E': .12702, 'F': .02228, 'G': .02015, 'H': .06094,
    'I': .06094, 'J': .00153, 'K': .00772, 'L': .04025,
    'M': .02406, 'N': .06749, 'O': .07507, 'P': .01929,
    'Q': .00095, 'R': .05987, 'S': .06327, 'T': .09056,
    'U': .02758, 'V': .00978, 'W': .02360, 'X': .00150,
    'Y': .01974, 'Z': .00074
}


def get_score(data):
    sum = 0
    for letter in data:
        if not chr(letter).isalpha():
            sum += 0
            continue
        score = character_frequencies.get(chr(letter))
        if score is not None:
            sum += score

    return sum


def get_score2(data: str):
    join = "".join(re.split("[^a-zA-Z]*", data))
    sum = 0
    for l in join:
        score = character_frequencies.get(l)
        if score is not None:
            sum += score
    return len(join)


def automate_cracking_single_letter_xor(data):
    max_score = 0
    result_plaintext = ""
    result_key = 0
    for key in range(256):
        current_plaintext = decrypt(hex2bin(data), key)
        # current_score = get_score(current_plaintext)
        current_score = get_score2(hex2txt(bin2hex(current_plaintext)))
        if current_score > max_score:
            max_score = current_score
            result_plaintext = current_plaintext
            result_key = key

    return result_plaintext, result_key


data4 = ""
with open('text1.hex', 'r') as file:
    data4 = file.read()

plaintText4, key4 = automate_cracking_single_letter_xor(data4)
with open('result4.txt', 'w') as file:
    file.write(bin2txt(plaintText4))
    file.write("\n")
    file.write("Key is: ")
    file.write(str(key4))
# print(automate_cracking_single_letter_xor(data4))

print("*********************************************")
print("Exercise 4:")
print("First line of plaintext is: ", bin2txt(plaintText4).partition('\n')[0])
print("Key is: ", key4)
print("*********************************************")

# Exercise 5: crack multiple-letter xor with given key length

data5 = ""
with open('text2.hex', 'r') as f:
    data5 = f.read()

key5 = ""
for index in range(10):
    plaint_text, key = automate_cracking_single_letter_xor(txt2hex(hex2txt(data5)[index::10]))
    key5 = key5 + chr(key)
    # print(key)
    # print(key, chr(key))

plaintText5 = hex2txt(xor(hex2txt(data5), "SupremeNTM"))

with open('result5.txt', 'w') as file:
    file.write(plaintText5)
    file.write("\n")
    file.write("Key is: ")
    file.write("SupremeNTM")

# print(key5)
print("*********************************************")
print("Exercise 5:")
print("Plaintext is: ", plaintText5.partition('\n')[0])
print("Key is: ", "SupremeNTM")
print("*********************************************")

# Exercise 6: crack multiple-letter xor with unknown key length

def hamming_distance(str1, str2):
    distance = 0
    xor_hex = xor(bin2txt(str1), bin2txt(str2))

    for byte in hex2bin(xor_hex):
        distance += bin(byte).count("1")

    return distance


def key_length(data):
    min_avg = None
    result_key_length = None

    for key_len in range(2, 41):
        normalized_distances = []

        chunks = [data[i:i + key_len] for i in range(0, len(data), key_len)]
        while True:
            if len(chunks) < 2:
                break

            chunk1 = chunks[0]
            chunk2 = chunks[1]

            if key_len > len(chunk2):
                break

            normalized_distances.append(hamming_distance(chunk1, chunk2) / key_len)
            chunks = chunks[2:]

        avg = sum(normalized_distances) / len(normalized_distances)

        if min_avg is None or avg < min_avg:
            min_avg = avg
            result_key_length = key_len

    return result_key_length


def transpose_chunks_by_key_len(key_len, data):
    chunks = []
    for i in range(key_len):
        chunks.append(data[i::key_len])

    return chunks


def find_key(chunks):
    key = ''

    for i in chunks:
        max_score = 0
        best_key_char = ''
        for j in range(127):
            res = hex2txt(xor(bin2txt(i), chr(j)))
            current_score = 0
            for k in res.upper():
                if k in "ABCDEFGHIJKLMNOPQRSTUVWXYZ ":
                    current_score += character_frequencies.get(k)
            if current_score > max_score:
                max_score = current_score
                best_key_char = chr(j)
        key += best_key_char

    return key

data6 = ""
with open('text3.hex', 'r') as f:
    data6 = f.read()

data6 = hex2bin(data6)

key_len = key_length(data6)
chunks = transpose_chunks_by_key_len(key_len, data6)
key6 = find_key(chunks)
plaintext6 = xor(bin2txt(data6), key6)
plaintext6 = hex2txt(plaintext6)

with open('result6.txt', 'w') as file:
    file.write(plaintext6)
    file.write('\n')
    file.write("Key is: ")
    file.write(key6)

print("*********************************************")
print("Exercise 6:")
print("Plaintext is: ", plaintext6.partition("\n")[0])
print("Key is: ", key6)
print("*********************************************")
