import itertools
import hashlib


def tupleToString(tuple):
    str = ''.join(tuple)
    return str


salt = '1e09d'
my_sha1 = "2655a13f039e9966d590ca8e260cc1a48bf494a6"
password_possible_letters = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
         'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'y', 'x', 'z']


def find_passwd():
    possible_passwords = [tupleToString(x) for x in itertools.product(password_possible_letters, repeat=5)]
    password = ""
    print("Permutation with repetition done")

    for p_passd in possible_passwords:
        possible_sha1 = hashlib.sha1((p_passd + salt).encode()).hexdigest()
        if possible_sha1 == my_sha1:
            password = p_passd
            break

    return password


print(find_passwd())


def hex2bin(hex_str):
    return bytes.fromhex(hex_str)


def decrypt(data: bytes, key: str):
    plaintext = ""
    positionInKey = 0
    keySize = len(key)
    for byte in data:
        plaintext = plaintext + chr(byte ^ ord(key[positionInKey]))
        if positionInKey < (keySize - 1):
            positionInKey += 1
        else:
            positionInKey = 0

    return plaintext


def findKey(cipher: bytes, plaintext: str):
    key = ""
    position_plaintext = 0
    for byte in cipher:
        for potential_key in range(256):
            xor_chr = chr(byte ^ potential_key)
            if xor_chr == plaintext[position_plaintext]:
                key += chr(potential_key)
        position_plaintext += 1

    return key


data2 = "440e523719001f621e5c5f533a134c1537420f515f1c0a556123000b3a051a50097f120d107f51515c101e061c3b4b1c162a4b1542523c1e10007f515f565556"
message2 = "<a href='index.php?code'>Here</a> you can find your secure code."
data2Bin = hex2bin(data2)

data3 = "2f0a1e3347450d37584116447f0a0e097f545f4010160005714b360d3e40154542310e0645395d421244100a52310e1d0d7f5a5d505b330e0c023a411e"
message3 = "Well, that's all for now. Stay tuned for the next challenges."
data3Bin = hex2bin(data3)

message1 = "Welcome <b>matijmic</b>, this is your first secret message."
data = "2f0a1e3c04081c7f05570f5a3e1f0b0f325b530e1f1a515e7f1f0d102c195c4217260417177f545940430c4f013a08171c2b195854442c0a050071"
dataBin = hex2bin(data)

print(findKey(dataBin, message1))
print(findKey(data2Bin, message2))
print(findKey(data3Bin, message3))

key = "xor_key_9517_kbe_2020"
print(decrypt(dataBin, key))
print(decrypt(data2Bin, key))
print(decrypt(data3Bin, key))
