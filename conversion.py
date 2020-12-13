import binascii


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


def int2bytes(i: int):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')


def bytes2int(b: bytes):
    return int.from_bytes(b, byteorder='big')
