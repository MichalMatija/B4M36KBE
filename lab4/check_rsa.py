import conversion
from lab4.RSA import RSA

p = 13604067676942311473880378997445560402287533018336255431768131877166265134668090936142489291434933287603794968158158703560092550835351613469384724860663783
q = 20711176938531842977036011179660439609300527493811127966259264079533873844612186164429520631818559067891139294434808806132282696875534951083307822997248459
e = 3

rsa = RSA(p, q, e)
private_key = rsa.decryption_exponent
public_key = rsa.encryption_exponent
message = "I will not write crypto code myself, but defer to high-level libraries written by experts who took the right decisions for me".encode()
encrypted_message = rsa.encrypt(message, conversion.int2bytes(rsa.n), conversion.int2bytes(public_key))
decrypted_message = rsa.decrypt(encrypted_message)
assert message == decrypted_message
