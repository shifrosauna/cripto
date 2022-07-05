from base64 import b64decode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
backend = default_backend()

def decrypt_aes_128_ecb(ctxt, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data =  decryptor.update(ctxt) + decryptor.finalize()
    # would need some padding stripping actually (we'll see padding later)
    message = decrypted_data
    return message


with open("1.txt") as file:
    data = file.read()

print(decrypt_aes_128_ecb(
    ctxt=b64decode(data),
    key=b"YELLOW SUBMARINE"
).decode())
