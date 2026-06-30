import socket
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

SHARED_PASSWORD = b"wrong_password"
SALT = b"fixed_salt_for_lab"

def derive_key(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=16)

def aes_encrypt(key, plaintext):
    iv = b'\x00' * 16
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

key = derive_key(SHARED_PASSWORD, SALT)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 9999))

client.send(b"AUTH_REQUEST|user1")

data = client.recv(1024).decode().strip()
if data.startswith("CHALLENGE|"):
    challenge_hex = data.split("|")[1]
    challenge = bytes.fromhex(challenge_hex)
    print(f"收到挑战: {challenge_hex}")

    response = aes_encrypt(key, challenge)
    client.send(f"RESPONSE|{response.hex()}".encode())
else:
    print("服务器返回异常:", data)
    client.close()
    exit()

result = client.recv(1024).decode().strip()
if result == "AUTH_SUCCESS":
    print("客户端：认证成功！")
else:
    print("客户端：认证失败！")
client.close()