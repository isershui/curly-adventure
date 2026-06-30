import socket
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

SHARED_PASSWORD = b"iot_secret_2024"
SALT = b"fixed_salt_for_lab"
USERS = {"user1", "user2"}

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

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('127.0.0.1', 9999))
server.listen(1)
print("服务器已启动，等待客户端连接...")

conn, addr = server.accept()
print(f"客户端已连接：{addr}")

data = conn.recv(1024).decode().strip()
if not data.startswith("AUTH_REQUEST|"):
    conn.close()
    exit()

username = data.split("|")[1]
if username not in USERS:
    conn.send(b"USER_INVALID")
    conn.close()
    print("非法用户名，已拒绝")
    exit()

challenge = os.urandom(16)
expected_response = aes_encrypt(key, challenge)
conn.send(f"CHALLENGE|{challenge.hex()}".encode())
print(f"已发送挑战: {challenge.hex()}")

resp_data = conn.recv(1024).decode().strip()
if not resp_data.startswith("RESPONSE|"):
    conn.send(b"AUTH_FAIL")
    conn.close()
    exit()

client_response = bytes.fromhex(resp_data.split("|")[1])

if client_response == expected_response:
    conn.send(b"AUTH_SUCCESS")
    print("认证成功！")
else:
    conn.send(b"AUTH_FAIL")
    print("认证失败：应答不一致")

conn.close()
server.close()