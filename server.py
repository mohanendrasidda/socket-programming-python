import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

T_PORT = 12345
BUF_SIZE = 1024

# Generate RSA key pair
rsa_key = RSA.generate(2048)
public_key = rsa_key.publickey().export_key()

# Start server socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', T_PORT))
server_socket.listen(1)

print("Server is listening...")

# Accept connection from client
conn, addr = server_socket.accept()
print('Connected by', addr)

# Send public key to client
conn.sendall(public_key)

while True:
    # Receive AES key from client
    aes_key_cipher = conn.recv(BUF_SIZE)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(aes_key_cipher)

    # Use AES key for communication
    aes_cipher = AES.new(aes_key, AES.MODE_CTR)

    # Receive encrypted message from client
    encrypted_msg = conn.recv(BUF_SIZE)
    if not encrypted_msg:
        break

    # Decrypt message
    decrypted_msg = aes_cipher.decrypt(encrypted_msg)
    print('Received message from client:', decrypted_msg.decode("iso-8859-1"))

    # Send encrypted response to client
    response = input("Enter your response: ")
    aes_cipher_encryption = AES.new(aes_key, AES.MODE_CTR)
    encrypted_response = aes_cipher_encryption.encrypt(response.encode())
    conn.sendall(encrypted_response)

conn.close()
