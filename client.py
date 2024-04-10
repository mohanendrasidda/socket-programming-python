import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

T_PORT = 12345
BUF_SIZE = 1024

# Connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', T_PORT))

# Receive server's public key
server_public_key = client_socket.recv(BUF_SIZE)

# Load server's public key
rsa_key = RSA.import_key(server_public_key)

while True:
    # Generate AES key
    aes_key = get_random_bytes(16)

    # Encrypt AES key with server's public key
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key_cipher = cipher_rsa.encrypt(aes_key)

    # Send encrypted AES key to the server
    client_socket.sendall(aes_key_cipher)

    # Use AES key for communication
    aes_cipher = AES.new(aes_key, AES.MODE_CTR)

    # Get message from user
    message = input("Enter your message: ")

    # Encrypt message with AES key
    encrypted_message = aes_cipher.encrypt(message.encode())

    # Send encrypted message to server
    client_socket.sendall(encrypted_message)

    # Receive encrypted response from server
    encrypted_response = client_socket.recv(BUF_SIZE)

    # Decrypt response with AES key
    aes_cipher_decryption = AES.new(aes_key, AES.MODE_CTR)  # Create new AES cipher object for decryption
    decrypted_response = aes_cipher_decryption.decrypt(encrypted_response)

    print(f"message recieved from server: {decrypted_response.hex()}")


# Close the connection
client_socket.close()
