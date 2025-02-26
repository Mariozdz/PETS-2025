import os
import socket
import time

from cryptography.hazmat.primitives.asymmetric import rsa, padding as async_padding
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Cargar la llave publica desde el archivo PEM
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/
def load_public_key(pem_path):
    with open(pem_path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

# Cifrado AES-CBC
def cifrado_aes(message, key):
    iv = os.urandom(16) # Vector de Inicializacion Random

    # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CBC
    # https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher.encryptor
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv)) # Cifrado AES Modo CBC al IV
    encryptor = cipher.encryptor()

    # https://cryptography.io/en/latest/hazmat/primitives/padding/#cryptography.hazmat.primitives.padding.PKCS7.padder
    padder = padding.PKCS7(128).padder()
    padded_text = padder.update(message) + padder.finalize()

    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    return iv, ciphertext

# Cifrado RSA-OAEP
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
def cifrado_rsa(public_key, data):
    return public_key.encrypt(
        data,
        async_padding.OAEP(
            mgf=async_padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

# Función para enviar mensaje al mixnet
def enviar_mensaje(host, port, encrypted_message):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))

            s.sendall(encrypted_message)

            response_bytes = s.recv(1)

            if response_bytes == b"\x06":
                print("Success")
            elif response_bytes == b"\x15":
                print("Error")
            else:
                print(f"Default: {response_bytes.hex()}")

    except socket.error as e:
        print(f"Socket error ({host}:{port}): {e}")

# Cargar llaves publicas
mix1 = load_public_key("public-key-mix-1.pem")
mix2 = load_public_key("public-key-mix-2.pem")
mix3 = load_public_key("public-key-mix-3.pem")

for i in range(6):
    # Mensaje
    recipient = "estudiante6"
    message = "Hola"
    message = f"{recipient},{message}".encode()

    # Primer cifrado (Mix 3)
    key3 = os.urandom(16) # Llave Random
    iv3, cifrado_1 = cifrado_aes(message, key3)
    E1 = cifrado_rsa(mix3, iv3 + key3) + cifrado_1

    # Segunda cifrado (Mix 2)
    key2 = os.urandom(16)
    iv2, cifrado_2 = cifrado_aes(E1, key2)
    E2 = cifrado_rsa(mix2, iv2 + key2) + cifrado_2

    # Tercer cifrado (Mix 1)
    key1 = os.urandom(16)
    iv1, cifrado_3 = cifrado_aes(E2, key1)
    E3 = cifrado_rsa(mix1, iv1 + key1) + cifrado_3

    # Calcular y verificar el tamaño
    actual_length = len(E3)
    message_length = actual_length.to_bytes(4, byteorder='big', signed=False)

    # Construir mensaje final
    network_message = message_length + E3

    # Enviar al primer MIX
    URL = ""
    PORT = 50018
    enviar_mensaje(URL, PORT, network_message)
    #time.sleep(1)