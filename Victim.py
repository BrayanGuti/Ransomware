import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import json
import threading
import os
from Crypto.Hash import SHA256


def handle_attacker(conn):
    """Maneja la comunicación con el atacante, incluyendo el intercambio de claves y el proceso de descifrado."""
    
    # Generar el par de claves RSA de la víctima
    victim_key = RSA.generate(2048)
    victim_public_key = victim_key.publickey().export_key().decode()
    victim_cert = {'id': 'Víctima', 'pk': victim_public_key}

    # Recibir y mostrar el certificado del atacante
    attacker_cert = json.loads(conn.recv(2048).decode())
    print("Certificado recibido del atacante:", attacker_cert)

    # Enviar el certificado público de la víctima al atacante
    conn.send(json.dumps(victim_cert).encode())

    # Recibir la clave cifrada enviada por el atacante
    encrypted_key = conn.recv(256)
    cipher = PKCS1_OAEP.new(victim_key)
    # Desencriptar la clave temporal usando la clave privada de la víctima
    short_term_key = cipher.decrypt(encrypted_key)

    # Recibir y mostrar el mensaje de rescate (notificación)
    ransom_message = json.loads(conn.recv(2048).decode())
    print("Mensaje de rescate:", ransom_message)

    # Esperar recibir las instrucciones de descifrado de los archivos
    decryption_instructions = json.loads(conn.recv(2048).decode())
    print("Instrucciones de descifrado recibidas:", decryption_instructions)

    # Derivar la clave simétrica para el descifrado y proceder a descifrar los archivos
    symmetric_key = SHA256.new(short_term_key).digest()[:16]
    decrypt_files(symmetric_key)  # Función que implementa la lógica de descifrado de archivos

    # Cerrar la conexión con el atacante
    conn.close()

def decrypt_files(secret_key):
    """Descifra los archivos cifrados utilizando AES en modo CBC y elimina los archivos cifrados si es necesario."""
    
    # Asegurarse de que la carpeta 'Decrypted' exista para guardar los archivos descifrados
    decrypted_folder = 'Decrypted'
    if not os.path.exists(decrypted_folder):
        os.makedirs(decrypted_folder)

    # Obtener los archivos cifrados en la carpeta 'Files_encrypted'
    files = os.listdir('Files_encrypted')

    for file in files:
        # Leer el archivo cifrado
        with open(f'Files_encrypted/{file}', 'rb') as f:
            iv = f.read(16)  # Leer el IV que está al inicio del archivo cifrado
            ciphertext = f.read()  # El resto del contenido es el texto cifrado

        # Crear un objeto de descifrado con la clave simétrica y el IV correspondiente
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
        # Descifrar el archivo y quitar el padding
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)

        # Guardar el archivo descifrado en la carpeta 'Decrypted'
        decrypted_filename = f'{decrypted_folder}/{file[:-4]}'  # Eliminar la extensión '.enc' del archivo descifrado
        with open(decrypted_filename, 'wb') as f:
            f.write(plaintext)

        # Eliminar el archivo cifrado original
        os.remove(f'Files_encrypted/{file}')

    # Verificar si la carpeta de archivos cifrados está vacía y eliminarla si es necesario
    if not os.listdir('Files_encrypted'):
        os.rmdir('Files_encrypted')  # Eliminar la carpeta si está vacía
        print("La carpeta 'Files_encrypted' estaba vacía y ha sido eliminada.")

    print("Archivos descifrados y archivos cifrados eliminados.")

def victim_program():
    """Función principal que escucha las conexiones del atacante y maneja las comunicaciones de descifrado."""
    host = '127.0.0.1'
    port = 5000

    # Crear el socket del servidor (victima)
    victim_socket = socket.socket()
    victim_socket.bind((host, port))
    victim_socket.listen(2)  # El servidor escucha hasta 2 conexiones entrantes

    print(f"Víctima escuchando en {host}:{port}")

    while True:
        # Aceptar una conexión entrante desde el atacante
        conn, address = victim_socket.accept()
        print("Conexión desde:", address)

        # Crear un hilo para manejar la comunicación con el atacante
        client_thread = threading.Thread(target=handle_attacker, args=(conn,))
        client_thread.start()

if __name__ == '__main__':
    victim_program()
