import socket


def attacker_program():
    host = '127.0.0.1'
    port = 5000  # Número de puerto del servidor

    attacker_socket = socket.socket()  # Instanciar socket
    attacker_socket.connect((host, port))  # Conectar al servidor
    message = input(" -> ")  # Tomar entrada del usuario

    while message.lower().strip() != 'bye':
        attacker_socket.send(message.encode())  # Enviar mensaje
        data = attacker_socket.recv(1024).decode()  # Recibir respuesta
        print('Recibido de la victima: ' + data)  # Mostrar en terminal
        message = input(" -> ")  # Volver a tomar entrada

    attacker_socket.close()  # Cerrar la conexión


if __name__ == '__main__':
    attacker_program()
