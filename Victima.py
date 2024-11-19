import socket
import threading

def handle_attacker(conn):
    while True:
        data = conn.recv(1024).decode()  # Recibir datos del cliente
        if not data:
            break
        print("De atacante conectado: " + str(data))
        response = input(' -> ')  # Pedir mensaje de respuesta
        conn.send(response.encode())  # Enviar respuesta al cliente

    conn.close()  # Cerrar la conexión con el cliente actual

def victim_program():
    host = '127.0.0.1'
    port = 5000  # Puerto a usar

    victim_socket = socket.socket()  
    victim_socket.bind((host, port))  
    victim_socket.listen(2)  # Escucha hasta 2 clientes simultáneamente

    print(f"victima escuchando en {host}:{port}")

    while True:
        conn, address = victim_socket.accept()  # Acepta nueva conexión
        print("Conexión desde: " + str(address))
        
        # Crear un hilo para manejar la conexión del cliente
        client_thread = threading.Thread(target=handle_attacker, args=(conn,))
        client_thread.start()

if __name__ == '__main__':
    victim_program()