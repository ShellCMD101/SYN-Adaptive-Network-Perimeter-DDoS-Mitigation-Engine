import socket

# Configuration
HOST = '192.168.10.5'  # Server machine's IP address
PORT = 9999             # Port number

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))  # Bind to server IP and port
    server_socket.listen(5)          # Listen for up to 5 connections
    print(f"Server running on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server_socket.accept()
            print(f"Connection from {addr}")
            try:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    print(f"Received: {data.decode()}")
                    conn.sendall(b"ACK")
            finally:
                conn.close()  # Ensure the connection is closed after handling it
    except Exception as e:
        print(f"Error occurred: {e}")
    finally:
        server_socket.close()  # Close the server socket when the server stops

if __name__ == "__main__":
    start_server()
