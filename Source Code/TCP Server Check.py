import socket

HOST = '192.168.204.117'  # Use localhost for local testing
PORT = 9999

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # with -> auto ensures socket goes boom when block ends
    try:
        s.connect((HOST, PORT))
        s.sendall(b'I will be hacking You!!!')
        data = s.recv(1024) # also waiting to receive up to 1024 bytes of data from the server
        print(f'Received: {data.decode()}')
    except ConnectionRefusedError as e:
        print(f"[ERROR] Failed to connect: {e}")
