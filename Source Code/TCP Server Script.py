import socket
import threading # Allows multi-threaded programming so the server can handle multiple clients simultaneously.
import time
import re # Enables regular expression matching for text processing, such as checking IPs in the log file.

# Configuration
HOST = '192.168.204.13'  # Server machine's IP address
PORT = 9999             # Port number

# Track active connections
active_connections = 0
lock = threading.Lock()  # To synchronize access to the active_connections counter
connection_time = {}     # Dictionary to store the time when connections were established

def is_blocked(ip):
    """
    Check if an IP is in the blocked IP log file.
    """
    try:
        with open("blocked_ips_log.txt", "r") as f: # r -> read mode & with -> manage file resouces
            for line in f:
                # Extract IP addresses matching the format in the log file
                if (match := re.search(r"IP (\d+\.\d+\.\d+\.\d+)", line)): # Yhe walrus operator to assign the val of re.search to match while evaluating it.
                    if match.group(1) == ip:
                        return True  # IP is blocked
        return False  # IP not found in the log
    except FileNotFoundError:
        print("[ERROR] blocked_ips_log.txt not found!")
        return False

# Test IPs
# print(is_blocked("192.168.43.117"))  # Should return True if this IP is in the log
# print(is_blocked("192.168.10.20"))   # Should return False if this IP is not in the log

def handle_client(conn, addr): # addr -> tuple containing the client’s IP & port, conn -> socket object representing the conn to the client.
    """
    Handle a single client connection.
    """
    global active_connections # changes here can be reflected outward. 
    with lock: # lock -> Ensures that race conditions don't occur. -> Give scenario
        active_connections += 1
        print(f"[DEBUG] Active Connections: {active_connections}")

    # Store the time when this connection was established
    connection_time[addr] = time.time() # Present epoch if possible

    try:
        print(f"[DEBUG] Connection from {addr}")
        while True:
            data = conn.recv(1024) # rece upto 1024 bytes of data
            if not data: # If no data was rece
                break
            print(f"[DEBUG] Received from {addr}: {data.decode()}")
            conn.sendall(b"Let's see you try !!!")
    except Exception as e:
        print(f"[ERROR] Error with {addr}: {e}")
    finally: # Ensures that the cleanup code is always executed
        conn.close()
        with lock:
            active_connections -= 1
            print(f"[DEBUG] Connection from {addr} closed. Active Connections: {active_connections}")
        
        # After the connection is closed, check if the IP is blocked
        if is_blocked(addr[0]):
            print(f"[DEBUG] Connection from {addr[0]} was processed after being blocked.")
        else:
            print(f"[DEBUG] Connection from {addr[0]} was processed normally.")

def start_server():
    """
    Start the server to listen for connections.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # AF_INET -> Specifies IPv4 addressing & SOCK_STREAM -> Specifies TCP protocol 
    server_socket.bind((HOST, PORT))  # Bind to server IP and port
    server_socket.listen(5)           # Listen for up to 5 connections
    print(f"[INFO] Server running on {HOST}:{PORT}")

    try:
        while True:
            conn, addr = server_socket.accept() # Blocks until a client connects

            # Check if the incoming connection is from a blocked IP
            if is_blocked(addr[0]):
                print(f"[DEBUG] Blocking connection from IP {addr[0]} (logged in blocked_ips_log.txt).")
                conn.close()  # Close the connection if the IP is blocked
            else:
                print(f"[DEBUG] Allowing connection from IP {addr[0]}.")
                threading.Thread(target=handle_client, args=(conn, addr)).start()

    except Exception as e:
        print(f"[ERROR] Error occurred: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
    