import socket
import threading
import select


def handle_client(client_socket):
    try:
        # Read the HTTP request from the client
        request_data = client_socket.recv(4096)
        if not request_data:
            return

        # Extract the host and port from the CONNECT request
        first_line = request_data.split(b'\n')[0]
        method, url, _ = first_line.split(b' ')

        if method != b'CONNECT':
            # For simplicity, this bridge only handles HTTPS CONNECT requests
            client_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            return

        host, port_str = url.split(b':')
        port = int(port_str)

        # Create a SOCKS5 proxy request
        # For simplicity, assuming no authentication is required for the SOCKS5 server
        socks_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # The SOCKS5 server is the tlsp service running on localhost (inside the container)
        socks_socket.connect(('127.0.0.1', 2500))

        # Send the SOCKS5 connection request
        # Version 5, 1 authentication method, No authentication required
        socks_socket.sendall(b'\x05\x01\x00')
        auth_response = socks_socket.recv(2)
        if auth_response != b'\x05\x00':
            raise Exception('SOCKS5 authentication failed')

        # Send the SOCKS5 connection request to the final destination
        # Version 5, CONNECT command, Reserved, Address type (domain), host length, host, port
        socks_request = b'\x05\x01\x00\x03' + len(host).to_bytes(1, 'big') + host + port.to_bytes(2, 'big')
        socks_socket.sendall(socks_request)

        # Receive the SOCKS5 response
        socks_response = socks_socket.recv(4096)
        if not (socks_response and socks_response[1] == 0):
            raise Exception(f'SOCKS5 connection failed, response: {socks_response}')

        # Send a successful HTTP response to the client
        client_socket.sendall(b'HTTP/1.1 200 OK\r\n\r\n')

        # Bridge the connections
        bridge_connection(client_socket, socks_socket)

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()

def bridge_connection(sock1, sock2):
    sockets = [sock1, sock2]
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 60)

            if exceptional:
                break

            if not readable:
                continue

            for sock in readable:
                other_sock = sock2 if sock is sock1 else sock1
                data = sock.recv(4096)
                if not data:
                    # Connection closed
                    return
                other_sock.sendall(data)
    except Exception as e:
        print(f"Bridge error: {e}")
    finally:
        for s in sockets:
            s.close()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind to 0.0.0.0 to accept connections from outside the container
    server_socket.bind(('0.0.0.0', 5000))
    server_socket.listen(10)
    # print("HTTP-to-SOCKS5 bridge listening on 0.0.0.0:5000")

    while True:
        client_socket, addr = server_socket.accept()
        # print(f"Accepted connection from {addr}")
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()

if __name__ == "__main__":
    main()
