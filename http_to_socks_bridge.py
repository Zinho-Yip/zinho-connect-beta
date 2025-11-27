import socket
import threading
import select
from urllib.parse import urlparse

# --- 配置 ---
# 内部SOCKS5代理的地址和端口
SOCKS5_SERVER_HOST = '127.0.0.1'
SOCKS5_SERVER_PORT = 2500

# 桥接服务监听的地址和端口
BRIDGE_HOST = '0.0.0.0'
BRIDGE_PORT = 5000
# --- 配置结束 ---

def log(message):
    """简单的日志函数，用于输出信息"""
    print(f"[Bridge] {message}")

def handle_client(client_socket):
    """处理单个客户端连接"""
    try:
        request_data = client_socket.recv(4096)
        if not request_data:
            return

        first_line = request_data.split(b'\r\n')[0]
        log(f"Request: {first_line.decode(errors='ignore')}")
        
        method, url, version = first_line.split(b' ', 2)

        if method == b'CONNECT':
            # 处理 HTTPS 的 CONNECT 请求
            host, port = parse_connect_request(url)
        else:
            # 处理 HTTP 的普通请求
            host, port = parse_http_request(url)

        if not host or not port:
            raise ValueError("Could not determine target host or port.")

        log(f"Connecting to {host}:{port} via SOCKS5 proxy...")
        
        # 连接到后端的SOCKS5服务
        socks_socket = connect_to_socks_proxy(host, port)
        
        log("SOCKS5 connection successful.")

        if method == b'CONNECT':
            # 如果是CONNECT, 通知客户端连接已建立
            client_socket.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        else:
            # 如果是普通HTTP请求, 需要将修改后的请求发送到SOCKS5隧道
            modified_request = rewrite_http_request(request_data)
            socks_socket.sendall(modified_request)

        # 开始双向转发数据
        bridge_connection(client_socket, socks_socket)

    except Exception as e:
        log(f"Error handling client: {e}")
    finally:
        client_socket.close()

def parse_connect_request(url):
    """从CONNECT请求的URL中解析主机和端口"""
    try:
        host, port_str = url.split(b':')
        return host.decode('utf-8'), int(port_str)
    except Exception as e:
        log(f"Failed to parse CONNECT URL '{url.decode(errors='ignore')}': {e}")
        return None, None

def parse_http_request(url):
    """从普通HTTP请求的URL中解析主机和端口"""
    try:
        parsed_url = urlparse(url.decode('utf-8'))
        scheme = parsed_url.scheme
        host = parsed_url.hostname
        port = parsed_url.port or (80 if scheme == 'http' else 443)
        return host, port
    except Exception as e:
        log(f"Failed to parse HTTP URL '{url.decode(errors='ignore')}': {e}")
        return None, None

def connect_to_socks_proxy(target_host, target_port):
    """通过SOCKS5代理连接到目标主机"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((SOCKS5_SERVER_HOST, SOCKS5_SERVER_PORT))

    # 1. 发送SOCKS5认证请求 (无认证)
    s.sendall(b'\x05\x01\x00')
    auth_response = s.recv(2)
    if auth_response != b'\x05\x00':
        raise ConnectionError(f'SOCKS5 authentication failed. Got: {auth_response.hex()}')

    # 2. 发送SOCKS5连接请求 (使用域名)
    host_bytes = target_host.encode('utf-8')
    port_bytes = target_port.to_bytes(2, 'big')
    
    # [VER, CMD, RSV, ATYP, ADDR_LEN, ADDR, PORT]
    #  05   01   00    03     len      ...   ...
    request = b'\x05\x01\x00\x03' + len(host_bytes).to_bytes(1, 'big') + host_bytes + port_bytes
    s.sendall(request)

    # 3. 接收SOCKS5响应
    # +----+-----+-------+------+----------+----------+
    # |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    # +----+-----+-------+------+----------+----------+
    # | 1  |  1  | X'00' |  1   | Variable |    2     |
    # +----+-----+-------+------+----------+----------+
    response_header = s.recv(4)
    if len(response_header) < 4 or response_header[0] != 0x05 or response_header[1] != 0x00:
        # 读取剩余的响应数据以提供更详细的错误信息
        remaining_data = s.recv(1024)
        raise ConnectionError(f'SOCKS5 connection failed. REP code: {response_header[1] if len(response_header) > 1 else "N/A"}. Full response: {(response_header + remaining_data).hex()}')

    # 根据地址类型(ATYP)读取绑定的地址和端口
    addr_type = response_header[3]
    if addr_type == 1:  # IPv4
        s.recv(4)
    elif addr_type == 3:  # Domain name
        domain_len = s.recv(1)[0]
        s.recv(domain_len)
    elif addr_type == 4:  # IPv6
        s.recv(16)
    s.recv(2) # Port

    return s

def rewrite_http_request(request_data):
    """重写HTTP请求，将绝对URI改为相对URI"""
    lines = request_data.split(b'\r\n')
    first_line = lines[0]
    method, url, version = first_line.split(b' ', 2)
    
    parsed_url = urlparse(url)
    path = parsed_url.path or '/'
    if parsed_url.query:
        path += '?' + parsed_url.query
    
    new_request_line = b' '.join([method, path.encode(), version])
    
    # 替换掉Proxy-Connection头
    new_headers = []
    for line in lines[1:]:
        if line and not line.lower().startswith(b'proxy-connection'):
            new_headers.append(line)
            
    return b'\r\n'.join([new_request_line] + new_headers)

def bridge_connection(sock1, sock2):
    """在两个socket之间双向转发数据"""
    sockets = [sock1, sock2]
    try:
        while True:
            # 等待可读或异常事件
            readable, _, exceptional = select.select(sockets, [], sockets, 60)

            if exceptional:
                log("Bridge connection error.")
                break

            if not readable:
                # 超时
                continue

            for sock in readable:
                other_sock = sock2 if sock is sock1 else sock1
                try:
                    data = sock.recv(4096)
                    if not data:
                        # 连接已关闭
                        log("Connection closed by one side.")
                        return
                    other_sock.sendall(data)
                except ConnectionError:
                    log("Connection error during data transfer.")
                    return
    except Exception as e:
        log(f"Bridge error: {e}")
    finally:
        for s in sockets:
            s.close()

def main():
    """主函数，启动桥接服务"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((BRIDGE_HOST, BRIDGE_PORT))
    server_socket.listen(20)
    log(f"HTTP-to-SOCKS5 bridge listening on {BRIDGE_HOST}:{BRIDGE_PORT}")

    while True:
        try:
            client_socket, addr = server_socket.accept()
            log(f"Accepted connection from {addr}")
            thread = threading.Thread(target=handle_client, args=(client_socket,))
            thread.daemon = True
            thread.start()
        except KeyboardInterrupt:
            log("Server shutting down.")
            break
        except Exception as e:
            log(f"Error accepting connections: {e}")
    
    server_socket.close()

if __name__ == "__main__":

    try:

        main()

    except Exception as e:

        log(f"FATAL: Bridge service failed to start: {e}")

        # Exit with a non-zero code to make sure the container stops

        import sys

        sys.exit(1)
