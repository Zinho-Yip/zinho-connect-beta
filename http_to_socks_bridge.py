
import socket
import threading
import select
import struct

# --- 配置 ---
# 桥接服务监听的地址和端口
BRIDGE_HOST = '0.0.0.0'
BRIDGE_PORT = 5000

# 内部SOCKS5代理的地址和端口 (tlsp 服务)
SOCKS5_HOST = '127.0.0.1'
SOCKS5_PORT = 2500

# --- 实现 ---

def handle_client(client_socket):
    """处理每个客户端的连接请求"""
    try:
        request_data = client_socket.recv(4096)
        if not request_data:
            return

        # 1. 解析 HTTP CONNECT 请求
        try:
            first_line = request_data.split(b'\r\n')[0].decode('utf-8')
            method, target, _ = first_line.split(' ')
            if method.upper() != 'CONNECT':
                client_socket.sendall(b'HTTP/1.1 405 Method Not Allowed\r\n\r\n')
                return
            target_host, target_port = target.split(':')
            target_port = int(target_port)
        except Exception as e:
            print(f"[-] 解析HTTP CONNECT请求失败: {e}")
            client_socket.sendall(b'HTTP/1.1 400 Bad Request\r\n\r\n')
            return
        
        print(f"[+] 收到 CONNECT 请求，目标: {target_host}:{target_port}")

        # 2. 作为SOCKS5客户端连接到内部的tlsp服务
        socks_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            socks_socket.connect((SOCKS5_HOST, SOCKS5_PORT))

            # SOCKS5 握手
            # a. 发送客户端支持的认证方法 (0x00 = No Auth)
            socks_socket.sendall(b'\x05\x01\x00')
            auth_method_resp = socks_socket.recv(2)
            if auth_method_resp != b'\x05\x00':
                raise Exception(f"SOCKS5服务器需要认证，但我不会: {auth_method_resp.hex()}")

            # b. 发送连接请求
            # VER=5, CMD=1(CONNECT), RSV=0, ATYP=3(Domain), HOST_LEN, HOST, PORT
            host_bytes = target_host.encode('utf-8')
            port_bytes = struct.pack('!H', target_port)
            req = b'\x05\x01\x00\x03' + bytes([len(host_bytes)]) + host_bytes + port_bytes
            socks_socket.sendall(req)

            # c. 接收SOCKS5服务器的响应
            resp = socks_socket.recv(4)
            if resp[0] != 0x05 or resp[1] != 0x00:
                raise Exception(f"SOCKS5连接失败，响应: {resp.hex()}")
            
            # 读取剩余的响应以清空缓冲区
            # BND.ADDR和BND.PORT依赖于ATYP，这里简化处理，直接读取直到结束
            # 通常响应长度是 1 + 1 + 1 + 1 + len(addr) + 2，但我们不关心具体地址
            # 简单假设是IPv4，读取 1 + 4 + 2 = 7 字节
            addr_type = socks_socket.recv(1)[0]
            if addr_type == 1: # IPv4
                socks_socket.recv(4 + 2)
            elif addr_type == 3: # Domain
                domain_len = socks_socket.recv(1)[0]
                socks_socket.recv(domain_len + 2)
            elif addr_type == 4: # IPv6
                socks_socket.recv(16 + 2)
            else:
                 raise Exception(f"未知的地址类型 {addr_type}")

        except Exception as e:
            print(f"[-] 连接到内部SOCKS5代理失败: {e}")
            client_socket.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            socks_socket.close()
            return
        
        print(f"[+] SOCKS5 连接成功建立: {target_host}:{target_port}")

        # 3. 通知客户端连接已建立
        client_socket.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')

        # 4. 双向转发数据
        transfer_data(client_socket, socks_socket)

    finally:
        client_socket.close()


def transfer_data(sock1, sock2):
    """在两个socket之间双向转发数据"""
    sockets = [sock1, sock2]
    try:
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, 600)
            if exceptional:
                break
            if not readable: # Timeout
                break
                
            for s in readable:
                data = s.recv(8192)
                if not data:
                    # socket关闭
                    return
                if s is sock1:
                    sock2.sendall(data)
                else:
                    sock1.sendall(data)
    except Exception as e:
        print(f"[!] 转发数据时发生错误: {e}")
    finally:
        sock1.close()
        sock2.close()


def main():
    """主函数，启动服务"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((BRIDGE_HOST, BRIDGE_PORT))
    server_socket.listen(10)
    print(f"[*] HTTP-to-SOCKS5 桥接服务已启动，监听于 {BRIDGE_HOST}:{BRIDGE_PORT}")
    print(f"[*] 将转发到内部 SOCKS5 代理 {SOCKS5_HOST}:{SOCKS5_PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[*] 收到来自 {addr[0]}:{addr[1]} 的新连接")
        # 为每个客户端连接创建一个新线程
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.daemon = True
        thread.start()

if __name__ == '__main__':
    main()
