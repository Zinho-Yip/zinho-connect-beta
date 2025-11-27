# cli.py （修改后完整文件）
from .log import logger

from pathlib import Path

import socket

import threading

import time

from . import remote, fake_desync, fragment, utils

from .config import config

from .remote import match_domain

from .pac import generate_pac, load_pac

from urllib.parse import urlparse

datapath = Path()

pacfile = "function genshin(){}"

ThreadtoWork = False

proxy_thread = None

class ThreadedServer(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))

    def listen(self,block=True):
        global ThreadtoWork, proxy_thread
        self.sock.listen(
            128
        )  # up to 128 concurrent unaccepted socket queued , the more is refused untill accepting those.
        proxy_thread = threading.Thread(target=self.accept_connections, args=())
        proxy_thread.start()
        if block:
            try:
                # 主程序逻辑
                while True:
                    time.sleep(1)  # 主线程的其他操作
            except KeyboardInterrupt:
                # 捕获 Ctrl+C
                logger.warning("\nServer shutting down.")
            finally:
                ThreadtoWork = False
                self.sock.close()
        else:
            return self

    def accept_connections(self):
        try:
            global ThreadtoWork
            while ThreadtoWork:
                client_sock, _ = self.sock.accept()
                client_sock.settimeout(config["my_socket_timeout"])
                time.sleep(0.01)  # avoid server crash on flooding request
                thread_up = threading.Thread(
                    target=self.my_upstream, args=(client_sock,)
                )
                thread_up.daemon = True  # avoid memory leak by telling os its belong to main program , its not a separate program , so gc collect it when thread finish
                thread_up.start()
            self.sock.close()
        except Exception as e:
            logger.warning(f"Server error: {repr(e)}")

    def handle_client_request(self, client_socket):
        try:
            # 协议嗅探（兼容原有逻辑）
            initial_data = client_socket.recv(5, socket.MSG_PEEK)
            if not initial_data:
                client_socket.close()
                return None

            # 协议分流判断
            if initial_data[0] == 0x05:  # SOCKS5协议
                return self._handle_socks5(client_socket)
            else:  # HTTP协议处理
                return self._handle_http_protocol(client_socket)

        except Exception as e:
            logger.error(f"协议检测异常: {repr(e)}")
            client_socket.close()
            return None

    def _handle_socks5(self, client_socket):
#"'''处理SOCKS5协议连接，保持与原有返回格式一致'''
        try:
            # 认证协商阶段
            client_socket.recv(2)  # 已经通过peek确认版本
            nmethods = client_socket.recv(1)[0]
            client_socket.recv(nmethods)  # 读取方法列表
            client_socket.sendall(b"\x05\x00")  # 选择无认证

            # 请求解析阶段
            header = client_socket.recv(3)
            while header[0]!=0x05:
                logger.debug("right 1, %s",str(header))
                header=header[1:]+client_socket.recv(1)
            logger.debug("socks5 header: %s",header)
            if len(header) != 3 or header[0] != 0x05:
                raise ValueError("Invalid SOCKS5 header")

            _, cmd, _ = header

            if cmd not in {0x01, 0x05}:  # 只支持CONNECT和UDP（over TCP）命令
                client_socket.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                client_socket.close()
                raise ValueError(f"Not supported socks command, {cmd}")

            # 目标地址解析（复用原有DNS逻辑）
            server_name, server_port = utils.parse_socks5_address(client_socket)

            logger.info("%s:%d",server_name,server_port)

            # 建立连接（完全复用原有逻辑）
            try:
                if cmd==0x01:
                    remote_obj = remote.Remote(server_name, server_port, 6)
                elif cmd==0x05:
                    remote_obj = remote.Remote(server_name, server_port, 17)

                client_socket.sendall(
                    b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + b"\x00\x00"
                )
                return remote_obj
            except Exception as e:
                logger.info(f"连接失败: {repr(e)}")
                client_socket.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                client_socket.close()
                return server_name if utils.is_ip_address(server_name) else None

        except Exception as e:
            logger.info(f"SOCKS5处理错误: {repr(e)}")
            client_socket.close()
            return None

    def _handle_http_protocol(self, client_socket):
        "'''增强后的 HTTP 处理：
           - 支持 CONNECT（原有）
           - 支持 proxy-forward（返回 (remote_obj, initial_request_bytes)）
           - 支持 PAC / 原有重定向 / 错误处理
        '''
        data = client_socket.recv(16384)
        if not data:
            client_socket.close()
            return None

        # 原有CONNECT处理
        if data.startswith(b"CONNECT "):
            server_name, server_port = self.extract_servername_and_port(data)
            logger.info(f"CONNECT {server_name}:{server_port}")
            try:
                remote_obj = remote.Remote(server_name, server_port)
                client_socket.sendall(
                    b"HTTP/1.1 200 Connection established\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
                )
                return remote_obj
            except Exception as e:
                logger.info(f"连接失败: {repr(e)}")
                client_socket.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nProxy-agent : MyProxy/1.0\r\n\r\n"
                )
                client_socket.close()
                return server_name if utils.is_ip_address(server_name) else None

        # 原有PAC文件处理（如果访问 /proxy.pac 则直接响应）
        elif b"/proxy.pac" in data.splitlines()[0]:
            response = load_pac()
            client_socket.sendall(response.encode())
            client_socket.close()
            return None

        # 处理普通 HTTP 方法（GET/POST/...）
        elif data.startswith((b'GET ', b'PUT ', b'DELETE ', b'POST ', b'HEAD ', b'OPTIONS ')):
            # 解析请求行和 Host 头
            try:
                # 把首行解码，安全地处理
                lines = data.split(b"\r\n")
                request_line = lines[0].decode(errors="ignore")
                method, req_uri, http_ver = request_line.split(None, 2)
            except Exception as e:
                logger.info(f"无法解析请求行: {repr(e)}")
                client_socket.sendall(
                    b"HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
                )
                client_socket.close()
                return None

            # helper: parse headers to dict
            headers = {}
            for line in lines[1:]:
                if not line:
                    break
                try:
                    k, v = line.decode(errors="ignore").split(":", 1)
                    headers[k.strip().lower()] = v.strip()
                except:
                    continue

            # 判断请求类型：绝对URI (proxy request) 或 相对路径 + Host
            target_host = None
            target_port = None
            is_proxy_request = False

            if req_uri.startswith("http://") or req_uri.startswith("https://"):
                parsed = urlparse(req_uri)
                target_host = parsed.hostname
                target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
                is_proxy_request = True
            else:
                # 相对路径，需要从 Host 头得到目标
                host_header = headers.get("host")
                if host_header:
                    # Host 可能包含端口
                    if ":" in host_header:
                        try:
                            h, p = host_header.rsplit(":", 1)
                            target_host = h
                            target_port = int(p)
                        except:
                            target_host = host_header
                            target_port = 80
                    else:
                        target_host = host_header
                        # 默认端口依据请求行（若是 https 绝非此处）：
                        target_port = 80
                    # 如果 Host 指向代理自身（即 client 想访问代理网页），我们视为 origin-request，不当作要转发给上游
                    # 想法：只有当 Host != 本机代理域名时，才当作转发请求
                    # 这里检查是否 Host 等于我们服务器的外放域名（可能需要由用户调整）
                    # 简化：如果 Host 不等于我们监听的空字符串或 localhost，则视为要转发
                    # 如果 Host 看起来是代理自身（例如和 client_socket 的目标域名一致），则不转发
                    # 我们在下面再次校验：如果 Host 等于代理域名则认为是 origin 请求
                    is_proxy_request = True
                else:
                    # 没有 Host，无法作为代理请求
                    is_proxy_request = False

            # 如果不是代理请求（比如访问代理自身），使用原有逻辑（重定向或 400）
            # 判断 Host 是否为代理自身：如果 Host 与我们被访问的域名相同（例如 client 打开 http://cdn.zinho.../），视为 origin
            # 这里没有直接可用的“当前代理域名”信息，采用保守策略：若 host_header == socket.gethostname() / 或空，则当作 origin
            if not is_proxy_request:
                logger.info("HTTP 请求既非绝对 URI，也无 Host，返回 400")
                client_socket.sendall(
                    b"HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
                )
                client_socket.close()
                return None

            # 如果 host 看起来正是代理自身（例如目标 Host 等于代理域名），则认为是 origin 请求，保留原有行为（生成 302 重定向）
            # 这种情况会导致之前那种“self redirect”的日志。我们要避免误判：只有当请求行为相对路径且 Host 与本代理域名相同时才视为 origin。
            try:
                proxy_domain_candidates = [config.get("external_domain"), config.get("domain"), socket.gethostname()]
            except:
                proxy_domain_candidates = [socket.gethostname()]

            if req_uri.startswith("/") and headers.get("host") and headers.get("host") in proxy_domain_candidates:
                # 认为客户端是访问代理自身网页（而不是用它做代理），按原来逻辑处理（重定向）
                response = utils.generate_302(data, "github.com")
                client_socket.sendall(response.encode(encoding="UTF-8"))
                client_socket.close()
                return None

            # 到此，我们把该请求视为要转发的 HTTP 请求
            # 创建 remote 对象，但不要立刻 connect：让上游线程统一 connect
            try:
                # 默认使用 TCP (协议号 6)
                remote_obj = remote.Remote(target_host, target_port, 6)
                # 标记：这是一个 HTTP forward 请求，并将初始数据一并返回，my_upstream 会负责第一次发送并改写绝对 URI
                remote_obj._is_http_forward = True
                return (remote_obj, data)
            except Exception as e:
                logger.info(f"创建 upstream 连接对象失败: {repr(e)}")
                client_socket.sendall(
                    b"HTTP/1.1 502 Bad Gateway\r\nProxy-agent : MyProxy/1.0\r\n\r\n"
                )
                client_socket.close()
                return None

        # 原有错误处理
        else:
            logger.info(f"未知请求: {data[:10]}")
            client_socket.sendall(
                b"HTTP/1.1 400 Bad Request\r\nProxy-agent: MyProxy/1.0\r\n\r\n"
            )
            client_socket.close()
            return None

    def my_upstream(self, client_sock):
        first_flag = True

        backend_sock = self.handle_client_request(client_sock)

        if backend_sock == None:
            client_sock.close()
            return

        # 支持 _handle_http_protocol 返回 (remote_obj, initial_data)
        initial_data = None
        if isinstance(backend_sock, tuple):
            backend_sock, initial_data = backend_sock

        global ThreadtoWork

        while ThreadtoWork:
            try:
                if first_flag is True:
                    first_flag = False

                    time.sleep(
                        0.1
                    )  # speed control + waiting for packet to fully recieve

                    # 如果 handle_client_request 已经给了初始请求数据，就用它；否则从 socket 读取
                    if initial_data is not None:
                        data = initial_data
                        # 清掉引用，避免重复使用
                        initial_data = None
                    else:
                        data = client_sock.recv(16384)

                    try:
                        extractedsni = utils.extract_sni(data)
                        if backend_sock.domain=="127.0.0.114" or backend_sock.domain=="::114" or (config["BySNIfirst"] and str(extractedsni,encoding="ASCII") != backend_sock.domain):
                            port, protocol=backend_sock.port,backend_sock.protocol
                            logger.info(f"replace backendsock: {extractedsni} {port} {protocol}")
                            new_backend_sock=remote.Remote(str(extractedsni,encoding="ASCII"),port,protocol)
                            backend_sock=new_backend_sock
                    except:
                        pass

                    backend_sock.client_sock = client_sock

                    try:
                        backend_sock.connect()
                    except:
                        raise Exception("backend connect fail")

                    # 如果是 HTTP forward 请求，并且 data 包含 HTTP 请求（例如 GET http://...），需把请求行改写为 origin 所需的相对路径
                    if getattr(backend_sock, "_is_http_forward", False) and data:
                        try:
                            # 尝试解析并重写请求行
                            # data 可能包含 body；先只处理 headers + 请求行
                            header_end = data.find(b"\r\n\r\n")
                            headers_block = data if header_end == -1 else data[:header_end+4]
                            rest = b"" if header_end == -1 else data[header_end+4:]
                            lines = headers_block.split(b"\r\n")
                            request_line = lines[0].decode(errors="ignore")
                            method, req_uri, http_ver = request_line.split(None, 2)

                            # 若 req_uri 是绝对 URL，则改为 path
                            if req_uri.startswith("http://") or req_uri.startswith("https://"):
                                parsed = urlparse(req_uri)
                                path = parsed.path or "/"
                                if parsed.query:
                                    path += "?" + parsed.query
                                new_request_line = f'{method} {path} {http_ver}'.encode()
                            else:
                                # 相对路径直接保持
                                new_request_line = lines[0]

                            # 过滤掉 Proxy-Connection 等头
                            new_headers = []
                            saw_connection = False
                            for h in lines[1:]:
                                if not h:
                                    break
                                try:
                                    hs = h.decode(errors="ignore")
                                except:
                                    continue
                                if hs.lower().startswith("proxy-connection:"):
                                    continue
                                if hs.lower().startswith("proxy-"):
                                    # 其它 proxy-* 也移除
                                    continue
                                if hs.lower().startswith("connection:"):
                                    saw_connection = True
                                    # 强制设置为 close（可按需改为 keep-alive）
                                    new_headers.append("Connection: close".encode())
                                else:
                                    new_headers.append(h)

                            if not saw_connection:
                                new_headers.append(b"Connection: close")

                            # 重新构造要发送给 origin 的请求数据
                            new_request = b"\r\n".join([new_request_line] + new_headers) + b"\r\n\r\n" + rest
                            data = new_request
                        except Exception as e:
                            logger.debug(f"rewrite http request failed: {repr(e)}")
                            # 如果重写失败，仍尝试直接发送原 data

                    # 如果上游策略要求 safety_check 并且这是 http 请求 -> 可能旧逻辑是重定向到 https
                    if backend_sock.policy.get("safety_check") is True and data.startswith((b'GET ', b'PUT ', b'DELETE ', b'POST ', b'HEAD ', b'OPTIONS ')):
                        logger.warning("HTTP protocol detected, will redirect to https")
                        # 如果是http协议，重定向到https，要从data中提取url
                        response = utils.generate_302(data,extractedsni if 'extractedsni' in locals() else None)
                        client_sock.sendall(response.encode())
                        client_sock.close()
                        backend_sock.close()
                        return

                    if data:
                        thread_down = threading.Thread(
                            target=self.my_downstream,
                            args=(backend_sock, client_sock),
                        )
                        thread_down.daemon = True
                        thread_down.start()

                    try:
                        backend_sock.sni = extractedsni
                        if str(backend_sock.sni)!=str(backend_sock.domain):
                            backend_sock.policy = {**backend_sock.policy, **match_domain(str(backend_sock.sni))}
                    except:
                        backend_sock.send(data)
                        continue

                    if backend_sock.policy.get("safety_check") is True:
                        try:
                            can_pass=utils.detect_tls_version_by_keyshare(data)
                        except:
                            pass
                        if can_pass != 1:
                            logger.warning("Not a TLS 1.3 connection and will close")
                            try:
                                client_sock.send(utils.generate_tls_alert(data))
                            except:
                                pass
                            backend_sock.close()
                            client_sock.close()
                            raise ValueError("Not a TLS 1.3 connection")

                    if data:
                        mode = backend_sock.policy.get('mode')
                        if mode == "TLSfrag":
                            fragment.send_fraggmed_tls_data(backend_sock, data)
                        elif mode == "FAKEdesync":
                            fake_desync.send_data_with_fake(backend_sock,data)
                        elif mode == "DIRECT":
                            backend_sock.send(data)
                        elif mode == "GFWlike":
                            backend_sock.close()
                            client_sock.close()
                            return False
                    else:
                        raise Exception("cli syn close")

                else:
                    data = client_sock.recv(16384)
                    if data:
                        backend_sock.send(data)
                    else:
                        raise Exception("cli pipe close")

            except Exception as e:
                # import traceback
                # traceback.print_exc()
                logger.info(f"upstream : {repr(e)} from {getattr(backend_sock,'domain',str(backend_sock))}")
                time.sleep(2)  # wait two second for another thread to flush
                client_sock.close()
                try:
                    backend_sock.close()
                except:
                    pass
                return False

        client_sock.close()
        try:
            backend_sock.close()
        except:
            pass

    def my_downstream(self, backend_sock: remote.Remote, client_sock: socket.socket):

        first_flag = True

        global ThreadtoWork

        while ThreadtoWork:
            try:
                if first_flag is True:
                    first_flag = False
                    data = backend_sock.recv(16384)           
                    if data:
                        client_sock.sendall(data)
                    else:
                        raise Exception("backend pipe close at first")
                else:
                    data = backend_sock.recv(16384)
                    if data:
                        client_sock.sendall(data)
                    else:
                        raise Exception("backend pipe close")

            except Exception as e:
                # import traceback
                # traceback.print_exc()
                logger.info(f"downstream : {repr(e)} from {backend_sock.domain}")
                time.sleep(2)  # wait two second for another thread to flush
                backend_sock.close()
                client_sock.close()
                return False

        client_sock.close()
        backend_sock.close()

    def extract_servername_and_port(self, data):
        host_and_port = str(data).split()[1]
        try:
            host, port = host_and_port.split(":")
        except:
            # ipv6
            if host_and_port.find("[") != -1:
                host, port = host_and_port.split("]:")
                host = host[1:]
            else:
                idx = 0
                for _ in range(6):
                    idx = host_and_port.find(":", idx + 1)
                host = host_and_port[:idx]
                port = host_and_port[idx + 1 :]
        return (host, int(port))


# http114=b""

serverHandle = None

def start_server(block=True):
    generate_pac()

    global serverHandle
    logger.info(f"Now listening at: 0.0.0.0:{config['port']}")
    serverHandle = ThreadedServer("0.0.0.0", config['port']).listen(block)

def stop_server(wait_for_stop=True):
    global ThreadtoWork, proxy_thread
    ThreadtoWork = False
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", config["port"]))
    sock.close()
    if wait_for_stop:
        while proxy_thread.is_alive():
            pass
        logger.info("Server stopped")

dataPath = Path.cwd()
ThreadtoWork = True

if __name__ == "__main__":
    start_server()
