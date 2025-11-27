#!/bin/sh

# 启动主 tlsp 应用 (run.py) 在后台运行
echo "Starting tlsp service on port 2500..."
python run.py &

# 启动 HTTP-to-SOCKS5 桥接服务在前台运行
echo "Starting HTTP-to-SOCKS5 bridge on port 5000..."
python http_to_socks_bridge.py
