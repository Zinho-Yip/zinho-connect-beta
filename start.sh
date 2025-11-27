#!/bin/sh

# set -e: 如果任何命令失败，立即退出脚本
# set -x: 在执行前打印出每一条命令
set -ex

# -u: 强制Python使用无缓存的标准输出，确保日志能实时显示
echo "Starting tlsp service on port 2500 (in background)..."
python -u run.py &

# 短暂等待后台服务启动
sleep 2

echo "Starting HTTP-to-SOCKS5 bridge on port 5000 (in foreground)..."
python -u http_to_socks_bridge.py