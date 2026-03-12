#!/bin/bash
# 生成自签 SSL 证书（有效期 365 天）
# 用法: bash gen-cert.sh

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

openssl req -x509 -nodes -days 365 \
    -newkey rsa:2048 \
    -keyout "$SCRIPT_DIR/server.key" \
    -out "$SCRIPT_DIR/server.crt" \
    -subj "/C=CN/ST=Default/L=Default/O=VulnKB/CN=vulnkb"

echo "证书已生成:"
echo "  $SCRIPT_DIR/server.crt"
echo "  $SCRIPT_DIR/server.key"
