#!/bin/bash

# 重启 Uptime Kuma 服务以清理内存

echo "正在查找 Uptime Kuma 进程..."

# 查找主进程
MAIN_PID=$(ps aux | grep "node server/server.js" | grep -v grep | awk '{print $2}' | head -1)

if [ -z "$MAIN_PID" ]; then
    echo "未找到 Uptime Kuma 主进程"
    echo "可能通过 npm run dev 启动，查找父进程..."
    
    # 查找 concurrently 进程（npm run dev 的父进程）
    PARENT_PID=$(ps aux | grep "concurrently" | grep -v grep | awk '{print $2}' | head -1)
    
    if [ -z "$PARENT_PID" ]; then
        echo "未找到 Uptime Kuma 进程"
        echo ""
        echo "请手动重启："
        echo "  1. 按 Ctrl+C 停止当前服务"
        echo "  2. 然后运行: npm run dev"
        exit 1
    else
        echo "找到父进程 PID: $PARENT_PID"
        echo "正在停止所有相关进程..."
        kill -TERM $PARENT_PID 2>/dev/null
        sleep 2
        
        # 确保所有子进程也被停止
        pkill -f "node server/server.js" 2>/dev/null
        pkill -f "vite" 2>/dev/null
        
        echo "✓ 已停止 Uptime Kuma"
    fi
else
    echo "找到主进程 PID: $MAIN_PID"
    echo "正在停止进程..."
    kill -TERM $MAIN_PID 2>/dev/null
    sleep 2
    
    # 确保进程已停止
    if ps -p $MAIN_PID > /dev/null 2>&1; then
        echo "强制停止进程..."
        kill -9 $MAIN_PID 2>/dev/null
    fi
    
    echo "✓ 已停止 Uptime Kuma"
fi

echo ""
echo "等待 3 秒后重启..."
sleep 3

# 检查是否在正确的目录
if [ ! -f "server/server.js" ]; then
    echo "错误: 请在 Uptime Kuma 项目根目录运行此脚本"
    exit 1
fi

echo "正在启动 Uptime Kuma..."
cd "$(dirname "$0")/.."

# 检查是否使用 PM2
if command -v pm2 &> /dev/null; then
    if pm2 list | grep -q "uptime-kuma"; then
        echo "使用 PM2 重启..."
        pm2 restart uptime-kuma
        pm2 logs uptime-kuma --lines 20
    else
        echo "PM2 未配置，使用 npm run dev 启动..."
        npm run dev &
    fi
else
    echo "使用 npm run dev 启动..."
    npm run dev &
fi

echo ""
echo "✓ Uptime Kuma 已重启"
echo "内存已清理，所有监控器状态已重置"

