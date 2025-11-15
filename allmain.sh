#!/bin/bash
# ============================================================
# Scamnet 全协议异步扫描器 v5.1
# 修正版 by ChatGPT（2025）
# ============================================================

set -euo pipefail
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; CYAN='\033[36m'; NC='\033[0m'

BASE_DIR="$(pwd)"
LOG_DIR="$BASE_DIR/logs"
mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"
RUN_SCRIPT="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).sh"

echo -e "${CYAN}============================================================"
echo -e " Scamnet v5.1 全协议异步扫描器"
echo -e "============================================================${NC}"
echo "日志目录: $LOG_DIR"
echo

# ==================== 依赖检查 ====================
if [ ! -f ".deps_installed" ]; then
    echo -e "${YELLOW}[*] 安装依赖中...${NC}"
    if ! command -v python3 >/dev/null 2>&1; then
        echo -e "${RED}[!] 未检测到 Python3，请先安装。${NC}"
        exit 1
    fi
    if ! command -v pip3 >/dev/null 2>&1; then
        if command -v apt >/dev/null 2>&1; then sudo apt update -y && sudo apt install -y python3-pip
        elif command -v yum >/dev/null 2>&1; then sudo yum install -y python3-pip
        elif command -v apk >/dev/null 2>&1; then sudo apk add py3-pip
        else
            echo -e "${RED}[!] 无法自动安装 pip3，请手动安装。${NC}"
            exit 1
        fi
    fi
    pip3 install --user -i https://pypi.tuna.tsinghua.edu.cn/simple aiohttp tqdm asyncio pyyaml >/dev/null 2>&1
    touch .deps_installed
    echo -e "${GREEN}[+] 依赖安装完成${NC}"
else
    echo -e "${GREEN}[+] 依赖已存在${NC}"
fi
echo

# ==================== 用户输入 ====================
DEFAULT_START="157.254.32.0"
DEFAULT_END="157.254.52.255"

read -p "请输入起始 IP（默认: $DEFAULT_START）: " START_IP
START_IP=${START_IP:-$DEFAULT_START}

read -p "请输入结束 IP（默认: $DEFAULT_END）: " END_IP
END_IP=${END_IP:-$DEFAULT_END}

if ! [[ $START_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ && $END_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo -e "${RED}[!] IP 格式错误！${NC}"
    exit 1
fi

echo -e "${GREEN}[*] 扫描范围: $START_IP - $END_IP${NC}"

read -p "请输入端口（默认: 1080）: " PORT_INPUT
PORT_INPUT=${PORT_INPUT:-1080}

if [[ $PORT_INPUT =~ ^[0-9]+-[0-9]+$ ]]; then
    PORTS_CONFIG="range: \"$PORT_INPUT\""
elif [[ $PORT_INPUT =~ ^[0-9]+( [0-9]+)*$ ]]; then
    PORT_LIST=$(echo "$PORT_INPUT" | tr ' ' ',' | sed 's/,/","/g')
    PORTS_CONFIG="ports: [\"$PORT_LIST\"]"
else
    PORTS_CONFIG="ports: [$PORT_INPUT]"
fi
echo -e "${GREEN}[*] 端口配置: $PORT_INPUT${NC}"
echo

# ==================== 生成 Python 扫描脚本 ====================
cat > "$LOG_DIR/scanner_full.py" << 'PYEOF'
#!/usr/bin/env python3
import asyncio, aiohttp, ipaddress, yaml, base64, time, warnings
from tqdm.asyncio import tqdm_asyncio
warnings.filterwarnings("ignore", category=DeprecationWarning)

# ------------------ 配置加载 ------------------
with open("config.yaml", "r", encoding="utf-8") as f:
    cfg = yaml.safe_load(f)

IP_RANGE = cfg["input_range"]
PORTS = cfg.get("ports") or cfg.get("range")
TIMEOUT = cfg.get("timeout", 5.0)
MAX_CONCURRENT = cfg.get("max_concurrent", 5000)
PROTOCOL_ORDER = cfg.get("protocol_order", ["http", "https", "socks4", "socks5"])

# ------------------ 工具函数 ------------------
def parse_ip_range(r):
    if "/" in r:
        return [str(ip) for ip in ipaddress.ip_network(r, strict=False).hosts()]
    s, e = r.split("-")
    start, end = int(ipaddress.IPv4Address(s)), int(ipaddress.IPv4Address(e))
    return [str(ipaddress.IPv4Address(i)) for i in range(start, end + 1)]

def parse_ports(p):
    if isinstance(p, str) and "-" in p:
        a, b = map(int, p.split("-")); return range(a, b + 1)
    if isinstance(p, list):
        return [int(x) for x in p]
    return [int(p)]

ips = parse_ip_range(IP_RANGE)
ports = parse_ports(PORTS)
print(f"[*] IPs: {len(ips):,} Ports: {len(ports):,}  Total: {len(ips)*len(ports):,}")

# ------------------ 测试函数 ------------------
async def test_http(ip, port, session):
    proxy = f"http://{ip}:{port}"
    try:
        start = time.time()
        async with session.get("http://httpbin.org/ip", proxy=proxy, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as r:
            if r.status == 200:
                latency = round((time.time() - start) * 1000)
                return True, latency
    except:
        return False, 0
    return False, 0

# ------------------ 主函数 ------------------
async def worker(ip, port, session, pbar):
    ok, latency = await test_http(ip, port, session)
    if ok:
        async with asyncio.Lock():
            with open("logs/valid.txt", "a") as f:
                f.write(f"{ip}:{port} | HTTP | {latency}ms\n")
    pbar.update(1)

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = []
        pbar = tqdm_asyncio(total=len(ips)*len(ports), desc="Scanning", unit="target")
        for ip in ips:
            for port in ports:
                if len(tasks) >= MAX_CONCURRENT:
                    await asyncio.gather(*tasks)
                    tasks = []
                tasks.append(worker(ip, port, session, pbar))
        if tasks:
            await asyncio.gather(*tasks)
        pbar.close()

if __name__ == "__main__":
    asyncio.run(main())
PYEOF

chmod +x "$LOG_DIR/scanner_full.py"

# ==================== 生成配置文件 ====================
cat > "$LOG_DIR/config.yaml" <<EOF
input_range: "${START_IP}-${END_IP}"
$PORTS_CONFIG
timeout: 5.0
max_concurrent: 5000
protocol_order: ["http", "https", "socks4", "socks5"]
EOF

# ==================== 后台运行脚本 ====================
cat > "$RUN_SCRIPT" <<EOF
#!/bin/bash
cd "$LOG_DIR"
python3 scanner_full.py >> "$LATEST_LOG" 2>&1
EOF
chmod +x "$RUN_SCRIPT"

# ==================== 启动后台进程 ====================
echo -e "${YELLOW}[*] 启动异步扫描器...${NC}"
nohup bash "$RUN_SCRIPT" > "$LATEST_LOG" 2>&1 &
PID=$!

sleep 1
if ps -p $PID > /dev/null; then
    echo -e "${GREEN}[+] 已后台运行！PID: $PID${NC}"
    echo -e "日志查看：tail -f $LATEST_LOG"
else
    echo -e "${RED}[!] 启动失败，请检查日志：$LATEST_LOG${NC}"
fi
