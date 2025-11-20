#!/bin/bash
# main.sh - Scamnet OTC 全协议异步扫描器 (修复版 v5.1)
set -e
RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; NC='\033[0m'
LOG_DIR="logs"; mkdir -p "$LOG_DIR"
LATEST_LOG="$LOG_DIR/latest.log"

echo -e "${BLUE}"
echo "███████╗ ██████╗ █████╗ ███╗   ███╗███╗   ██╗███████╗███████╗"
echo "██╔════╝██╔════╝██╔══██╗████╗ ████║████╗  ██║██╔════╝╚══███╔╝"
echo "███████╗██║     ███████║██╔████╔██║██╔██╗ ██║█████╗    ███╔╝ "
echo "╚════██║██║     ██╔══██║██║╚██╔╝██║██║╚██╗██║██╔══╝   ███╔╝  "
echo "███████║╚██████╗██║  ██║██║ ╚═╝ ██║██║ ╚████║███████╗███████╗"
echo "╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
echo -e "${NC}"
echo -e "${GREEN}[OTC] Scamnet v5.1 (SOCKS支持修复 + 依赖自动补全)${NC}"

# ==================== 依赖安装 (自动修复) ====================
if [ ! -f ".deps_installed_v5" ]; then
    echo -e "${YELLOW}[*] 检测并安装 Python 依赖 (aiohttp, aiohttp-socks, PyYAML)...${NC}"
    
    # 检测包管理器
    if ! command -v pip3 &>/dev/null; then
        if command -v apt >/dev/null; then sudo apt update -qq && sudo apt install -y python3-pip python3-dev; fi
        if command -v yum >/dev/null; then sudo yum install -y python3-pip python3-devel; fi
        if command -v apk >/dev/null; then apk add py3-pip python3-dev; fi
    fi
    
    # 安装核心库
    pip3 install --user -i https://pypi.tuna.tsinghua.edu.cn/simple aiohttp aiohttp-socks tqdm PyYAML asyncio
    touch .deps_installed_v5
    echo -e "${GREEN}[+] 依赖环境部署完成${NC}"
else
    echo -e "${GREEN}[+] 依赖已就绪${NC}"
fi

# ==================== 调整系统限制 ====================
ulimit -n 65535 2>/dev/null || true

# ==================== 输入配置 ====================
DEFAULT_START="157.254.32.0"
DEFAULT_END="157.254.52.255"
echo -e "${YELLOW}请输入起始 IP (默认: $DEFAULT_START):${NC}"
read -r START_IP
START_IP=${START_IP:-$DEFAULT_START}

echo -e "${YELLOW}请输入结束 IP (默认: $DEFAULT_END):${NC}"
read -r END_IP
END_IP=${END_IP:-$DEFAULT_END}

echo -e "${YELLOW}请输入端口 (默认: 1080):${NC}"
echo " 格式: 1080 或 1080 8080 或 1-65535"
read -r PORT_INPUT
PORT_INPUT=${PORT_INPUT:-1080}

# 端口配置解析
PORTS_CONFIG=""
if [[ $PORT_INPUT =~ ^[0-9]+-[0-9]+$ ]]; then
    PORTS_CONFIG="range: \"$PORT_INPUT\""
elif [[ $PORT_INPUT =~ ^[0-9]+( [0-9]+)*$ ]]; then
    PORT_LIST=$(echo "$PORT_INPUT" | tr ' ' ',' | sed 's/,/","/g')
    PORTS_CONFIG="ports: [\"$PORT_LIST\"]"
else
    PORTS_CONFIG="ports: [$PORT_INPUT]"
fi

echo -e "${GREEN}[*] 目标: $START_IP - $END_IP | 端口: $PORT_INPUT${NC}"

# ==================== 生成运行脚本 ====================
RUN_SCRIPT="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).sh"
cat > "$RUN_SCRIPT" << EOF
#!/bin/bash
set -e
cd "\$(dirname "\$0")"

# 1. 生成配置文件
cat > config.yaml << CONFIG
input_range: "${START_IP}-${END_IP}"
$PORTS_CONFIG
timeout: 8.0
# 建议并发设置：机器性能好可设为 3000-5000，过高会导致丢包或报错
max_concurrent: 3000
protocol_order: ["socks5", "socks4", "http", "https"]
CONFIG

# 2. 生成 Python 扫描器 (修复版)
cat > scanner_full.py << 'PY'
#!/usr/bin/env python3
import asyncio
import aiohttp
import ipaddress
import sys
import yaml
import socket
from aiohttp_socks import ProxyConnector, ProxyType
from tqdm.asyncio import tqdm_asyncio
import warnings

# 屏蔽 SSL 警告和 DeprecationWarning
warnings.filterwarnings("ignore")

# ==================== 加载配置 ====================
try:
    with open('config.yaml') as f:
        cfg = yaml.safe_load(f)
except Exception as e:
    print(f"配置文件加载失败: {e}")
    sys.exit(1)

INPUT_RANGE = cfg['input_range']
RAW_PORTS = cfg.get('ports', cfg.get('range'))
TIMEOUT = cfg.get('timeout', 8.0)
MAX_CONCURRENT = cfg.get('max_concurrent', 3000)
PROTOCOL_ORDER = cfg.get('protocol_order', ["socks5", "socks4", "http", "https"])

# ==================== 解析函数 ====================
def parse_ip_range(s):
    try:
        if '/' in s:
            return [str(ip) for ip in ipaddress.ip_network(s, strict=False).hosts()]
        parts = s.split('-')
        if len(parts) == 2:
            start, end = parts
            s_int = int(ipaddress.IPv4Address(start))
            e_int = int(ipaddress.IPv4Address(end))
            if e_int < s_int: return []
            # 限制最大 IP 数量防止内存爆炸，分块处理建议在外部做
            if e_int - s_int > 65535:
                print("警告: IP 范围过大，仅扫描前 65535 个")
                e_int = s_int + 65535
            return [str(ipaddress.IPv4Address(i)) for i in range(s_int, e_int + 1)]
        return [s]
    except Exception as e:
        print(f"IP 解析错误: {e}")
        return []

def parse_ports(p):
    try:
        if isinstance(p, str) and '-' in p:
            a, b = map(int, p.split('-'))
            return list(range(a, b + 1))
        if isinstance(p, list):
            return [int(x) for x in p]
        return [int(p)]
    except:
        return [1080]

ips = parse_ip_range(INPUT_RANGE)
ports = parse_ports(RAW_PORTS)

if not ips:
    print("没有有效的 IP 目标")
    sys.exit(0)

# ==================== 弱密码字典 (精简版) ====================
# 完整爆破字典会导致扫描极慢，此处保留高频 Top 20
WEAK_PASSWORDS = [
    ("admin", "admin"), ("root", "root"), ("user", "user"), 
    ("guest", "guest"), ("test", "test"), ("123456", "123456"),
    ("1234", "1234"), ("admin", "123456"), ("proxy", "proxy"),
    ("socks", "socks"), ("123", "123"), ("password", "password")
]

# ==================== 全局变量 ====================
valid_count = 0
valid_lock = asyncio.Lock()
detail_lock = asyncio.Lock()
sem = asyncio.Semaphore(MAX_CONCURRENT)

# ==================== 核心扫描逻辑 ====================
async def check_proxy(ip, port, protocol, auth=None):
    """
    核心检测函数：根据协议构建不同的 Connector
    """
    target_url = "http://www.google.com/generate_204" # 或 http://ifconfig.me
    # 国内环境可能需要换成 http://connect.rom.miui.com/generate_204
    
    connector = None
    try:
        if protocol == "http" or protocol == "https":
            # HTTP 代理直接用 aiohttp 原生支持
            # 构造 proxy 字符串
            if auth:
                proxy_url = f"http://{auth[0]}:{auth[1]}@{ip}:{port}"
            else:
                proxy_url = f"http://{ip}:{port}"
            
            async with aiohttp.ClientSession() as session:
                start_time = asyncio.get_event_loop().time()
                async with session.get(target_url, proxy=proxy_url, timeout=TIMEOUT, ssl=False) as resp:
                    if resp.status < 400:
                        latency = int((asyncio.get_event_loop().time() - start_time) * 1000)
                        return True, latency, "Unknown" # 获取 IP 需要请求 ifconfig.me，这里为了速度简化
        
        elif protocol.startswith("socks"):
            # SOCKS 必须用 ProxyConnector
            socks_ver = ProxyType.SOCKS5 if protocol == "socks5" else ProxyType.SOCKS4
            username, password = auth if auth else (None, None)
            
            connector = ProxyConnector(
                proxy_type=socks_ver,
                host=ip,
                port=port,
                username=username,
                password=password,
                rdns=True
            )
            
            async with aiohttp.ClientSession(connector=connector) as session:
                start_time = asyncio.get_event_loop().time()
                async with session.get(target_url, timeout=TIMEOUT, ssl=False) as resp:
                    if resp.status < 400:
                        latency = int((asyncio.get_event_loop().time() - start_time) * 1000)
                        return True, latency, "Unknown"
                        
    except:
        return False, 0, None
    finally:
        # 确保 connector 关闭 (虽然 context manager 会处理 session，但 connector 显式关闭更安全)
        if connector:
            try:
                await connector.close()
            except: pass
            
    return False, 0, None

# ==================== 任务调度 ====================
async def scan_task(ip, port):
    async with sem:
        # 1. 无密码扫描
        for scheme in PROTOCOL_ORDER:
            is_valid, lat, exp = await check_proxy(ip, port, scheme, auth=None)
            if is_valid:
                await save_result(ip, port, scheme, lat, "None", "XX")
                return

        # 2. 弱密码爆破 (仅当无密码失败时尝试，且仅针对支持认证的协议)
        # 注意：爆破会显著降低速度，建议仅对特定端口(如1080)开启
        # 如果需要爆破，取消下面注释
        '''
        for scheme in ["socks5", "http"]:
            for user, pwd in WEAK_PASSWORDS:
                is_valid, lat, exp = await check_proxy(ip, port, scheme, auth=(user, pwd))
                if is_valid:
                    await save_result(ip, port, scheme, lat, f"{user}:{pwd}", "XX")
                    return
        '''

async def save_result(ip, port, scheme, latency, auth, country):
    global valid_count
    valid_count += 1
    
    auth_str = f"{auth}@" if auth != "None" else ""
    proxy_str = f"{scheme}://{auth_str}{ip}:{port}"
    
    print(f"\r[+] 发现: {proxy_str} (延迟: {latency}ms)")
    
    async with valid_lock:
        with open("proxy_valid.txt", "a") as f:
            f.write(f"{proxy_str}#{latency}ms\n")

async def main():
    print(f"[*] 目标: {len(ips)} IP | 端口: {len(ports)}")
    print(f"[*] 协议: {PROTOCOL_ORDER}")
    print(f"[*] 并发: {MAX_CONCURRENT} | 超时: {TIMEOUT}s")
    print("------------------------------------------------")

    # 初始化文件
    with open("proxy_valid.txt", "w") as f: f.write("")

    tasks = []
    for ip in ips:
        for port in ports:
            tasks.append(scan_task(ip, port))

    await tqdm_asyncio.gather(*tasks, desc="扫描进度", unit="目标", ncols=80)

    print(f"\n[+] 扫描完成! 共发现 {valid_count} 个有效代理")
    print(f"[+] 结果已保存至: proxy_valid.txt")

if __name__ == '__main__':
    try:
        # 针对 Windows 系统的策略调整，Linux 一般不需要
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
    except Exception as e:
        print(f"\n[!] 发生错误: {e}")
PY

chmod +x scanner_full.py

echo "# 扫描开始: \$(date)" > result.log
python3 scanner_full.py 2>&1 | tee -a result.log
EOF

chmod +x "$RUN_SCRIPT"

# ==================== 启动 ====================
echo -e "${GREEN}[*] 后台任务已配置: $RUN_SCRIPT${NC}"
echo -e "${YELLOW}[*] 正在启动... (请使用 tail -f $LOG_DIR/latest.log 查看日志)${NC}"

nohup "$RUN_SCRIPT" > "$LATEST_LOG" 2>&1 &
PID=$!
echo -e "${GREEN}[SUCCESS] 扫描器运行中! PID: $PID${NC}"
echo -e "停止命令: kill $PID"
