#!/usr/bin/env python3
"""代理节点聚合爬虫 - 抓取、去重、测活、地区分类"""

import asyncio
import base64
import ipaddress
import json
import os
import socket
import ssl
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, quote
from urllib.request import urlopen, Request

import yaml

try:
    import maxminddb
except ImportError:
    maxminddb = None

PROTOCOLS = (
    'vmess://', 'vless://', 'trojan://', 'ss://',
    'ssr://', 'hy2://', 'hysteria2://', 'hysteria://',
    'socks5://', 'socks://',
)

GEOIP_DB = 'GeoLite2-Country.mmdb'
TCP_CONCURRENCY = 200
TCP_TIMEOUT = 3
FETCH_TIMEOUT = 15
FETCH_WORKERS = 8
MAX_CDN_NODES = 30  # 每个 CDN 提供商最多保留节点数


# ===== 数据源抓取 =====

def load_sources(path='sources.yaml'):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def fetch_url(url, timeout=FETCH_TIMEOUT):
    req = Request(url, headers={
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f'  [!] 请求失败: {e}')
        return None


def resolve_url(source):
    if 'url' in source:
        return source['url']
    if 'url_template' in source:
        now = datetime.now(timezone(timedelta(hours=8)))
        fmt = source.get('date_format', '%Y%m%d')
        return source['url_template'].replace('{date}', now.strftime(fmt))
    return None


def fetch_all_sources(config):
    """多线程并发抓取所有源"""
    sources = config.get('sources', [])
    all_nodes = []
    source_stats = []

    def _fetch_one(src):
        name = src['name']
        url = resolve_url(src)
        if not url:
            return name, [], 'invalid'
        try:
            content = fetch_url(url)
            if not content:
                return name, [], 'failed'
            nodes = parse_nodes(content)
            return name, nodes, 'ok'
        except Exception as e:
            return name, [], 'failed'

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        futures = {pool.submit(_fetch_one, src): src for src in sources}
        for future in as_completed(futures):
            name, nodes, status = future.result()
            count = len(nodes)
            icon = '✓' if status == 'ok' else '✗'
            print(f'  [{icon}] {name}: {count} 个节点')
            all_nodes.extend(nodes)
            source_stats.append({'name': name, 'count': count, 'status': status})

    return all_nodes, source_stats


# ===== 节点解析 =====

def _pad_b64(s):
    return s + '=' * (-len(s) % 4)


def decode_base64(text):
    try:
        return base64.b64decode(_pad_b64(text.strip())).decode('utf-8', errors='ignore')
    except Exception:
        return None


def is_node(line):
    return any(line.startswith(p) for p in PROTOCOLS)


def parse_nodes(content):
    nodes = []
    for line in content.splitlines():
        line = line.strip()
        if is_node(line):
            nodes.append(line)
    if nodes:
        return nodes
    # 尝试 base64 解码
    decoded = decode_base64(content)
    if decoded:
        for line in decoded.splitlines():
            line = line.strip()
            if is_node(line):
                nodes.append(line)
    if nodes:
        return nodes
    # 尝试 Clash YAML 解析
    return _parse_clash_yaml(content)


def _parse_clash_yaml(content):
    """从 Clash YAML 配置中提取代理并转为 URI"""
    try:
        data = yaml.safe_load(content)
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    proxies = data.get('proxies', [])
    if not proxies:
        return []

    nodes = []
    for p in proxies:
        if not isinstance(p, dict):
            continue
        uri = _clash_proxy_to_uri(p)
        if uri:
            nodes.append(uri)
    return nodes


def _clash_proxy_to_uri(p):
    """将单个 Clash 代理字典转为 URI 字符串"""
    ptype = p.get('type', '').lower()
    server = p.get('server', '')
    port = p.get('port', 0)
    name = quote(str(p.get('name', '')), safe='')
    if not server or not port:
        return None

    if ptype == 'vmess':
        info = {
            'v': '2', 'ps': p.get('name', ''),
            'add': server, 'port': str(port),
            'id': p.get('uuid', ''), 'aid': str(p.get('alterId', 0)),
            'scy': p.get('cipher', 'auto'), 'net': p.get('network', 'tcp'),
            'type': 'none', 'tls': 'tls' if p.get('tls') else '',
        }
        ws = p.get('ws-opts', {})
        if ws:
            info['path'] = ws.get('path', '/')
            info['host'] = ws.get('headers', {}).get('Host', '')
        if p.get('servername'):
            info['sni'] = p['servername']
        return 'vmess://' + base64.b64encode(
            json.dumps(info, ensure_ascii=False).encode()).decode()

    if ptype == 'vless':
        params = _build_clash_params(p)
        flow = p.get('flow', '')
        if flow:
            params['flow'] = flow
        return f"vless://{p.get('uuid', '')}@{server}:{port}?{_urlencode(params)}#{name}"

    if ptype == 'trojan':
        params = _build_clash_params(p)
        return f"trojan://{p.get('password', '')}@{server}:{port}?{_urlencode(params)}#{name}"

    if ptype == 'ss':
        method = p.get('cipher', 'aes-256-gcm')
        pwd = p.get('password', '')
        userinfo = base64.b64encode(f'{method}:{pwd}'.encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{name}"

    if ptype in ('ssr', 'hysteria2', 'hy2'):
        # 简单支持
        if ptype == 'ssr':
            return None  # SSR 格式复杂，跳过
        pwd = p.get('password', p.get('auth', ''))
        params = {}
        if p.get('sni'):
            params['sni'] = p['sni']
        if p.get('insecure') or p.get('skip-cert-verify'):
            params['insecure'] = '1'
        qs = _urlencode(params)
        return f"hy2://{pwd}@{server}:{port}?{qs}#{name}"

    return None


def _build_clash_params(p):
    """从 Clash 代理字典构建 URI 查询参数"""
    params = {}
    if p.get('tls'):
        params['security'] = 'tls'
    if p.get('servername'):
        params['sni'] = p['servername']
    if p.get('skip-cert-verify'):
        params['allowInsecure'] = '1'
    net = p.get('network', '')
    if net:
        params['type'] = net
    ws = p.get('ws-opts', {})
    if ws:
        params['host'] = ws.get('headers', {}).get('Host', '')
        params['path'] = ws.get('path', '/')
    grpc = p.get('grpc-opts', {})
    if grpc:
        params['serviceName'] = grpc.get('grpc-service-name', '')
    fp = p.get('client-fingerprint', '')
    if fp:
        params['fp'] = fp
    ro = p.get('reality-opts', {})
    if ro:
        params['security'] = 'reality'
        params['pbk'] = ro.get('public-key', '')
        params['sid'] = ro.get('short-id', '')
    flow = p.get('flow', '')
    if flow:
        params['flow'] = flow
    return params


def _urlencode(params):
    """简单 URL 编码"""
    return '&'.join(f'{k}={quote(str(v), safe="")}' for k, v in params.items() if v)


def parse_host_port(uri):
    """从节点 URI 提取 (host, port)"""
    try:
        if uri.startswith('vmess://'):
            raw = uri[8:].split('#')[0]
            info = json.loads(base64.b64decode(_pad_b64(raw)).decode())
            return str(info.get('add', '')), int(info.get('port', 0))

        if uri.startswith('ssr://'):
            raw = uri[6:].split('#')[0]
            decoded = base64.b64decode(_pad_b64(raw)).decode()
            parts = decoded.split(':')
            return parts[0], int(parts[1])

        if uri.startswith('ss://'):
            content = uri[5:].split('#')[0]
            if '@' in content:
                hostport = content.rsplit('@', 1)[1]
                p = urlparse('http://x@' + hostport)
                return p.hostname, p.port
            else:
                decoded = base64.b64decode(_pad_b64(content)).decode()
                hostport = decoded.rsplit('@', 1)[1]
                host, port = hostport.rsplit(':', 1)
                return host, int(port)

        _, rest = uri.split('://', 1)
        p = urlparse('http://' + rest)
        return p.hostname, p.port
    except Exception:
        return None, None


def get_protocol_name(uri):
    proto = uri.split('://')[0].lower()
    return 'hy2' if proto in ('hysteria2', 'hy2') else proto


# ===== 预过滤与深度去重 =====

def _is_private_host(host):
    """检查是否为私有/保留 IP"""
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_reserved
    except ValueError:
        # 域名，检查常见无效域名
        return host in ('localhost', '127.0.0.1', '0.0.0.0', '::1', '')


def prefilter(nodes):
    """预过滤无效节点"""
    valid = []
    skipped = 0
    for node in nodes:
        host, port = parse_host_port(node)
        if not host or not port or port <= 0 or port > 65535:
            skipped += 1
            continue
        if _is_private_host(host):
            skipped += 1
            continue
        valid.append(node)
    return valid, skipped


def deep_deduplicate(nodes):
    """按 (协议, host, port) 深度去重，保留首次出现的节点"""
    seen = set()
    result = []
    for node in nodes:
        proto = get_protocol_name(node)
        host, port = parse_host_port(node)
        if not host or not port:
            continue
        key = (proto, host.lower(), port)
        if key not in seen:
            seen.add(key)
            result.append(node)
    return result


# ===== 测活：L1 TCP + L2 TLS 两层漏斗 =====

TLS_PORTS = {443, 2053, 2083, 2087, 2096, 8443, 8880}

_tls_ctx = ssl.create_default_context()
_tls_ctx.check_hostname = False
_tls_ctx.verify_mode = ssl.CERT_NONE


async def _check_tcp(host, port):
    """L1: TCP 连接测试，返回延迟(ms)或 None"""
    loop = asyncio.get_event_loop()
    t0 = loop.time()
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        latency = (loop.time() - t0) * 1000
        w.close()
        await w.wait_closed()
        return latency
    except Exception:
        return None


async def _check_tls(host, port, sni=None):
    """L2: TLS 握手验证，返回延迟(ms)或 None"""
    loop = asyncio.get_event_loop()
    t0 = loop.time()
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_tls_ctx,
                                    server_hostname=sni or host),
            timeout=TCP_TIMEOUT
        )
        latency = (loop.time() - t0) * 1000
        w.close()
        await w.wait_closed()
        return latency
    except Exception:
        return None


def _extract_sni(uri):
    """从节点 URI 中提取 SNI"""
    try:
        if uri.startswith('vmess://'):
            raw = uri[8:].split('#')[0]
            info = json.loads(base64.b64decode(_pad_b64(raw)).decode())
            return info.get('sni') or info.get('host') or None
        qs = uri.split('?', 1)[1].split('#')[0] if '?' in uri else ''
        for param in qs.split('&'):
            if param.startswith('sni='):
                return param[4:] or None
        return None
    except Exception:
        return None


async def test_alive(nodes):
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    parse_fail = 0

    async def _test(node):
        nonlocal parse_fail
        host, port = parse_host_port(node)
        if not host or not port:
            parse_fail += 1
            return None
        async with sem:
            # L1: TCP
            latency = await _check_tcp(host, port)
            if latency is None:
                return None
            # L2: TLS 端口做 TLS 握手二次验证
            if port in TLS_PORTS:
                sni = _extract_sni(node)
                tls_latency = await _check_tls(host, port, sni)
                if tls_latency is None:
                    return None
                latency = tls_latency
            return (node, latency)

    tasks = await asyncio.gather(*[_test(n) for n in nodes])
    alive = [r for r in tasks if r is not None]
    dead = len(nodes) - len(alive) - parse_fail

    alive.sort(key=lambda x: x[1])

    avg_latency = sum(lat for _, lat in alive) / len(alive) if alive else 0
    print(f'  存活: {len(alive)} | 失联: {dead} | 解析失败: {parse_fail}')
    if alive:
        print(f'  平均延迟: {avg_latency:.0f}ms | 最快: {alive[0][1]:.0f}ms | 最慢: {alive[-1][1]:.0f}ms')

    return [node for node, _ in alive]


# ===== 地区分类 =====

def _resolve_ip(host, dns_cache):
    if host in dns_cache:
        return dns_cache[host]
    ip = None
    try:
        ipaddress.ip_address(host)
        ip = host
    except ValueError:
        try:
            ip = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
        except Exception:
            pass
    dns_cache[host] = ip
    return ip


def _country_flag(code):
    if not code or len(code) != 2 or code == 'XX':
        return '🏳️'
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())


COUNTRY_NAMES = {
    'AD': '安道尔', 'AE': '阿联酋', 'AF': '阿富汗', 'AL': '阿尔巴尼亚',
    'AM': '亚美尼亚', 'AR': '阿根廷', 'AT': '奥地利', 'AU': '澳大利亚',
    'AZ': '阿塞拜疆', 'BA': '波黑', 'BD': '孟加拉', 'BE': '比利时',
    'BG': '保加利亚', 'BH': '巴林', 'BO': '玻利维亚', 'BR': '巴西',
    'BY': '白俄罗斯', 'CA': '加拿大', 'CH': '瑞士', 'CL': '智利',
    'CN': '中国', 'CO': '哥伦比亚', 'CR': '哥斯达黎加', 'CY': '塞浦路斯',
    'CZ': '捷克', 'DE': '德国', 'DK': '丹麦', 'EC': '厄瓜多尔',
    'EE': '爱沙尼亚', 'EG': '埃及', 'ES': '西班牙', 'FI': '芬兰',
    'FR': '法国', 'GB': '英国', 'GE': '格鲁吉亚', 'GR': '希腊',
    'HK': '香港', 'HR': '克罗地亚', 'HU': '匈牙利', 'ID': '印尼',
    'IE': '爱尔兰', 'IL': '以色列', 'IN': '印度', 'IQ': '伊拉克',
    'IR': '伊朗', 'IS': '冰岛', 'IT': '意大利', 'JP': '日本',
    'KE': '肯尼亚', 'KG': '吉尔吉斯', 'KH': '柬埔寨', 'KR': '韩国',
    'KZ': '哈萨克斯坦', 'LA': '老挝', 'LT': '立陶宛', 'LU': '卢森堡',
    'LV': '拉脱维亚', 'MA': '摩洛哥', 'MD': '摩尔多瓦', 'MK': '北马其顿',
    'MM': '缅甸', 'MN': '蒙古', 'MO': '澳门', 'MT': '马耳他',
    'MX': '墨西哥', 'MY': '马来西亚', 'NG': '尼日利亚', 'NL': '荷兰',
    'NO': '挪威', 'NP': '尼泊尔', 'NZ': '新西兰', 'PA': '巴拿马',
    'PE': '秘鲁', 'PH': '菲律宾', 'PK': '巴基斯坦', 'PL': '波兰',
    'PR': '波多黎各', 'PT': '葡萄牙', 'PY': '巴拉圭', 'QA': '卡塔尔',
    'RO': '罗马尼亚', 'RS': '塞尔维亚', 'RU': '俄罗斯', 'SA': '沙特',
    'SC': '塞舌尔', 'SE': '瑞典', 'SG': '新加坡', 'SI': '斯洛文尼亚',
    'SK': '斯洛伐克', 'TH': '泰国', 'TN': '突尼斯', 'TR': '土耳其',
    'TW': '台湾', 'UA': '乌克兰', 'US': '美国', 'UY': '乌拉圭',
    'UZ': '乌兹别克', 'VE': '委内瑞拉', 'VN': '越南', 'ZA': '南非',
    # CDN
    'CLOUDFLARE': 'CF节点', 'CLOUDFRONT': 'CF-Front',
    'FASTLY': 'Fastly', 'GOOGLE': 'Google',
    'AKAMAI': 'Akamai', 'MICROSOFT': '微软',
    'XX': '未知',
}


def _country_display(cc):
    """返回中文名称，无映射则原样返回"""
    return COUNTRY_NAMES.get(cc, cc)


def _get_country(ip, reader):
    try:
        data = reader.get(ip)
        if isinstance(data, dict):
            country = data.get('country', {})
            if isinstance(country, dict):
                return country.get('iso_code', 'XX') or 'XX'
        return 'XX'
    except Exception:
        return 'XX'


def _rename_node(uri, new_name):
    if uri.startswith('vmess://'):
        try:
            raw = uri[8:].split('#')[0]
            info = json.loads(base64.b64decode(_pad_b64(raw)).decode())
            info['ps'] = new_name
            return 'vmess://' + base64.b64encode(
                json.dumps(info, ensure_ascii=False).encode()
            ).decode()
        except Exception:
            return uri
    return uri.split('#')[0] + '#' + quote(new_name, safe='')


def classify_and_rename(nodes, reader):
    dns_cache = {}
    buckets = defaultdict(list)
    for node in nodes:
        host, _ = parse_host_port(node)
        cc = 'XX'
        if host:
            ip = _resolve_ip(host, dns_cache)
            if ip:
                cc = _get_country(ip, reader)
        buckets[cc].append(node)

    # CDN 限流：code 超过 2 字符的是 CDN 提供商（CLOUDFLARE/FASTLY 等）
    cdn_trimmed = 0
    for cc in list(buckets):
        if len(cc) > 2 and cc != 'XX':
            original = len(buckets[cc])
            if original > MAX_CDN_NODES:
                buckets[cc] = buckets[cc][:MAX_CDN_NODES]
                cdn_trimmed += original - MAX_CDN_NODES

    renamed = []
    us_nodes = []
    country_stats = {}
    for cc in sorted(buckets, key=lambda c: ('ZZZ' if c == 'XX' else c)):
        flag = _country_flag(cc)
        cn_name = _country_display(cc)
        country_stats[cc] = len(buckets[cc])
        for i, node in enumerate(buckets[cc], 1):
            proto = get_protocol_name(node)
            new_node = _rename_node(node, f'{flag} {cn_name} | {proto} | {i:02d}')
            renamed.append(new_node)
            if cc == 'US':
                us_nodes.append(new_node)

    if cdn_trimmed:
        print(f'  CDN 限流: 裁剪 {cdn_trimmed} 个冗余 CDN 节点 (每提供商上限 {MAX_CDN_NODES})')

    return renamed, country_stats, us_nodes


# ===== 主流程 =====

async def async_main():
    t_start = time.time()

    config = load_sources()
    print(f'=== 节点聚合 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} ===\n')

    # 1. 并发抓取
    print(f'[1/5] 抓取 {len(config.get("sources", []))} 个源 (并发{FETCH_WORKERS})...')
    all_nodes, source_stats = fetch_all_sources(config)
    print(f'  合计: {len(all_nodes)} 个原始节点\n')

    # 2. 预过滤
    print('[2/5] 预过滤无效节点...')
    valid, skipped = prefilter(all_nodes)
    print(f'  有效: {len(valid)} | 过滤: {skipped}\n')

    # 3. 深度去重
    print('[3/5] 深度去重 (协议+地址+端口)...')
    unique = deep_deduplicate(valid)
    print(f'  {len(valid)} -> {len(unique)} (去除 {len(valid) - len(unique)} 重复)\n')

    # 4. 测活
    print(f'[4/5] 测活: L1 TCP + L2 TLS (并发{TCP_CONCURRENCY} 超时{TCP_TIMEOUT}s)...')
    alive = await test_alive(unique)

    # 5. 地区分类
    country_stats = {}
    us_nodes = []
    if maxminddb and os.path.exists(GEOIP_DB):
        print(f'\n[5/5] 地区分类...')
        reader = maxminddb.open_database(GEOIP_DB)
        result, country_stats, us_nodes = classify_and_rename(alive, reader)
        reader.close()
        for cc in sorted(country_stats, key=lambda c: ('ZZZ' if c == 'XX' else c)):
            print(f'  {_country_flag(cc)} {_country_display(cc)}: {country_stats[cc]}')
    else:
        print('\n[5/5] GeoIP 不可用，跳过地区分类')
        result = alive

    # 输出
    os.makedirs('output', exist_ok=True)

    with open('output/nodes.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(result) + '\n')

    b64 = base64.b64encode('\n'.join(result).encode()).decode()
    with open('output/nodes_base64.txt', 'w', encoding='utf-8') as f:
        f.write(b64)

    with open('output/easy_proxy_nodes.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(us_nodes) + '\n')
    print(f'  easy_proxy (US): {len(us_nodes)} 个节点 -> output/easy_proxy_nodes.txt')

    stats = {
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_fetched': len(all_nodes),
        'after_prefilter': len(valid),
        'unique_nodes': len(unique),
        'alive_nodes': len(alive),
        'country_stats': country_stats,
        'sources': source_stats,
    }
    with open('output/stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    elapsed = time.time() - t_start
    print(f'\n=== 完成: {len(result)} 个存活节点 | 耗时 {elapsed:.1f}s ===')


def main():
    asyncio.run(async_main())


if __name__ == '__main__':
    main()
