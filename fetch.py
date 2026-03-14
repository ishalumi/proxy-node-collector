#!/usr/bin/env python3
"""代理节点聚合爬虫 - 抓取、去重、测活、地区分类"""

import asyncio
import base64
import json
import os
import socket
from collections import defaultdict
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
TCP_CONCURRENCY = 50
TCP_TIMEOUT = 5


# ===== 数据源抓取 =====

def load_sources(path='sources.yaml'):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def fetch_url(url, timeout=30):
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
    decoded = decode_base64(content)
    if decoded:
        for line in decoded.splitlines():
            line = line.strip()
            if is_node(line):
                nodes.append(line)
    return nodes


def deduplicate(nodes):
    seen = set()
    result = []
    for n in nodes:
        if n not in seen:
            seen.add(n)
            result.append(n)
    return result


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
                # SIP002: base64(method:password)@host:port
                hostport = content.rsplit('@', 1)[1]
                p = urlparse('http://x@' + hostport)
                return p.hostname, p.port
            else:
                # Legacy: base64(method:password@host:port)
                decoded = base64.b64decode(_pad_b64(content)).decode()
                hostport = decoded.rsplit('@', 1)[1]
                host, port = hostport.rsplit(':', 1)
                return host, int(port)

        # vless, trojan, hy2, hysteria2, hysteria, socks5, socks
        _, rest = uri.split('://', 1)
        p = urlparse('http://' + rest)
        return p.hostname, p.port
    except Exception:
        return None, None


def get_protocol_name(uri):
    proto = uri.split('://')[0].lower()
    return 'hy2' if proto in ('hysteria2', 'hy2') else proto


# ===== TCP 测活 =====

async def _check_tcp(host, port):
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        w.close()
        await w.wait_closed()
        return True
    except Exception:
        return False


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
            return node if await _check_tcp(host, port) else None

    results = await asyncio.gather(*[_test(n) for n in nodes])
    alive = [r for r in results if r is not None]
    dead = len(nodes) - len(alive) - parse_fail
    print(f'  解析失败: {parse_fail} | 存活: {len(alive)} | 失联: {dead}')
    return alive


# ===== 地区分类 =====

def _resolve_ip(host):
    try:
        socket.inet_pton(socket.AF_INET, host)
        return host
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return host
    except OSError:
        pass
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
    except Exception:
        return None


def _country_flag(code):
    if not code or len(code) != 2 or code == 'XX':
        return '🏳️'
    return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())


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
    buckets = defaultdict(list)
    for node in nodes:
        host, _ = parse_host_port(node)
        cc = 'XX'
        if host:
            ip = _resolve_ip(host)
            if ip:
                cc = _get_country(ip, reader)
        buckets[cc].append(node)

    renamed = []
    country_stats = {}
    for cc in sorted(buckets, key=lambda c: ('ZZZ' if c == 'XX' else c)):
        flag = _country_flag(cc)
        country_stats[cc] = len(buckets[cc])
        for i, node in enumerate(buckets[cc], 1):
            proto = get_protocol_name(node)
            renamed.append(_rename_node(node, f'{flag} {cc} | {proto} | {i:02d}'))

    return renamed, country_stats


# ===== 主流程 =====

async def async_main():
    config = load_sources()
    all_nodes = []
    source_stats = []

    print(f'=== 节点聚合 {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} ===\n')

    for src in config.get('sources', []):
        name = src['name']
        url = resolve_url(src)
        if not url:
            print(f'[!] {name}: URL 无效，跳过')
            continue

        print(f'[*] {name}')
        content = fetch_url(url)
        if not content:
            source_stats.append({'name': name, 'count': 0, 'status': 'failed'})
            continue

        nodes = parse_nodes(content)
        print(f'    -> {len(nodes)} 个节点')
        all_nodes.extend(nodes)
        source_stats.append({'name': name, 'count': len(nodes), 'status': 'ok'})

    unique = deduplicate(all_nodes)
    print(f'\n=== 总计 {len(all_nodes)} -> 去重 {len(unique)} ===')

    # 测活
    print(f'\n=== TCP 测活 (并发{TCP_CONCURRENCY} 超时{TCP_TIMEOUT}s) ===')
    alive = await test_alive(unique)

    # 地区分类
    country_stats = {}
    if maxminddb and os.path.exists(GEOIP_DB):
        print(f'\n=== 地区分类 ===')
        reader = maxminddb.open_database(GEOIP_DB)
        result, country_stats = classify_and_rename(alive, reader)
        reader.close()
        for cc in sorted(country_stats, key=lambda c: ('ZZZ' if c == 'XX' else c)):
            print(f'  {_country_flag(cc)} {cc}: {country_stats[cc]}')
    else:
        print('\n[!] GeoIP 不可用，跳过地区分类')
        result = alive

    # 输出
    os.makedirs('output', exist_ok=True)

    with open('output/nodes.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(result) + '\n')

    b64 = base64.b64encode('\n'.join(result).encode()).decode()
    with open('output/nodes_base64.txt', 'w', encoding='utf-8') as f:
        f.write(b64)

    stats = {
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_fetched': len(all_nodes),
        'unique_nodes': len(unique),
        'alive_nodes': len(alive),
        'country_stats': country_stats,
        'sources': source_stats,
    }
    with open('output/stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print(f'\n输出 -> output/ ({len(result)} 个存活节点)')


def main():
    asyncio.run(async_main())


if __name__ == '__main__':
    main()
