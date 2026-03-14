#!/usr/bin/env python3
"""代理节点聚合爬虫 - 从多个公开源抓取、去重、输出"""

import base64
import json
import os
from datetime import datetime, timezone, timedelta
from urllib.request import urlopen, Request

import yaml

PROTOCOLS = (
    'vmess://', 'vless://', 'trojan://', 'ss://',
    'ssr://', 'hy2://', 'hysteria2://', 'hysteria://',
    'socks5://', 'socks://',
)


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


def decode_base64(text):
    text = text.strip()
    remainder = len(text) % 4
    if remainder:
        text += '=' * (4 - remainder)
    try:
        return base64.b64decode(text).decode('utf-8', errors='ignore')
    except Exception:
        return None


def is_node(line):
    return any(line.startswith(p) for p in PROTOCOLS)


def parse_nodes(content):
    """自动识别 base64 / 纯文本并提取节点 URI"""
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


def resolve_url(source):
    if 'url' in source:
        return source['url']
    if 'url_template' in source:
        now = datetime.now(timezone(timedelta(hours=8)))
        fmt = source.get('date_format', '%Y%m%d')
        return source['url_template'].replace('{date}', now.strftime(fmt))
    return None


def deduplicate(nodes):
    seen = set()
    result = []
    for n in nodes:
        if n not in seen:
            seen.add(n)
            result.append(n)
    return result


def main():
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

    os.makedirs('output', exist_ok=True)

    with open('output/nodes.txt', 'w', encoding='utf-8') as f:
        f.write('\n'.join(unique) + '\n')

    b64 = base64.b64encode('\n'.join(unique).encode()).decode()
    with open('output/nodes_base64.txt', 'w', encoding='utf-8') as f:
        f.write(b64)

    stats = {
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_fetched': len(all_nodes),
        'unique_nodes': len(unique),
        'sources': source_stats,
    }
    with open('output/stats.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2, ensure_ascii=False)

    print('输出 -> output/')


if __name__ == '__main__':
    main()
