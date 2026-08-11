#!/usr/bin/env python3
"""代理节点聚合爬虫 - 抓取、去重、测活、地区分类"""

import asyncio
import base64
import html
import ipaddress
import json
import os
import socket
import ssl
import time
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, quote, unquote
from urllib.request import urlopen, Request

import yaml

try:
    import maxminddb
except ImportError:
    maxminddb = None

def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default

def _env_float(name, default):
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default

PROTOCOLS = (
    'vmess://', 'vless://', 'trojan://', 'ss://',
    'ssr://', 'hy2://', 'hysteria2://', 'hysteria://',
    'socks5://', 'socks://',
)

GEOIP_DB = os.environ.get('GEOIP_DB', 'GeoLite2-Country.mmdb')
TCP_CONCURRENCY = _env_int('TCP_CONCURRENCY', 600)
TCP_TIMEOUT = _env_float('TCP_TIMEOUT', 3.5)
FETCH_TIMEOUT = _env_float('FETCH_TIMEOUT', 20)
FETCH_WORKERS = _env_int('FETCH_WORKERS', 16)
MAX_CDN_NODES = 30
# 默认 2.5s：GitHub Actions 在海外，过宽会把“端口开着但代理废了”的节点放进来
LATENCY_MAX_MS = _env_int('LATENCY_MAX_MS', 2500)
# 最终输出上限，避免 easy_proxies 被几千垃圾节点淹没
MAX_OUTPUT_NODES = _env_int('MAX_OUTPUT_NODES', 2500)

# ChatGPT/OpenAI 封锁国家（基于实测 API 验证 + 已知制裁清单）
CHATGPT_BLOCKED = {'CN', 'RU', 'BY', 'IR', 'KP', 'CU', 'SY'}
CDN_CODES = {'CLOUDFLARE', 'CLOUDFRONT', 'FASTLY', 'GOOGLE', 'AKAMAI', 'MICROSOFT', 'XX'}

# 亚洲 ChatGPT 可达地区
ASIA_CHATGPT = {
    'JP', 'KR', 'SG', 'TW', 'HK', 'VN', 'TH', 'ID', 'MY', 'IN',
    'PH', 'KH', 'MN', 'PK', 'BD', 'AE', 'BH', 'SA', 'KZ', 'AU',
}
# 美西服务器低延迟友好区域
US_WEST_FRIENDLY = {'US', 'CA', 'MX', 'JP', 'KR', 'TW', 'VN'}
# 欧洲 ChatGPT 可达地区
EUROPE_CHATGPT = {
    'DE', 'GB', 'FR', 'NL', 'SE', 'FI', 'AT', 'BE', 'BG', 'CH',
    'CZ', 'DK', 'EE', 'ES', 'GR', 'HR', 'HU', 'IE', 'IS', 'IT',
    'LT', 'LV', 'MK', 'MT', 'NO', 'PL', 'PT', 'RO', 'SI', 'CY',
    'MD', 'UA', 'AL',
}

DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
CLASH_UA = 'ClashforWindows/0.20.39'
BLUE2SEA_README = 'https://raw.githubusercontent.com/bq2015/FreeProxies/main/README.md'
BLUE2SEA_TOKEN_RE = re.compile(
    r'https?://blue2sea\.com/clash/([0-9a-fA-F]{16,})', re.I
)
PROVIDER_URL_RE = re.compile(
    r'''url:\s*["']?(https?://[^\s"'#]+)["']?''', re.I
)


# ===== 数据源抓取 =====

def load_sources(path='sources.yaml'):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)


def fetch_url(url, timeout=FETCH_TIMEOUT, headers=None):
    hdrs = {'User-Agent': DEFAULT_UA, 'Accept': '*/*'}
    if headers:
        hdrs.update(headers)
    req = Request(url, headers=hdrs)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f'  [!] 请求失败 {url[:80]}: {e}')
        return None


def resolve_url(source):
    if source.get('dynamic') == 'blue2sea':
        token = _resolve_blue2sea_token()
        if token:
            return f'https://blue2sea.com/clash/{token}'
        # fallback 到配置里的静态 url
    if 'url' in source:
        return source['url']
    if 'url_template' in source:
        now = datetime.now(timezone(timedelta(hours=8)))
        fmt = source.get('date_format', '%Y%m%d')
        return source['url_template'].replace('{date}', now.strftime(fmt))
    return None


_blue2sea_token_cache = None


def _resolve_blue2sea_token():
    """从 bq2015/FreeProxies README 解析当日公共 token（每日轮换）"""
    global _blue2sea_token_cache
    if _blue2sea_token_cache:
        return _blue2sea_token_cache
    content = fetch_url(BLUE2SEA_README, headers={'User-Agent': DEFAULT_UA})
    if not content:
        return None
    m = BLUE2SEA_TOKEN_RE.search(content)
    if not m:
        print('  [!] blue2sea token 未在 FreeProxies README 中找到')
        return None
    _blue2sea_token_cache = m.group(1)
    print(f'  [i] blue2sea token: {_blue2sea_token_cache[:8]}...')
    return _blue2sea_token_cache


def _source_headers(src):
    headers = {}
    raw = src.get('headers') or {}
    if isinstance(raw, dict):
        headers.update({str(k): str(v) for k, v in raw.items()})
    if src.get('dynamic') == 'blue2sea' or src.get('resolve_providers'):
        headers.setdefault('User-Agent', CLASH_UA)
    return headers


def _extract_provider_urls(content):
    """从 Clash 配置提取 proxy-providers 的真实节点 URL"""
    urls = []
    try:
        data = yaml.safe_load(content)
    except Exception:
        data = None
    if isinstance(data, dict):
        providers = data.get('proxy-providers') or data.get('proxy-provider') or {}
        if isinstance(providers, dict):
            for _, meta in providers.items():
                if isinstance(meta, dict) and meta.get('url'):
                    urls.append(str(meta['url']).strip())
        # 已内嵌 proxies 则无需 providers
        if data.get('proxies'):
            return urls
    if not urls:
        for m in PROVIDER_URL_RE.finditer(content or ''):
            u = m.group(1).strip().rstrip('",\'')
            if 'blue2sea.com/clash/proxies/' in u or 'proxy-providers' in content:
                urls.append(u)
            elif '/proxies/' in u and 'clash' in u:
                urls.append(u)
    # 去重保序；blue2sea 优先 ALL-NET，跳过 aiAgent 子集以免双倍 429
    seen = set()
    out = []
    for u in urls:
        low = u.lower()
        if 'blue2sea.com' in low and 'aiagent' in low:
            continue
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _fetch_content_with_providers(url, headers, resolve_providers=False):
    """抓取内容；若是 Clash provider 壳，则展开嵌套节点列表"""
    content = fetch_url(url, headers=headers)
    if not content:
        return None, []

    nodes = parse_nodes(content)
    if nodes:
        return content, nodes

    if not resolve_providers:
        return content, []

    provider_urls = _extract_provider_urls(content)
    if not provider_urls:
        return content, []

    all_nodes = []
    for pu in provider_urls:
        # provider 常强制 Clash UA
        ph = dict(headers or {})
        ph.setdefault('User-Agent', CLASH_UA)
        # blue2sea 的 provider 有时只认 query ua=
        if 'blue2sea.com' in pu and 'ua=' not in pu:
            sep = '&' if '?' in pu else '?'
            pu = f'{pu}{sep}ua=clashforwindows/0.20.39'
        # 优先 https
        candidates = [pu]
        if pu.startswith('http://'):
            candidates.insert(0, 'https://' + pu[len('http://'):])
        got = None
        for cand in candidates:
            for attempt in range(4):
                got = fetch_url(cand, headers=ph)
                if not got:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                # blue2sea 限流 JSON / 空 proxies
                if '过于频繁' in got or '"status": 429' in got or '"status":429' in got:
                    wait = 3 * (attempt + 1)
                    print(f'  [i] provider 429，等待 {wait}s 重试: {cand[:70]}')
                    time.sleep(wait)
                    got = None
                    continue
                if 'proxies: []' in got.strip() or got.strip() == 'proxies: []':
                    # 空列表也可能是限流伪装，退避再试
                    time.sleep(2 * (attempt + 1))
                    got = None
                    continue
                if len(got) > 32:
                    break
                got = None
            if got:
                break
        if not got:
            print(f'  [!] provider 拉取失败: {pu[:90]}')
            continue
        sub_nodes = parse_nodes(got)
        print(f'  [i] provider {pu[:70]}... -> {len(sub_nodes)} 节点')
        all_nodes.extend(sub_nodes)
        # 多个 provider 之间也稍作间隔，降低 429
        time.sleep(1.2)
    return content, all_nodes


def fetch_all_sources(config):
    """多线程并发抓取所有源；高 priority 源节点排在前面，便于去重保留"""
    sources = list(config.get('sources', []))
    # 高 priority 先抓、节点先入队
    sources.sort(key=lambda s: -int(s.get('priority', 50)))
    all_nodes = []
    source_stats = []

    def _fetch_one(src):
        name = src['name']
        url = resolve_url(src)
        if not url:
            return name, [], 'invalid', 0, 0, int(src.get('priority', 50))
        headers = _source_headers(src)
        resolve_providers = bool(src.get('resolve_providers') or src.get('dynamic') == 'blue2sea')
        for attempt in range(2):
            try:
                _, nodes = _fetch_content_with_providers(
                    url, headers, resolve_providers=resolve_providers
                )
                # blue2sea 主页本身没有 proxies，仅 provider
                if not nodes and not resolve_providers:
                    content = fetch_url(url, headers=headers)
                    nodes = parse_nodes(content or '')
                raw_count = len(nodes)
                if raw_count == 0:
                    if attempt == 0:
                        time.sleep(1.5)
                        continue
                    return name, [], 'failed', 0, 0, int(src.get('priority', 50))
                limit = src.get('limit')
                if limit and len(nodes) > int(limit):
                    step = (len(nodes) - 1) / (int(limit) - 1) if int(limit) > 1 else 1
                    nodes = [nodes[round(i * step)] for i in range(int(limit))]
                trimmed = raw_count - len(nodes)
                return name, nodes, 'ok', raw_count, trimmed, int(src.get('priority', 50))
            except Exception as e:
                if attempt == 0:
                    time.sleep(1)
                    continue
                print(f'  [!] {name} 异常: {e}')
                return name, [], 'failed', 0, 0, int(src.get('priority', 50))
        return name, [], 'failed', 0, 0, int(src.get('priority', 50))

    # 结果按 priority 回填，保证高优先级节点先进入去重
    results = []

    def _record(name, nodes, status, raw_count, trimmed, priority):
        count = len(nodes)
        icon = '✓' if status == 'ok' else '✗'
        if trimmed:
            print(f'  [{icon}] {name}: {raw_count} -> {count} 个节点 (限流 {trimmed})')
        else:
            print(f'  [{icon}] {name}: {count} 个节点')
        results.append((priority, name, nodes, status, raw_count, trimmed))
        source_stats.append({
            'name': name, 'count': count, 'raw_count': raw_count,
            'trimmed': trimmed, 'status': status, 'priority': priority,
        })

    # 动态源（blue2sea 等）串行优先，避免与并发抓取抢限流
    serial_sources = [s for s in sources if s.get('dynamic')]
    parallel_sources = [s for s in sources if not s.get('dynamic')]
    for src in serial_sources:
        _record(*_fetch_one(src))

    with ThreadPoolExecutor(max_workers=FETCH_WORKERS) as pool:
        futures = {pool.submit(_fetch_one, src): src for src in parallel_sources}
        for future in as_completed(futures):
            _record(*future.result())

    results.sort(key=lambda x: -x[0])
    for _, name, nodes, status, raw_count, trimmed in results:
        all_nodes.extend(nodes)

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
    if not content:
        return []
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
    if isinstance(data, list):
        # 某些 provider 直接返回 proxies 列表
        proxies = data
    elif isinstance(data, dict):
        proxies = data.get('proxies', [])
    else:
        return []
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
    name = quote(html.unescape(str(p.get('name', ''))), safe='')
    if not server or not port:
        return None

    if ptype == 'vmess':
        net = (p.get('network', 'tcp') or 'tcp').lower()
        if net == 'raw':
            return None  # sing-box 不认 raw transport，会 panic
        info = {
            'v': '2', 'ps': p.get('name', ''),
            'add': server, 'port': str(port),
            'id': p.get('uuid', ''), 'aid': str(p.get('alterId', 0)),
            'scy': p.get('cipher', 'auto'), 'net': net,
            'type': 'none', 'tls': 'tls' if p.get('tls') else '',
        }
        ws = p.get('ws-opts', {}) or {}
        if ws:
            info['path'] = ws.get('path', '/')
            info['host'] = (ws.get('headers') or {}).get('Host', '')
        if p.get('servername'):
            info['sni'] = p['servername']
        return 'vmess://' + base64.b64encode(
            json.dumps(info, ensure_ascii=False).encode()).decode()

    if ptype == 'vless':
        params = _build_clash_params(p)
        if params is None:
            return None  # transport 不兼容，丢弃
        flow = p.get('flow', '')
        if flow:
            params['flow'] = flow
        return f"vless://{p.get('uuid', '')}@{server}:{port}?{_urlencode(params)}#{name}"

    if ptype == 'trojan':
        params = _build_clash_params(p)
        if params is None:
            return None  # transport 不兼容，丢弃
        return f"trojan://{p.get('password', '')}@{server}:{port}?{_urlencode(params)}#{name}"

    if ptype == 'ss':
        method = p.get('cipher', 'aes-256-gcm')
        pwd = p.get('password', '')
        userinfo = base64.b64encode(f'{method}:{pwd}'.encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{name}"

    if ptype in ('ssr', 'hysteria2', 'hy2', 'hysteria'):
        if ptype == 'ssr':
            return None
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
        if net not in ('tcp', 'ws', 'grpc', 'httpupgrade', 'http'):
            return None  # xhttp/splithttp/h2/raw 等会 panic，整体丢弃该节点
        params['type'] = net
    ws = p.get('ws-opts', {}) or {}
    if ws:
        params['host'] = (ws.get('headers') or {}).get('Host', '')
        params['path'] = ws.get('path', '/')
    grpc = p.get('grpc-opts', {}) or {}
    if grpc:
        params['serviceName'] = grpc.get('grpc-service-name', '')
    fp = p.get('client-fingerprint', '')
    if fp:
        params['fp'] = fp
    ro = p.get('reality-opts', {}) or {}
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
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast
    except ValueError:
        return host in ('localhost', '127.0.0.1', '0.0.0.0', '::1', '')


# sing-box 支持的 ss 加密方法白名单
_GOOD_SS_METHODS = {
    'aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
    'xchacha20-ietf-poly1305', '2022-blake3-aes-128-gcm',
    '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'chacha20', 'chacha20-ietf', 'xchacha20',
    'none', 'plain',
}

_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_UUID_NOHYPHEN_RE = re.compile(r'^[0-9a-fA-F]{32}$')

# sing-box 支持的 vless flow 值
_GOOD_VLESS_FLOWS = {'', 'xtls-rprx-vision'}


def _validate_uri(node):
    """检查节点 URI 是否能被 sing-box 正确解析，过滤掉会导致 panic 的节点"""
    try:
        if '&amp;' in node:
            return False  # HTML 实体未解码，query 解析失败会导致 panic
        if node.startswith('vmess://'):
            raw = node[8:].split('#')[0]
            info = json.loads(base64.b64decode(_pad_b64(raw)).decode())
            if not info.get('id'):
                return False
            if not info.get('add'):
                return False
            port = info.get('port')
            if not port or str(port) == '0':
                return False
            net = (info.get('net') or info.get('network') or '').lower()
            if net == 'raw':
                return False  # sing-box 不认 raw transport，会 panic
        elif node.startswith('ss://'):
            content = node[5:].split('#')[0]
            if '@' in content:
                userinfo = content.split('@')[0]
                try:
                    decoded = base64.b64decode(_pad_b64(userinfo)).decode()
                    method = decoded.split(':')[0].lower().strip()
                except Exception:
                    return False
            else:
                try:
                    decoded = base64.b64decode(_pad_b64(content)).decode()
                    method = decoded.split(':')[0].lower().strip()
                except Exception:
                    return False
            if method not in _GOOD_SS_METHODS:
                return False
        elif node.startswith('vless://'):
            rest = node[8:]
            if '@' not in rest:
                return False
            uuid_part = rest.split('@')[0]
            if not (_UUID_RE.match(uuid_part) or _UUID_NOHYPHEN_RE.match(uuid_part)):
                return False
            qs = ''
            if '?' in node:
                qs = node.split('?', 1)[1].split('#')[0]
            qs = html.unescape(qs)
            params = {}
            for param in qs.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = v.lower()
            flow = params.get('flow', '')
            if flow and flow not in _GOOD_VLESS_FLOWS:
                return False
            encryption = params.get('encryption', 'none')
            if encryption not in ('none', ''):
                return False
            security = params.get('security', '')
            if security == 'reality' and not params.get('pbk'):
                return False  # reality 必须有 public_key，缺 pbk 会 panic
            if security not in ('', 'none', 'tls', 'reality'):
                return False
            ntype = params.get('type', '')
            if ntype and ntype not in ('tcp', 'ws', 'grpc', 'httpupgrade', 'http'):
                return False  # xhttp/splithttp/h2/raw 等 sing-box 不支持或会 panic
        elif node.startswith('trojan://') or node.startswith('hy2://') or node.startswith('hysteria2://'):
            qs = node.split('?', 1)[1].split('#')[0] if '?' in node else ''
            ntype = ''
            for param in qs.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    if k.lower() == 'type':
                        ntype = v.lower()
            if ntype and ntype not in ('tcp', 'ws', 'grpc', 'httpupgrade', 'http'):
                return False
        return True
    except Exception:
        return False


def prefilter(nodes):
    """预过滤无效节点"""
    valid = []
    skipped = 0
    bad_uri = 0
    for node in nodes:
        host, port = parse_host_port(node)
        if not host or not port or port <= 0 or port > 65535:
            skipped += 1
            continue
        if _is_private_host(host):
            skipped += 1
            continue
        if not _validate_uri(node):
            bad_uri += 1
            continue
        valid.append(node)
    if bad_uri:
        print(f'  URI 校验过滤: {bad_uri} 个（sing-box 不兼容）')
    return valid, skipped + bad_uri


def deep_deduplicate(nodes):
    """按 (协议, host, port) 深度去重，保留首次出现（调用方应保证高优先级在前）"""
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


# ===== 测活：L1 TCP + L2 TLS（协议感知） =====

# 常见 TLS 入口端口 + 代理常用 TLS 端口
TLS_PORTS = {
    443, 2053, 2083, 2087, 2096, 8443, 8880, 9443, 10443, 6443, 7443,
}


_tls_ctx = ssl.create_default_context()
_tls_ctx.check_hostname = False
_tls_ctx.verify_mode = ssl.CERT_NONE


async def _check_tcp(host, port):
    """L1: TCP 连接测试，返回延迟(ms)或 None"""
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        latency = (loop.time() - t0) * 1000
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        return latency
    except Exception:
        return None


async def _check_tls(host, port, sni=None):
    """L2: TLS 握手验证，返回延迟(ms)或 None"""
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    try:
        _, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=_tls_ctx,
                                    server_hostname=sni or host),
            timeout=TCP_TIMEOUT
        )
        latency = (loop.time() - t0) * 1000
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
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
                return unquote(param[4:]) or None
            if param.startswith('host='):
                # host 可作 sni 备选
                val = unquote(param[5:]) or None
                if val:
                    return val
        return None
    except Exception:
        return None


def _requires_tls(uri, port):
    """协议感知：声明了 TLS/REALITY 的节点必须过 TLS 握手"""
    try:
        if uri.startswith('trojan://') or uri.startswith('hy2://') or uri.startswith('hysteria'):
            return True
        if uri.startswith('vmess://'):
            raw = uri[8:].split('#')[0]
            info = json.loads(base64.b64decode(_pad_b64(raw)).decode())
            tls = str(info.get('tls', '')).lower()
            return tls in ('tls', '1', 'true', 'reality')
        if uri.startswith('vless://'):
            qs = uri.split('?', 1)[1].split('#')[0] if '?' in uri else ''
            params = {}
            for param in qs.split('&'):
                if '=' in param:
                    k, v = param.split('=', 1)
                    params[k.lower()] = unquote(v).lower()
            sec = params.get('security', '')
            return sec in ('tls', 'reality')
        return port in TLS_PORTS
    except Exception:
        return port in TLS_PORTS


async def test_alive(nodes):
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    parse_fail = 0
    tls_fail = 0

    async def _test(node):
        nonlocal parse_fail, tls_fail
        host, port = parse_host_port(node)
        if not host or not port:
            parse_fail += 1
            return None
        async with sem:
            need_tls = _requires_tls(node, port)
            if need_tls:
                sni = _extract_sni(node)
                latency = await _check_tls(host, port, sni)
                if latency is None:
                    # TLS 失败再尝试裸 TCP，仍失败才判死
                    # 但对明确 TLS 协议，TLS 失败直接丢弃（避免“端口开着”假活）
                    tls_fail += 1
                    return None
                return (node, latency)

            latency = await _check_tcp(host, port)
            if latency is None:
                return None
            # 常见 TLS 端口即使协议未声明也做 TLS 二次验证
            if port in TLS_PORTS:
                sni = _extract_sni(node)
                tls_latency = await _check_tls(host, port, sni)
                if tls_latency is None:
                    tls_fail += 1
                    return None
                latency = tls_latency
            return (node, latency)

    tasks = await asyncio.gather(*[_test(n) for n in nodes])
    alive = [r for r in tasks if r is not None]
    dead = len(nodes) - len(alive) - parse_fail

    alive.sort(key=lambda x: x[1])

    # 丢弃延迟超阈值的节点
    before_trim = len(alive)
    alive = [(node, lat) for node, lat in alive if lat <= LATENCY_MAX_MS]
    trimmed = before_trim - len(alive)

    # 输出上限：保留延迟最低的 N 个
    if MAX_OUTPUT_NODES and len(alive) > MAX_OUTPUT_NODES:
        print(f'  输出上限: {len(alive)} -> {MAX_OUTPUT_NODES}（按延迟截断）')
        alive = alive[:MAX_OUTPUT_NODES]

    avg_latency = sum(lat for _, lat in alive) / len(alive) if alive else 0
    print(f'  存活: {len(alive)} | 失联: {dead} | TLS失败: {tls_fail} | '
          f'高延迟丢弃(>{LATENCY_MAX_MS}ms): {trimmed} | 解析失败: {parse_fail}')
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
    groups = {'us': [], 'chatgpt': [], 'asia': [], 'europe': [], 'us_optimized': []}
    country_stats = {}
    for cc in sorted(buckets, key=lambda c: ('ZZZ' if c == 'XX' else c)):
        flag = _country_flag(cc)
        cn_name = _country_display(cc)
        country_stats[cc] = len(buckets[cc])
        is_chatgpt_ok = cc not in CHATGPT_BLOCKED and cc not in CDN_CODES
        for i, node in enumerate(buckets[cc], 1):
            proto = get_protocol_name(node)
            new_node = _rename_node(node, f'{flag} {cn_name} | {proto} | {i:02d}')
            renamed.append(new_node)
            if cc == 'US':
                groups['us'].append(new_node)
            if cc in US_WEST_FRIENDLY:
                groups['us_optimized'].append(new_node)
            if is_chatgpt_ok:
                groups['chatgpt'].append(new_node)
            if cc in ASIA_CHATGPT:
                groups['asia'].append(new_node)
            if cc in EUROPE_CHATGPT:
                groups['europe'].append(new_node)

    if cdn_trimmed:
        print(f'  CDN 限流: 裁剪 {cdn_trimmed} 个冗余 CDN 节点 (每提供商上限 {MAX_CDN_NODES})')

    return renamed, country_stats, groups


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
    print('[3/5] 深度去重 (协议+地址+端口，高优先级优先)...')
    unique = deep_deduplicate(valid)
    print(f'  {len(valid)} -> {len(unique)} (去除 {len(valid) - len(unique)} 重复)\n')

    # 4. 测活
    print(f'[4/5] 测活: 协议感知 TCP/TLS (并发{TCP_CONCURRENCY} 超时{TCP_TIMEOUT}s 延迟≤{LATENCY_MAX_MS}ms)...')
    alive = await test_alive(unique)

    # 5. 地区分类
    country_stats = {}
    groups = {}
    if maxminddb and os.path.exists(GEOIP_DB):
        print(f'\n[5/5] 地区分类...')
        reader = maxminddb.open_database(GEOIP_DB)
        result, country_stats, groups = classify_and_rename(alive, reader)
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

    # easy_proxy 多分类输出
    ep_files = {
        'us':           ('easy_proxy_nodes.txt',         'US'),
        'us_optimized': ('easy_proxy_us_optimized.txt',  '美西优化'),
        'chatgpt':      ('easy_proxy_chatgpt.txt',       'ChatGPT可达'),
        'asia':         ('easy_proxy_asia.txt',           '亚洲'),
        'europe':       ('easy_proxy_europe.txt',         '欧洲'),
    }
    for key, (fname, label) in ep_files.items():
        nodes = groups.get(key, [])
        with open(f'output/{fname}', 'w', encoding='utf-8') as f:
            f.write('\n'.join(nodes) + '\n')
        print(f'  easy_proxy ({label}): {len(nodes)} 个节点 -> output/{fname}')

    stats = {
        'updated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'total_fetched': len(all_nodes),
        'after_prefilter': len(valid),
        'unique_nodes': len(unique),
        'alive_nodes': len(alive),
        'latency_max_ms': LATENCY_MAX_MS,
        'tcp_timeout': TCP_TIMEOUT,
        'max_output_nodes': MAX_OUTPUT_NODES,
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
