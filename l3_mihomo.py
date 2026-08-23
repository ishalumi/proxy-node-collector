#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""L3 真流量测活：mihomo 加载真实代理配置 -> HTTP 204 探测（社区黄金标准）。
读 output/nodes.txt（TCP/TLS 存活），过滤出真实可转发流量的节点后原子写回。

比「端口开着/TLS 能握手」严格一个量级：
- 节点必须能真正建立代理连接并转发 HTTP 流量（generate_204）
- 延迟 > L3_LATENCY_MAX_MS 丢弃（默认 2000ms，配合 fetch.py 的 1500 阈值）
- 每个节点只保留 delay > 0 的结果
"""
import base64, json, os, re, socket, subprocess, sys, time, urllib.parse, shutil

NODES_FILE = os.environ.get("L3_IN", "output/nodes.txt")
OUT_FILE = os.environ.get("L3_OUT", "output/nodes.txt.l3")
TIMEOUT_MS = int(os.environ.get("L3_TIMEOUT_MS", "4000"))
LATENCY_MAX_MS = int(os.environ.get("L3_LATENCY_MAX_MS", "2000"))
MIHOMO_BATCH = int(os.environ.get("MIHOMO_BATCH", "500"))
MIHOMO_WORKERS = int(os.environ.get("MIHOMO_WORKERS", "30"))
MAX_TEST_NODES = int(os.environ.get("L3_MAX_TEST_NODES", "4000"))

def parse_uri(uri):
    try:
        u = urllib.parse.urlparse(uri)
        host = u.hostname
        port = u.port or 443
        return u, host, port
    except Exception:
        return None, None, None

def _b64d(s):
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()
    except Exception:
        return None

def to_clash(uri, idx):
    """URI -> Clash/mihomo proxy dict。无法转换/已知坏特征 -> None。"""
    u, host, port = parse_uri(uri)
    if not u or not host:
        return None
    qs = urllib.parse.parse_qs(u.query)
    name = f"n{idx}"

    if u.scheme == "vless":
        flow = qs.get("flow", [""])[0]
        if flow and flow not in ("xtls-rprx-vision", "xtls-rprx-direct"):
            return None
        security = qs.get("security", [""])[0]
        if security == "reality" and not qs.get("pbk"):
            return None
        p = {
            "name": name, "type": "vless", "server": host, "port": port,
            "uuid": u.username or "", "network": (qs.get("type", ["tcp"])[0] or "tcp"),
            "tls": security in ("tls", "reality"),
        }
        if flow:
            p["flow"] = flow
        if security == "reality":
            p["reality-opts"] = {"public-key": qs["pbk"][0], "short-id": (qs.get("sid") or [""])[0]}
            if qs.get("fp"):
                p["client-fingerprint"] = qs["fp"][0]
        if qs.get("sni"):
            p["servername"] = qs["sni"][0]
        if qs.get("host"):
            p["ws-opts"] = {"path": (qs.get("path") or ["/"])[0], "headers": {"Host": qs["host"][0]}}
        elif qs.get("path"):
            p["ws-opts"] = {"path": qs["path"][0]}
        return p

    if u.scheme == "vmess":
        # vmess://base64(json) 形态：无 @ 时 netloc 就是 base64 payload（hostname 会被小写化，必须用 netloc）
        userinfo, _, hostpart = u.netloc.rpartition("@")
        raw = userinfo or hostpart.split(":")[0]
        if raw and ":" not in raw:
            info = _b64d(raw)
            if not info:
                return None
            try:
                j = json.loads(info)
            except Exception:
                return None
            p = {
                "name": name, "type": "vmess", "server": j.get("add", host), "port": int(j.get("port", port)),
                "uuid": j.get("id") or "", "alterId": int(j.get("aid", 0)),
                "cipher": j.get("scy", "auto"),
                "network": j.get("net", "tcp"),
            }
            if p["network"] == "ws":
                p["ws-opts"] = {"path": j.get("path", "/"), "headers": {"Host": j.get("host", "")}}
            if j.get("tls") in ("tls", "1", "true", "reality"):
                p["tls"] = True
            if j.get("sni"):
                p["servername"] = j["sni"]
            return p
        return None

    if u.scheme == "trojan":
        p = {
            "name": name, "type": "trojan", "server": host, "port": port,
            "password": u.username or "", "network": (qs.get("type", ["tcp"])[0] or "tcp"),
            "tls": True,
        }
        if qs.get("sni"):
            p["servername"] = qs["sni"][0]
        return p

    if u.scheme == "ss":
        try:
            raw = u.username or ""
            cred = ""
            if raw and raw.count(":") == 1:
                cred = raw
            else:
                try:
                    cred = _b64d(raw) or ""
                except Exception:
                    cred = ""
            if not cred or ":" not in cred:
                return None
            method, password = cred.split(":", 1)
            if not method or not password:
                return None
            return {"name": name, "type": "ss", "server": host, "port": port, "cipher": method, "password": password}
        except Exception:
            return None
    return None


def yaml_escape(v):
    s = str(v)
    return s.replace(":", "\\:").replace("\n", " ")


def build_config(proxies, ctl_port, mixed_port):
    """手写 YAML（mihomo 不吃 JSON 初始配置）。每个 proxy 需要唯一 name。"""
    lines = [
        "mixed-port: %d" % mixed_port,
        "allow-lan: false",
        "mode: rule",
        "log-level: silent",
        "external-controller: 127.0.0.1:%d" % ctl_port,
        "proxies:",
    ]
    for p in proxies:
        lines.append("  - name: \"%s\"" % yaml_escape(p["name"]))
        lines.append("    type: %s" % p["type"])
        lines.append("    server: %s" % p["server"])
        lines.append("    port: %d" % p["port"])
        if p["type"] == "vless":
            lines.append("    uuid: \"%s\"" % p["uuid"])
            lines.append("    network: %s" % p["network"])
            lines.append("    tls: %s" % str(p.get("tls", False)).lower())
            if p.get("flow"):
                lines.append("    flow: %s" % p["flow"])
            if p.get("reality-opts"):
                ro = p["reality-opts"]
                lines.append("    reality-opts:")
                lines.append("      public-key: \"%s\"" % ro["public-key"])
                lines.append("      short-id: \"%s\"" % ro["short-id"])
            if p.get("servername"):
                lines.append("    servername: %s" % p["servername"])
            if p.get("client-fingerprint"):
                lines.append("    client-fingerprint: %s" % p["client-fingerprint"])
            if p.get("ws-opts"):
                w = p["ws-opts"]
                lines.append("    ws-opts:")
                lines.append("      path: \"%s\"" % w.get("path", "/"))
                if w.get("headers", {}).get("Host"):
                    lines.append("      headers:")
                    lines.append("        Host: \"%s\"" % w["headers"]["Host"])
        elif p["type"] == "vmess":
            lines.append("    uuid: \"%s\"" % p["uuid"])
            lines.append("    alterId: %d" % p.get("alterId", 0))
            lines.append("    cipher: %s" % p.get("cipher", "auto"))
            lines.append("    network: %s" % p["network"])
            if p.get("tls"):
                lines.append("    tls: true")
            if p.get("servername"):
                lines.append("    servername: %s" % p["servername"])
            if p.get("ws-opts"):
                w = p["ws-opts"]
                lines.append("    ws-opts:")
                lines.append("      path: \"%s\"" % w.get("path", "/"))
                if w.get("headers", {}).get("Host"):
                    lines.append("      headers:")
                    lines.append("        Host: \"%s\"" % w["headers"]["Host"])
        elif p["type"] == "trojan":
            lines.append("    password: \"%s\"" % p["password"])
            lines.append("    network: %s" % p["network"])
            lines.append("    tls: true")
            if p.get("servername"):
                lines.append("    servername: %s" % p["servername"])
        elif p["type"] == "ss":
            lines.append("    cipher: %s" % p["cipher"])
            lines.append("    password: \"%s\"" % p["password"])
    # rules: 默认全部走代理
    lines.append("rules:")
    lines.append("  - MATCH,DIRECT")
    return "\n".join(lines) + "\n"


def download_mihomo():
    """下载 mihomo 二进制（GitHub Actions 环境，arch=amd64）。"""
    import urllib.request
    ver = None
    try:
        with urllib.request.urlopen("https://api.github.com/repos/MetaCubeX/mihomo/releases/latest", timeout=20) as r:
            ver = json.load(r).get("tag_name")
    except Exception:
        ver = "v1.18.10"  # fallback
    url = f"https://github.com/MetaCubeX/mihomo/releases/download/{ver}/mihomo-linux-amd64-{ver}.gz"
    print(f"[L3] 下载 mihomo {ver} ...", flush=True)
    urllib.request.urlretrieve(url, "/tmp/mihomo.gz")
    with open("/tmp/mihomo", "wb") as out:
        import gzip
        with gzip.open("/tmp/mihomo.gz", "rb") as gz:
            out.write(gz.read())
    os.chmod("/tmp/mihomo", 0o755)


def delay_probe(ctl_port, name, timeout_ms):
    """调 mihomo /proxies/{name}/delay API。返回延迟 ms 或 None。"""
    import urllib.request
    url = f"http://127.0.0.1:{ctl_port}/proxies/{urllib.parse.quote(name)}/delay?url=http://www.gstatic.com/generate_204&timeout={timeout_ms}"
    try:
        with urllib.request.urlopen(url, timeout=timeout_ms / 1000 + 5) as r:
            d = json.load(r)
            return int(d.get("delay", 0)) or None
    except Exception:
        return None


def wait_ready(ctl_port, tries=20):
    import urllib.request
    for _ in range(tries):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{ctl_port}/version", timeout=3) as r:
                return True
        except Exception:
            time.sleep(1)
    return False


def main():
    if not os.path.exists(NODES_FILE):
        print(f"[L3] 输入缺失: {NODES_FILE}")
        sys.exit(1)
    nodes = [l.strip() for l in open(NODES_FILE, encoding="utf-8") if l.strip()]
    print(f"[L3] 输入: {len(nodes)} 个 TCP/TLS 存活节点（取前 {MAX_TEST_NODES} 测真实转发）", flush=True)
    nodes = nodes[:MAX_TEST_NODES]

    mihomo = "/tmp/mihomo"
    if not os.path.exists(mihomo):
        download_mihomo()

    converted = {}
    keep_order = []
    for i, uri in enumerate(nodes):
        p = to_clash(uri, i)
        if p:
            converted[uri] = p
            keep_order.append(uri)
    print(f"[L3] 可转换: {len(converted)} / {len(nodes)}", flush=True)

    os.makedirs("/tmp/mihomo-l3", exist_ok=True)
    alive_uris = []
    batch = 0
    total_batches = (len(keep_order) + MIHOMO_BATCH - 1) // MIHOMO_BATCH
    for start in range(0, len(keep_order), MIHOMO_BATCH):
        batch += 1
        chunk_uris = keep_order[start:start + MIHOMO_BATCH]
        proxies = [converted[u] for u in chunk_uris]
        ctl_port = 19090 + (batch % 10)
        mixed_port = 29090 + (batch % 10)
        cfg_path = f"/tmp/mihomo-l3/config_{batch}.yaml"
        with open(cfg_path, "w", encoding="utf-8") as f:
            f.write(build_config(proxies, ctl_port, mixed_port))

        proc = subprocess.Popen([mihomo, "-d", "/tmp/mihomo-l3", "-f", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            if not wait_ready(ctl_port):
                print(f"  [批 {batch}/{total_batches}] mihomo 未就绪，跳过", flush=True)
                continue
            # 并发调 delay
            import concurrent.futures
            passes = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=MIHOMO_WORKERS) as ex:
                futures = {ex.submit(delay_probe, ctl_port, proxies[j]["name"], TIMEOUT_MS): j for j in range(len(proxies))}
                for fut in concurrent.futures.as_completed(futures):
                    j = futures[fut]
                    lat = fut.result()
                    if lat is not None and 0 < lat <= LATENCY_MAX_MS:
                        passes.append((chunk_uris[j], lat))
            passes.sort(key=lambda x: x[1])
            print(f"  [批 {batch}/{total_batches}] 通过 {len(passes)}/{len(chunk_uris)} (中位 {passes[len(passes)//2][1] if passes else 0}ms)", flush=True)
            alive_uris.extend([u for u, _ in passes])
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()

    # 原子写回
    tmp_out = OUT_FILE + ".tmp"
    with open(tmp_out, "w", encoding="utf-8") as f:
        f.write("\n".join(alive_uris) + "\n")
    shutil.move(tmp_out, OUT_FILE)
    print(f"[L3] 最终: {len(alive_uris)} 个真实可用节点 -> {OUT_FILE}", flush=True)


if __name__ == "__main__":
    main()