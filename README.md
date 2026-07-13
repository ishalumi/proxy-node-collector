# Proxy Node Collector

自动聚合互联网公开免费代理节点，定时爬取 + 去重，输出标准订阅格式。

## 订阅链接

| 格式 | 链接 |
|------|------|
| 纯文本 (一行一个 URI) | `https://raw.githubusercontent.com/ishalumi/proxy-node-collector/main/output/nodes.txt` |
| Base64 (标准订阅) | `https://raw.githubusercontent.com/ishalumi/proxy-node-collector/main/output/nodes_base64.txt` |

### 在 easy_proxies 中使用

```yaml
subscriptions:
  - "https://raw.githubusercontent.com/ishalumi/proxy-node-collector/main/output/nodes_base64.txt"
```

或下载 `output/nodes.txt` 作为 `nodes_file` 使用。

## 数据源

见 [`sources.yaml`](sources.yaml)。策略是**少而精**：

- **blue2sea/public**（优先）：从 [bq2015/FreeProxies](https://github.com/bq2015/FreeProxies) 自动解析当日 token，展开 Clash `proxy-providers` 嵌套节点
- **mahdibland / peasoft / Pawdroid / ermaozi** 等中等体量、相对干净的源
- 超大垃圾池（Epodonios / barry-far / MatinGhanbari 等）**严格 limit**，`v2go` / `SubCrawler` 默认关闭

### 测活说明

本仓库在 GitHub Actions 上做 **协议感知 TCP + TLS 握手**测活（不是完整代理拨号）：

| 项 | 默认 |
|----|------|
| TCP/TLS 超时 | `3.5s` |
| 延迟上限 | `2500ms` |
| 输出上限 | `2500` 节点（按延迟截断） |
| CDN 同类节点 | 每提供商最多 `30` |

> **为什么 easy_proxies 只有 ~100 健康节点？**  
> easy_proxies 会用 sing-box **真实出站**访问 `cp.cloudflare.com/generate_204`，能抓到鉴权失败 / TLS 慢 / 假 200。  
> 本仓库的 TCP 开端口 ≠ 代理可用。收紧超时与源质量后，下游真实可用率会明显提高，但数量会变少——这是预期行为。

## 更新频率

GitHub Actions **每 6 小时**自动运行，也支持手动触发。

## 添加新源

编辑 `sources.yaml`：

```yaml
# 普通源
- name: "新源"
  url: "https://example.com/nodes.txt"
  priority: 60   # 越大越优先保留（去重时）
  limit: 500     # 可选，防止膨胀

# 动态日期 URL
- name: "日期源"
  url_template: "https://example.com/nodes_{date}.txt"
  date_format: "%Y%m%d"

# Clash 壳 + proxy-providers
- name: "provider源"
  url: "https://example.com/clash.yml"
  resolve_providers: true
  headers:
    User-Agent: "ClashforWindows/0.20.39"
```

脚本自动识别 base64 / 纯文本 / Clash YAML，无需手动指定。

## 本地运行

```bash
pip install pyyaml
python fetch.py
```

## 免责声明

- 本项目**仅爬取互联网公开资源**并进行聚合整理，不提供、不运营任何代理服务。
- 项目**不对节点的可用性、安全性、速度、合法性作任何担保**。
- 使用者因使用本项目所产生的一切后果，由使用者自行承担，与本项目及作者无关。
- 请遵守您所在地区的法律法规，本项目仅供学习与技术研究用途。
